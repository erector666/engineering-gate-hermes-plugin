import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.models import (
    AcceptanceCriterion, ApprovalReceipt, ApprovalRequest, Evidence, ExecutionPermit,
    InspectionEvidenceRef, MutationScope, NormalizedOperation, OperationKind, Plan,
    PlanReview, RequesterIdentity, ResultReview, ReviewVerdict, TaskState,
    VerificationCommand,
)
from engineering_gate_core.state_store import StateStore
from engineering_gate_core.workflow import Event, TransitionError, new_task
import engineering_gate_core.verification_execution as verification_execution
from engineering_gate_core.verification_execution import (
    CommandLaunchError, GateVerificationRunner, WorkspaceIdentityError,
)


class GateVerificationRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.db = self.base / "state.sqlite3"
        self.store = StateStore(self.db)
        self.task_id = "runner-task"
        self.criteria = (
            AcceptanceCriterion("c1", "first", "check"),
            AcceptanceCriterion("c2", "second", "check"),
        )
        self.commands = (
            VerificationCommand((sys.executable, "-c", "print('PASS')"), ("c1",), 3, 4096),
            VerificationCommand((sys.executable, "-c", "raise SystemExit(0)"), ("c2",), 3, 4096),
        )
        self.operation = NormalizedOperation(OperationKind.READ, "workspace")

    def create_implementing(self, commands=None, *, criteria=None, root=None):
        """Create a fresh task with this exact approved plan and its commands."""
        commands = self.commands if commands is None else tuple(commands)
        criteria = self.criteria if criteria is None else tuple(criteria)
        root = self.root if root is None else Path(root)
        root.mkdir(parents=True, exist_ok=True)
        task_id = self.task_id
        plan = Plan("plan", (self.operation,), criteria, ("verify",),
                    workspace_root=str(root), verification_commands=commands)
        self.store.create(new_task(task_id, "runner test", RequesterIdentity("tester")))
        self.store.transition(task_id, Event.INSPECTION_RECORDED, InspectionEvidenceRef("i", "inspection"))
        self.store.transition(task_id, Event.ANALYSIS_RECORDED, Evidence("a", "analysis"))
        self.store.transition(task_id, Event.PLAN_RECORDED, plan)
        self.store.transition(task_id, Event.BLAST_RADIUS_RECORDED, Evidence("b", "impact"))
        self.store.transition(task_id, Event.PLAN_REVIEW_PASSED, PlanReview(ReviewVerdict.APPROVED))
        state = self.store.load(task_id)
        self.store.transition(task_id, Event.APPROVAL_REQUESTED,
                              ApprovalRequest(state.task_id, state.revision, state.plan_digest, "r"))
        state = self.store.load(task_id)
        self.store.record_approval(task_id, ApprovalReceipt(
            "r", state.task_id, state.revision, state.plan_digest, state.task.requester, True))
        state = self.store.load(task_id)
        self.store.transition(task_id, Event.IMPLEMENTATION_STARTED,
                              ExecutionPermit(state.task_id, state.revision, state.plan_digest,
                                              MutationScope(state.plan.operations)))
        return task_id

    def run_all(self, task_id):
        return GateVerificationRunner(self.store).run_all(task_id)

    def test_runs_approved_commands_and_binds_evidence_to_criteria(self):
        task_id = self.create_implementing()
        result = self.run_all(task_id)
        self.assertEqual(result.state, TaskState.VERIFYING)
        self.assertEqual([item.criterion_id for item in result.verification], ["c1", "c2"])
        observed = [e for item in result.verification for e in item.evidence]
        self.assertEqual([e.criterion_id for e in observed], ["c1", "c2"])
        self.assertEqual([e.argv for e in observed], [command.argv for command in self.commands])
        self.assertEqual(len({e.execution_id for e in observed}), 2)
        self.assertTrue(all(item.passed for item in result.verification))

    def test_shared_command_runs_once_and_associates_one_observation_with_each_criterion(self):
        shared = VerificationCommand(
            (sys.executable, "-c", "print('SHARED PASS')"), ("c1", "c2"), 3, 4096)
        task_id = self.create_implementing((shared,))
        real_observe = verification_execution._observe_verification_command
        with patch.object(verification_execution, "_observe_verification_command",
                          wraps=real_observe) as observe:
            result = self.run_all(task_id)

        observe.assert_called_once()
        self.assertEqual([item.criterion_id for item in result.verification], ["c1", "c2"])
        evidence = [item.evidence[0] for item in result.verification]
        self.assertEqual([item.criterion_id for item in evidence], ["c1", "c2"])
        self.assertEqual(evidence[0].argv, shared.argv)
        self.assertTrue(evidence[0].execution_id)
        self.assertEqual(evidence[0].execution_id, evidence[1].execution_id)
        self.assertEqual(evidence[0].started_at, evidence[1].started_at)
        self.assertEqual(evidence[0].completed_at, evidence[1].completed_at)
        self.assertEqual(evidence[0].stdout_digest, evidence[1].stdout_digest)
        self.assertEqual(evidence[0].stderr_digest, evidence[1].stderr_digest)
        self.assertTrue(all(item.passed for item in result.verification))

    def test_exit_one_with_pass_text_persists_failure_and_blocks_pass_review(self):
        bad = VerificationCommand(
            (sys.executable, "-c", "print('PASS'); raise SystemExit(1)"), ("c1",), 3, 4096)
        task_id = self.create_implementing((bad, self.commands[1]))
        result = self.run_all(task_id)
        self.assertEqual(result.state, TaskState.VERIFYING)
        self.assertFalse(result.verification[0].passed)
        self.assertIn("PASS", result.verification[0].evidence[0].output_summary)
        self.assertEqual(result.verification[0].evidence[0].exit_code, 1)
        with self.assertRaises(TransitionError):
            self.store.transition(task_id, Event.RESULT_REVIEW_PASSED, ResultReview(ReviewVerdict.PASS))

    def test_missing_coverage_is_rejected_before_spawn(self):
        fail_if_run = VerificationCommand(
            (sys.executable, "-c", "raise SystemExit(91)"), ("c1",), 1, 100)
        task_id = self.create_implementing((fail_if_run,), criteria=self.criteria)
        with patch.object(verification_execution, "_observe_verification_command") as observe:
            with self.assertRaises(ValueError):
                self.run_all(task_id)
            observe.assert_not_called()
        state = self.store.load(task_id)
        self.assertEqual(state.state, TaskState.IMPLEMENTING)
        self.assertEqual(state.verification, ())

    def test_launch_failure_does_not_persist(self):
        bad = VerificationCommand(("/definitely/not/a/real/executable",), ("c1",), 1, 100)
        task_id = self.create_implementing((bad, self.commands[1]))
        with self.assertRaises(CommandLaunchError):
            self.run_all(task_id)
        state = self.store.load(task_id)
        self.assertEqual(state.state, TaskState.IMPLEMENTING)
        self.assertEqual(state.verification, ())

    def test_timeout_persists_failure_without_hanging(self):
        slow = VerificationCommand(
            (sys.executable, "-c", "import time; time.sleep(10)"), ("c1",), 1, 100)
        task_id = self.create_implementing((slow, self.commands[1]))
        result = self.run_all(task_id)
        self.assertEqual(result.state, TaskState.VERIFYING)
        self.assertFalse(result.verification[0].passed)
        self.assertTrue(result.verification[0].evidence[0].timed_out)
        self.assertTrue(result.verification[1].passed)

    def test_workspace_replacement_before_run_fails_closed(self):
        task_id = self.create_implementing()
        moved = self.root.with_name("workspace-moved")
        self.root.rename(moved)
        self.root.mkdir()
        with self.assertRaises(WorkspaceIdentityError):
            self.run_all(task_id)
        state = self.store.load(task_id)
        self.assertEqual(state.state, TaskState.IMPLEMENTING)
        self.assertEqual(state.verification, ())

    def test_workspace_replacement_during_run_fails_closed(self):
        script = "import os,time; p=os.getcwd(); os.rename(p,p+'-moved'); os.mkdir(p); time.sleep(.1)"
        replacing = VerificationCommand((sys.executable, "-c", script), ("c1",), 3, 100)
        task_id = self.create_implementing((replacing, self.commands[1]))
        with self.assertRaises(WorkspaceIdentityError):
            self.run_all(task_id)
        state = self.store.load(task_id)
        self.assertEqual(state.state, TaskState.IMPLEMENTING)
        self.assertEqual(state.verification, ())

    def test_stale_concurrent_state_rejects_observations(self):
        task_id = self.create_implementing()
        real_observe = verification_execution._observe_verification_command
        cancelled = []

        def observe_then_cancel(*args, **kwargs):
            observed = real_observe(*args, **kwargs)
            if not cancelled:
                self.store.transition(task_id, Event.CANCEL)
                cancelled.append(True)
            return observed

        with patch.object(verification_execution, "_observe_verification_command", observe_then_cancel):
            with self.assertRaises(Exception):
                self.run_all(task_id)
        state = self.store.load(task_id)
        self.assertEqual(state.state, TaskState.CANCELLED)
        self.assertEqual(state.verification, ())

    def test_api_rejects_caller_argv_injection(self):
        task_id = self.create_implementing()
        with self.assertRaises(TypeError):
            GateVerificationRunner(self.store).run_all(task_id, argv=("false",))
        result = self.run_all(task_id)
        observed = [e for item in result.verification for e in item.evidence]
        self.assertEqual([e.argv for e in observed], [command.argv for command in self.commands])


if __name__ == "__main__":
    unittest.main()
