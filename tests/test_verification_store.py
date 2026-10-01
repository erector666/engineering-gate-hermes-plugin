import hashlib
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.models import (
    AcceptanceCriterion, ApprovalReceipt, ApprovalRequest, Evidence,
    EvidenceProvenance, ExecutionPermit, InspectionEvidenceRef, MutationScope,
    NormalizedOperation, OperationKind, Plan, PlanReview, RequesterIdentity,
    ResultReview, ReviewVerdict, TaskState, VerificationCommand,
    WorkspaceIdentity, ObservedCommandEvidence, _ISSUER,
)
from engineering_gate_core.state_store import StateStore
from engineering_gate_core.workflow import Event, TransitionError, new_task


class VerificationStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = str(Path(self.temp.name).resolve())
        self.db_path = Path(self.temp.name) / "state.sqlite3"
        self.store = StateStore(self.db_path)
        self.task_id = "verify-task"
        self.commands = (VerificationCommand(("python", "-m", "unittest"), ("c1",), 30, 4096),
                         VerificationCommand(("python", "audit.py"), ("c2",), 30, 4096))
        self.plan = Plan("test plan", (NormalizedOperation(OperationKind.READ, "src"),),
                         (AcceptanceCriterion("c1", "works", "run tests"),
                          AcceptanceCriterion("c2", "safe", "run audit")), ("verify",),
                         workspace_root=self.root, verification_commands=self.commands)
        self.task = self._create_implementing()

    def _create_implementing(self):
        task = new_task(self.task_id, "test verification", RequesterIdentity("tester"))
        self.store.create(task)
        task = self.store.transition(self.task_id, Event.INSPECTION_RECORDED,
                                     InspectionEvidenceRef("inspect", "test-only inspection"))
        task = self.store.transition(self.task_id, Event.ANALYSIS_RECORDED,
                                     Evidence("analysis", "test-only analysis"))
        task = self.store.transition(self.task_id, Event.PLAN_RECORDED, self.plan)
        task = self.store.transition(self.task_id, Event.BLAST_RADIUS_RECORDED,
                                     Evidence("impact", "test-only impact"))
        task = self.store.transition(self.task_id, Event.PLAN_REVIEW_PASSED,
                                     PlanReview(ReviewVerdict.APPROVED))
        request = ApprovalRequest(task.task_id, task.revision, task.plan_digest, "request")
        task = self.store.transition(self.task_id, Event.APPROVAL_REQUESTED, request)
        receipt = ApprovalReceipt("request", task.task_id, task.revision, task.plan_digest,
                                  task.task.requester, True)
        task = self.store.record_approval(self.task_id, receipt)
        permit = ExecutionPermit(task.task_id, task.revision, task.plan_digest,
                                 MutationScope(task.plan.operations))
        return self.store.transition(self.task_id, Event.IMPLEMENTATION_STARTED, permit)

    def observation(self, criterion, argv=None, *, task=None, revision=None, digest=None,
                    workspace=None, exit_code=0, timed_out=False):
        task = task or self.task
        argv = argv or next(cmd.argv for cmd in self.commands if criterion in cmd.criterion_ids)
        return ObservedCommandEvidence._issue(_issuer=_ISSUER,
            task_id=str(task.task_id), plan_revision=int(task.revision) if revision is None else revision,
            plan_digest=task.plan_digest if digest is None else digest,
            criterion_id=criterion, argv=argv,
            workspace_identity=task.plan.workspace_identity if workspace is None else workspace,
            started_at="2026-10-01T10:00:00Z", completed_at="2026-10-01T10:00:01Z",
            exit_code=exit_code, stdout_digest=hashlib.sha256(b"out").hexdigest(),
            stderr_digest=hashlib.sha256(b"").hexdigest(), output_summary="test-only output",
            timed_out=timed_out)

    def record(self, observations):
        return self.store._record_gate_verification(
            self.task_id, expected_revision=self.task.revision,
            expected_plan_digest=self.task.plan_digest, observations=observations)

    def test_valid_observations_round_trip_and_pass_review(self):
        updated = self.record((self.observation("c1"), self.observation("c2")))
        loaded = StateStore(self.db_path).load(self.task_id)
        self.assertEqual(loaded, updated)
        self.assertEqual(loaded.state, TaskState.VERIFYING)
        self.assertTrue(all(result.passed for result in loaded.verification))
        self.assertEqual(len(loaded.verification), 2)
        self.assertEqual(self.store.transition(self.task_id, Event.RESULT_REVIEW_PASSED,
                         ResultReview(ReviewVerdict.PASS)).state, TaskState.HANDOFF)

    def test_invalid_context_and_observations_are_atomic(self):
        one, two = self.observation("c1"), self.observation("c2")
        cases = (
            ("wrong task", "other", self.task.revision, self.task.plan_digest, (one, two)),
            ("stale revision", self.task_id, self.task.revision + 1, self.task.plan_digest, (one, two)),
            ("stale digest", self.task_id, self.task.revision, "0" * 64, (one, two)),
            ("wrong criterion", self.task_id, self.task.revision, self.task.plan_digest,
             (self.observation("c1", argv=self.commands[0].argv).__class__._issue(
                 task_id=str(self.task.task_id), plan_revision=int(self.task.revision),
                 _issuer=_ISSUER, plan_digest=self.task.plan_digest, criterion_id="other", argv=self.commands[0].argv,
                 workspace_identity=self.task.plan.workspace_identity,
                 started_at="2026-10-01T10:00:00Z", completed_at="2026-10-01T10:00:01Z",
                 exit_code=0, stdout_digest=hashlib.sha256(b"out").hexdigest(),
                 stderr_digest=hashlib.sha256(b"").hexdigest(), output_summary="test-only output",
                 timed_out=False), two)),
            ("unapproved argv", self.task_id, self.task.revision, self.task.plan_digest,
             (self.observation("c1", ("sh", "-c", "false")), two)),
            ("wrong workspace", self.task_id, self.task.revision, self.task.plan_digest,
             (self.observation("c1", workspace=WorkspaceIdentity(self.root, -1, -1)), two)),
            ("missing criterion", self.task_id, self.task.revision, self.task.plan_digest, (one,)),
        )
        for label, task_id, revision, digest, observations in cases:
            with self.subTest(label=label):
                before = self.store.load(self.task_id)
                with self.assertRaises(Exception):
                    self.store._record_gate_verification(task_id, expected_revision=revision,
                        expected_plan_digest=digest, observations=observations)
                self.assertEqual(self.store.load(self.task_id), before)

    def test_failed_observation_persists_but_review_rejects_and_fix_clears(self):
        recorded = self.record((self.observation("c1", exit_code=1), self.observation("c2")))
        self.assertFalse(recorded.verification[0].passed)
        with self.assertRaises(TransitionError):
            self.store.transition(self.task_id, Event.RESULT_REVIEW_PASSED,
                                  ResultReview(ReviewVerdict.PASS))
        fixed = self.store.transition(self.task_id, Event.IMPLEMENTATION_FIX_REQUIRED,
                                      ResultReview(ReviewVerdict.IMPLEMENT_FIX))
        self.assertEqual(fixed.state, TaskState.IMPLEMENTING)
        self.assertEqual(fixed.verification, ())

    def test_generic_transition_injection_is_rejected_atomically(self):
        before = self.store.load(self.task_id)
        with self.assertRaises(TransitionError):
            self.store.transition(self.task_id, Event.VERIFICATION_RECORDED, ())
        self.assertEqual(self.store.load(self.task_id), before)

    def test_generic_evidence_cannot_create_verification_result(self):
        from engineering_gate_core.models import VerificationResult
        with self.assertRaises(ValueError):
            VerificationResult("c1", (Evidence("claim", "passed", True),))


if __name__ == "__main__":
    unittest.main()
