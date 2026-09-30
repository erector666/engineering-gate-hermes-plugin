import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.a3_execution import GateWriteService
from engineering_gate_core.models import (
    AcceptanceCriterion, ApprovalReceipt, ApprovalRequest, Evidence,
    ExecutionPermit, InspectionEvidenceRef, MutationScope, NormalizedOperation,
    OperationKind, Plan, PlanReview, RequesterIdentity, ReviewVerdict, TaskState,
)
from engineering_gate_core.state_store import StateStore
from engineering_gate_core.workflow import Event, canonical_plan_digest, new_task


class StateStoreGateWriteIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.store = StateStore(self.base / "state.sqlite3")
        self.operation = NormalizedOperation(OperationKind.WRITE, "approved.txt")
        self.store.create(new_task("task-1", "write approved file", RequesterIdentity("requester")))
        self._advance_to_approval_request()
        current = self.store.load("task-1")
        # Synthetic fixture approval only; this is not proof of real human authentication.
        self.store.record_approval("task-1", ApprovalReceipt(
            current.approval_request.request_id, current.task_id, current.revision,
            current.plan_digest, current.task.requester, True))
        current = self.store.load("task-1")
        permit = ExecutionPermit(current.task_id, current.revision, current.plan_digest,
                                 MutationScope((self.operation,)))
        self.store.transition("task-1", Event.IMPLEMENTATION_STARTED, permit)
        self.service = GateWriteService(self.root, state_loader=self.store.load,
                                       state_transaction=self.store.with_current_state_transaction)
        self.addCleanup(self.service.close)

    def _advance_to_approval_request(self):
        store = self.store
        store.transition("task-1", Event.INSPECTION_RECORDED,
                         InspectionEvidenceRef("inspect-1", "fixture inspection"))
        store.transition("task-1", Event.ANALYSIS_RECORDED, Evidence("analysis-1", "fixture analysis"))
        plan = Plan("write approved file", (self.operation,),
                    (AcceptanceCriterion("written", "file is written", "read file"),),
                    ("verify file",), workspace_root=str(self.root.resolve()))
        store.transition("task-1", Event.PLAN_RECORDED, plan)
        store.transition("task-1", Event.BLAST_RADIUS_RECORDED, Evidence("blast-1", "fixture scope"))
        store.transition("task-1", Event.PLAN_REVIEW_PASSED, PlanReview(ReviewVerdict.APPROVED))
        current = store.load("task-1")
        store.transition("task-1", Event.APPROVAL_REQUESTED,
                         ApprovalRequest(current.task_id, current.revision, current.plan_digest, "request-1"))

    def _permit(self):
        return self.service.issue_permit(task_id="task-1", operation=self.operation,
                                         arguments={"content": "approved content"})

    def test_authorized_write_runs_against_real_store_state(self):
        path = self.service.execute(self._permit(), task_id="task-1", operation=self.operation,
                                    arguments={"content": "approved content"})
        self.assertEqual(path.read_text(), "approved content")

    def test_cancellation_before_execute_denies_write(self):
        permit = self._permit()
        self.store.transition("task-1", Event.CANCEL)
        with self.assertRaises(PermissionError):
            self.service.execute(permit, task_id="task-1", operation=self.operation,
                                 arguments={"content": "approved content"})
        self.assertFalse((self.root / "approved.txt").exists())

    def test_cancellation_waits_until_filesystem_write_finishes(self):
        permit = self._permit()
        entered_write = threading.Event()
        release_write = threading.Event()
        write_finished = threading.Event()
        cancel_finished = threading.Event()
        errors = []
        real_write = __import__("os").write

        def paused_write(fd, data):
            entered_write.set()
            if not release_write.wait(3):
                raise AssertionError("test did not release filesystem write")
            try:
                return real_write(fd, data)
            finally:
                write_finished.set()

        def execute():
            try:
                self.service.execute(permit, task_id="task-1", operation=self.operation,
                                     arguments={"content": "approved content"})
            except Exception as exc:
                errors.append(exc)

        def cancel():
            try:
                self.store.transition("task-1", Event.CANCEL)
            except Exception as exc:
                errors.append(exc)
            finally:
                cancel_finished.set()

        with patch("engineering_gate_core.a3_execution.os.write", side_effect=paused_write):
            writer = threading.Thread(target=execute)
            writer.start()
            self.assertTrue(entered_write.wait(2))
            canceller = threading.Thread(target=cancel)
            canceller.start()
            self.assertFalse(cancel_finished.wait(0.1))
            release_write.set()
            writer.join(3)
            canceller.join(3)

        self.assertFalse(writer.is_alive())
        self.assertFalse(canceller.is_alive())
        self.assertTrue(write_finished.is_set())
        self.assertTrue(cancel_finished.is_set())
        self.assertEqual(errors, [])
        self.assertEqual((self.root / "approved.txt").read_text(), "approved content")
        self.assertEqual(self.store.load("task-1").state, TaskState.CANCELLED)


if __name__ == "__main__":
    unittest.main()
