import sys
import tempfile
import threading
from contextlib import contextmanager
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.a3_execution import GateWriteService
from engineering_gate_core.mutation_authority import GateMutationAuthority
from datetime import datetime, timezone, timedelta
from engineering_gate_core.models import (
    AcceptanceCriterion, ApprovalReceipt, ApprovalRequest, Evidence,
    ExecutionPermit, InspectionEvidenceRef, MutationAuthorization, MutationProposal, MutationScope, NormalizedOperation,
    OperationKind, Plan, PlanReview, RequesterIdentity, ReviewVerdict, TaskState,
)
from engineering_gate_core.state_store import StateStore
from engineering_gate_core.workflow import (Event, canonical_plan_digest, canonical_mutation_proposal_digest,
                                            mutation_argument_digest, new_task)


class SyntheticAuthorizationProvider:
    """Test-only provider registry; it does not authenticate human identity."""

    def __init__(self):
        self._approvals = set()
        self._lock = threading.Lock()

    def issue(self, authorization):
        with self._lock:
            self._approvals.add(authorization)

    def revoke(self, authorization_id):
        with self._lock:
            self._approvals = {approval for approval in self._approvals if approval.authorization_id != authorization_id}

    def verify(self, authorization, proposal):
        with self._lock:
            return (authorization in self._approvals and
                    authorization.proposal_digest == canonical_mutation_proposal_digest(proposal))

    @contextmanager
    def acquire_lease(self, authorization, proposal):
        self._lock.acquire()
        try:
            if not (authorization in self._approvals and
                    authorization.proposal_digest == canonical_mutation_proposal_digest(proposal)):
                raise PermissionError("authorization revoked")
            yield
        finally:
            self._lock.release()


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
        current = self.store.load("task-1")
        content = "approved content"
        proposal = MutationProposal("proposal-1", "task-1", current.revision, current.plan_digest,
                                    self.operation, mutation_argument_digest(content), "test-only proposal")
        self.store.record_mutation_proposal("task-1", proposal)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from engineering_gate_core.signed_authorization import ReviewerPublicKey, SignedMutationVerdict, DOMAIN_PREFIX, canonical_signed_verdict
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.store.register_reviewer_key(ReviewerPublicKey("key-1", "reviewer", "provider", public))
        state = self.store.load("task-1")
        payload = {"schema_version":1,"signature_algorithm":"Ed25519","key_id":"key-1","review_id":"review-1",
          "reviewer_id":"reviewer","reviewer_provider":"provider","implementer_id":"implementer","task_id":"task-1",
          "plan_revision":int(state.revision),"plan_digest":str(state.plan_digest),"proposal_digest":canonical_mutation_proposal_digest(proposal),
          "verdict":"approve","reviewed_at":now.strftime("%Y-%m-%dT%H:%M:%SZ")}
        encoded = canonical_signed_verdict(payload)
        verdict = SignedMutationVerdict(encoded, self.private.sign(DOMAIN_PREFIX + encoded))
        self.authority = GateMutationAuthority(self.store, implementer_id="implementer")
        self.authorization = self.authority.record_signed_verdict("task-1", verdict)
        self.service = GateWriteService(self.root, state_store=self.store, mutation_authority=self.authority)
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

    def test_service_constructor_requires_gate_authority(self):
        with self.assertRaises(TypeError):
            GateWriteService(self.root)

    def test_authority_revocation_after_permit_issue_denies_real_store_write(self):
        permit = self._permit()
        self.authority.revoke(self.authorization.authorization_id, reason="revoked")
        with self.assertRaises(PermissionError):
            self.service.execute(permit, task_id="task-1", operation=self.operation,
                                 arguments={"content": "approved content"})
        self.assertFalse((self.root / "approved.txt").exists())
        self.assertEqual(self.store.list_execution_audits("task-1"), ())

    def test_authorized_write_runs_against_real_store_state(self):
        permit = self._permit()
        expected_permit_hash = __import__("hashlib").sha256(permit._nonce.encode("utf-8")).hexdigest()
        path = self.service.execute(permit, task_id="task-1", operation=self.operation,
                                    arguments={"content": "approved content"})
        self.assertEqual(path.read_text(), "approved content")
        audits = self.store.list_execution_audits("task-1")
        self.assertEqual(len(audits), 1)
        audit = audits[0]
        self.assertEqual(audit.outcome.value, "succeeded")
        self.assertEqual(audit.target, "approved.txt")
        self.assertEqual(audit.permit_hash, expected_permit_hash)
        self.assertEqual(audit.resulting_artifact_digest, __import__("hashlib").sha256(b"approved content").hexdigest())

    def test_cancellation_before_execute_denies_write(self):
        permit = self._permit()
        self.store.transition("task-1", Event.CANCEL)
        with self.assertRaises(PermissionError):
            self.service.execute(permit, task_id="task-1", operation=self.operation,
                                 arguments={"content": "approved content"})
        self.assertFalse((self.root / "approved.txt").exists())
        self.assertEqual(self.store.list_execution_audits("task-1"), ())

    def test_replayed_permit_creates_no_second_audit(self):
        permit = self._permit()
        self.service.execute(permit, task_id="task-1", operation=self.operation,
                             arguments={"content": "approved content"})
        with self.assertRaises(PermissionError):
            self.service.execute(permit, task_id="task-1", operation=self.operation,
                                 arguments={"content": "approved content"})
        audits = self.store.list_execution_audits("task-1")
        self.assertEqual(len(audits), 1)

    def test_cancellation_waits_until_filesystem_write_finishes(self):
        permit = self._permit()
        entered_write = threading.Event()
        release_write = threading.Event()
        write_finished = threading.Event()
        cancel_finished = threading.Event()
        errors = []
        real_replace = __import__("os").replace

        def paused_replace(src, dst, **kwargs):
            entered_write.set()
            if not release_write.wait(3):
                raise AssertionError("test did not release final replacement")
            try:
                return real_replace(src, dst, **kwargs)
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

        with patch("engineering_gate_core.a3_execution.os.replace", side_effect=paused_replace):
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
