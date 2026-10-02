import sys
import tempfile
import unittest
import hashlib
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.a3_execution import GateWriteService
from engineering_gate_core.mutation_authority import GateMutationAuthority
from engineering_gate_core.state_store import StateStore
from engineering_gate_core.models import (AcceptanceCriterion, ApprovalReceipt, ApprovalRequest, ExecutionPermit,
    MutationProposal, MutationScope, NormalizedOperation, OperationKind, Plan, PlanReview, RequesterIdentity,
    ReviewVerdict, TaskState)
from engineering_gate_core.workflow import (Event, canonical_mutation_proposal_digest, canonical_plan_digest,
    mutation_argument_digest, new_task, capture_workspace_identity)
from engineering_gate_core.signed_authorization import (ReviewerPublicKey, SignedMutationVerdict, DOMAIN_PREFIX,
    canonical_signed_verdict)


class MutationAuthorityExecutionIntegrationTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.store = StateStore(self.base / "state.sqlite3")
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key = ReviewerPublicKey("key-1", "reviewer", "provider", public)
        self.store.register_reviewer_key(self.key)
        self.op = NormalizedOperation(OperationKind.WRITE, "approved.txt", "write")
        self.content = "approved content"
        self.store.create(new_task("task-1", "write file", RequesterIdentity("requester")))
        self.store.transition("task-1", Event.INSPECTION_RECORDED, __import__("engineering_gate_core.models", fromlist=["InspectionEvidenceRef"]).InspectionEvidenceRef("i", "inspection"))
        self.store.transition("task-1", Event.ANALYSIS_RECORDED, __import__("engineering_gate_core.models", fromlist=["Evidence"]).Evidence("a", "analysis"))
        plan = Plan("write file", (self.op,), (AcceptanceCriterion("c", "written", "read"),), ("verify",), workspace_root=str(self.root.resolve()))
        self.store.transition("task-1", Event.PLAN_RECORDED, plan)
        self.store.transition("task-1", Event.BLAST_RADIUS_RECORDED, __import__("engineering_gate_core.models", fromlist=["Evidence"]).Evidence("b", "scope"))
        self.store.transition("task-1", Event.PLAN_REVIEW_PASSED, PlanReview(ReviewVerdict.APPROVED))
        state = self.store.load("task-1")
        self.store.transition("task-1", Event.APPROVAL_REQUESTED, ApprovalRequest(state.task_id, state.revision, state.plan_digest, "request"))
        state = self.store.load("task-1")
        self.store.record_approval("task-1", ApprovalReceipt(state.approval_request.request_id, state.task_id, state.revision, state.plan_digest, state.task.requester, True))
        state = self.store.load("task-1")
        self.store.transition("task-1", Event.IMPLEMENTATION_STARTED, ExecutionPermit(state.task_id, state.revision, state.plan_digest, MutationScope((self.op,))))
        state = self.store.load("task-1")
        self.proposal = MutationProposal("proposal", "task-1", state.revision, state.plan_digest, self.op, mutation_argument_digest(self.content), "reviewed")
        self.store.record_mutation_proposal("task-1", self.proposal)
        self.authority = GateMutationAuthority(self.store, implementer_id="implementer")
        self.authorization = self.authority.record_signed_verdict("task-1", self.make_verdict())
        self.service = GateWriteService(self.root, state_store=self.store, mutation_authority=self.authority)
        self.addCleanup(self.service.close)

    def make_verdict(self):
        from datetime import datetime, timezone
        state = self.store.load("task-1")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        payload = {"schema_version":1,"signature_algorithm":"Ed25519","key_id":"key-1","review_id":"review-1",
          "reviewer_id":"reviewer","reviewer_provider":"provider","implementer_id":"implementer","task_id":"task-1",
          "plan_revision":int(state.revision),"plan_digest":str(state.plan_digest),"proposal_digest":canonical_mutation_proposal_digest(self.proposal),
          "verdict":"approve","reviewed_at":now.strftime("%Y-%m-%dT%H:%M:%SZ")}
        encoded = canonical_signed_verdict(payload)
        return SignedMutationVerdict(encoded, self.private.sign(DOMAIN_PREFIX + encoded))

    def permit(self):
        return self.service.issue_permit(task_id="task-1", operation=self.op, arguments={"content":self.content})

    def test_signed_approval_executes_one_exact_write_and_consumes_lease_with_audit(self):
        permit = self.permit()
        self.assertEqual(self.store.get_authorization(self.authorization.authorization_id).status.value, "ACTIVE")
        path = self.service.execute(permit, task_id="task-1", operation=self.op, arguments={"content":self.content})
        self.assertEqual(path.read_text(), self.content)
        self.assertEqual(self.store.get_authorization(self.authorization.authorization_id).status.value, "CONSUMED")
        audits = self.store.list_execution_audits("task-1")
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0].authorization_id, self.authorization.authorization_id)
        self.assertEqual(audits[0].resulting_artifact_digest, hashlib.sha256(self.content.encode()).hexdigest())

    def test_issue_permit_does_not_reserve_authorization(self):
        self.permit()
        self.assertEqual(self.store.get_authorization(self.authorization.authorization_id).status.value, "ACTIVE")

    def test_revoked_authorization_denies_execution(self):
        permit = self.permit()
        self.authority.revoke(self.authorization.authorization_id, reason="revoked")
        with self.assertRaises(PermissionError):
            self.service.execute(permit, task_id="task-1", operation=self.op, arguments={"content":self.content})
        self.assertFalse((self.root / self.op.target).exists())

    def test_staging_precedes_durable_reservation_and_target_replacement(self):
        permit = self.permit()
        reserve = self.store.reserve_mutation_lease
        events = []
        def observe(*args, **kwargs):
            staged = list(self.root.glob(".gate-write-*.tmp"))
            events.append(("reserve", bool(staged), (self.root / self.op.target).exists()))
            return reserve(*args, **kwargs)
        self.store.reserve_mutation_lease = observe
        self.service.execute(permit, task_id="task-1", operation=self.op, arguments={"content":self.content})
        self.assertEqual(events, [("reserve", True, False)])

    def test_mismatched_proposal_request_is_denied_without_reserving_authorization(self):
        permit = self.permit()
        with self.assertRaises(PermissionError):
            self.service.execute(permit, task_id="task-1", operation=self.op,
                                 arguments={"content":"different content"})
        self.assertFalse((self.root / self.op.target).exists())
        self.assertEqual(self.store.get_authorization(self.authorization.authorization_id).status.value, "ACTIVE")

    def test_audit_insert_failure_after_replacement_is_uncertain_and_consumes_uncertain(self):
        import sqlite3
        permit = self.permit()
        original_connect = self.store._connect
        import engineering_gate_core.a3_execution as a3_execution
        original_dup, original_open, original_close = a3_execution.os.dup, a3_execution.os.open, a3_execution.os.close
        fd_lifetimes = {}
        stage_complete = False

        def tracked_dup(fd):
            result = original_dup(fd)
            if not stage_complete:
                fd_lifetimes[result] = 0
            return result

        def tracked_open(path, flags, *args, **kwargs):
            result = original_open(path, flags, *args, **kwargs)
            if not stage_complete and flags & a3_execution.os.O_DIRECTORY:
                fd_lifetimes[result] = 0
            return result

        def tracked_close(fd):
            if fd in fd_lifetimes:
                fd_lifetimes[fd] += 1
            return original_close(fd)

        a3_execution.os.dup, a3_execution.os.open, a3_execution.os.close = tracked_dup, tracked_open, tracked_close
        self.addCleanup(setattr, a3_execution.os, "dup", original_dup)
        self.addCleanup(setattr, a3_execution.os, "open", original_open)
        self.addCleanup(setattr, a3_execution.os, "close", original_close)
        reserve = self.store.reserve_mutation_lease
        self.addCleanup(setattr, self.store, "reserve_mutation_lease", reserve)
        def mark_staged(*args, **kwargs):
            nonlocal stage_complete
            stage_complete = True
            return reserve(*args, **kwargs)
        self.store.reserve_mutation_lease = mark_staged

        class AuditFailingConnection:
            def __init__(self, connection):
                self._connection = connection

            def __getattr__(self, name):
                return getattr(self._connection, name)

            def execute(self, sql, *args, **kwargs):
                if sql.strip().upper().startswith("INSERT INTO EXECUTION_AUDIT"):
                    raise sqlite3.OperationalError("audit unavailable")
                return self._connection.execute(sql, *args, **kwargs)

        self.store._connect = lambda: AuditFailingConnection(original_connect())
        from engineering_gate_core.a3_execution import MutationOutcomeUnknown
        with self.assertRaises(MutationOutcomeUnknown) as caught:
            self.service.execute(permit, task_id="task-1", operation=self.op, arguments={"content":self.content})
        self.assertTrue(fd_lifetimes, "staging descriptors were not observed")
        self.assertEqual(fd_lifetimes, {fd: 1 for fd in fd_lifetimes}, "staged descriptors must be closed exactly once")
        self.assertIsInstance(caught.exception, MutationOutcomeUnknown)
        self.assertEqual((self.root / self.op.target).read_text(), self.content)
        self.assertEqual(self.store.get_authorization(self.authorization.authorization_id).status.value, "CONSUMED_UNCERTAIN")
        self.assertEqual(self.store.list_execution_audits("task-1"), ())


class RequiredMutationAuthorityInterfaceTests(unittest.TestCase):
    def test_service_requires_store_and_authority_and_binds_the_identical_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            store = StateStore(Path(tmp) / "state.sqlite3")
            authority = GateMutationAuthority(store, implementer_id="implementer")
            with GateWriteService(root, state_store=store, mutation_authority=authority) as service:
                self.assertIs(service._state_store, store)
                self.assertIs(service._mutation_authority, authority)

    def test_service_rejects_authority_for_another_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            store = StateStore(Path(tmp) / "one.sqlite3")
            other = StateStore(Path(tmp) / "two.sqlite3")
            authority = GateMutationAuthority(other, implementer_id="implementer")
            with self.assertRaises(ValueError):
                GateWriteService(root, state_store=store, mutation_authority=authority)


if __name__ == "__main__":
    unittest.main()
