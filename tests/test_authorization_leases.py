import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.models import AuthorizationLeaseStatus, MutationLeaseRecord
from engineering_gate_core.signed_authorization import ReviewerPublicKey, SignatureVerificationError, VerifiedReviewerVerdict
from engineering_gate_core.state_store import StateStore, StateStoreError


class AuthorizationLeaseTests(unittest.TestCase):
    def test_shorter_policy_applies_to_issuance_verification_and_later_reservation(self):
        from engineering_gate_core.authorization_policy import AuthorizationTimingPolicy
        from engineering_gate_core.signed_authorization import verify_signed_verdict
        policy = AuthorizationTimingPolicy(max_review_age_seconds=10, max_active_lease_seconds=20)
        store = StateStore(self.path, timing_policy=policy)
        self.assertIs(store.timing_policy, policy)
        self.registry = __import__("engineering_gate_core.mutation_authority", fromlist=["ReviewerKeyRegistry"]).ReviewerKeyRegistry(store)
        self.registry.register_reviewer_key(self.key)
        verified, encoded, signature, issued = self.verdict()
        from engineering_gate_core.signed_authorization import SignedMutationVerdict
        with self.assertRaises(SignatureVerificationError):
            verify_signed_verdict(SignedMutationVerdict(encoded, signature), self.key,
                now=issued + timedelta(seconds=11), implementer_id="implementer", timing_policy=policy)
        with self.assertRaises(StateStoreError):
            store._record_verified_verdict("task-1", verified, encoded, signature,
                authorization_id="too-long", issued_at=issued, expires_at=issued + timedelta(seconds=21))
        store._record_verified_verdict("task-1", verified, encoded, signature, authorization_id="auth-short",
            issued_at=issued, expires_at=issued + timedelta(seconds=20))
        with self.assertRaises(StateStoreError):
            store.reserve_mutation_lease("task-1", "auth-short", "b" * 64, issued + timedelta(seconds=11))

    def test_authority_issues_expiry_from_shorter_lease_policy(self):
        from dataclasses import replace
        from engineering_gate_core.authorization_policy import AuthorizationTimingPolicy
        from engineering_gate_core.models import (AcceptanceCriterion, ApprovalReceipt, ApprovalRequest,
            ExecutionPermit, MutationProposal, MutationScope, NormalizedOperation, OperationKind,
            Plan, PlanReview, PlanRevision, RequesterIdentity, ReviewVerdict, Task, TaskState, TaskStateRecord)
        from engineering_gate_core.mutation_authority import GateMutationAuthority
        from engineering_gate_core.workflow import (canonical_plan_digest, canonical_mutation_proposal_digest,
            mutation_argument_digest, capture_workspace_identity)
        from engineering_gate_core.state_store import _record_json
        from engineering_gate_core.signed_authorization import DOMAIN_PREFIX, SignedMutationVerdict, canonical_signed_verdict
        policy = AuthorizationTimingPolicy(max_review_age_seconds=10, max_active_lease_seconds=20)
        store = StateStore(self.path, timing_policy=policy)
        self.registry = __import__("engineering_gate_core.mutation_authority", fromlist=["ReviewerKeyRegistry"]).ReviewerKeyRegistry(store)
        self.registry.register_reviewer_key(self.key)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "write")
        with tempfile.TemporaryDirectory() as workspace:
            plan = Plan("change", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",),
                        workspace_root=str(Path(workspace).resolve()))
            plan = replace(plan, workspace_identity=capture_workspace_identity(plan.workspace_root))
            digest = canonical_plan_digest(plan)
            requester = RequesterIdentity("requester")
            task = Task("task-1", "change", requester)
            proposal = MutationProposal("proposal", "task-1", 1, digest, op, mutation_argument_digest("x"), "reviewed")
            state = TaskStateRecord(task, TaskState.IMPLEMENTING, PlanRevision(1), (TaskState.IMPLEMENTING,),
                plan=plan, plan_digest=digest, plan_review=PlanReview(ReviewVerdict.APPROVED),
                approval_request=ApprovalRequest("task-1", 1, digest, "request"),
                approval=ApprovalReceipt("request", "task-1", 1, digest, requester, True),
                permit=ExecutionPermit("task-1", 1, digest, MutationScope((op,))), mutation_proposal=proposal)
            store.create(__import__("engineering_gate_core.workflow", fromlist=["new_task"]).new_task("task-1", "change", requester))
            connection = store._connect()
            connection.execute("UPDATE task_state SET payload=? WHERE task_id=?", (_record_json(state), "task-1"))
            connection.commit()
            connection.close()
            authority = GateMutationAuthority(store, implementer_id="implementer")
            authority._now = lambda: now
            payload = {"schema_version": 1, "signature_algorithm": "Ed25519", "key_id": "key-1",
                "review_id": "short-policy", "reviewer_id": "reviewer", "reviewer_provider": "provider",
                "implementer_id": "implementer", "task_id": "task-1", "plan_revision": 1,
                "plan_digest": digest, "proposal_digest": canonical_mutation_proposal_digest(proposal),
                "verdict": "approve", "reviewed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
            encoded = canonical_signed_verdict(payload)
            signed = SignedMutationVerdict(encoded, self.private_key.sign(DOMAIN_PREFIX + encoded))
            lease = authority.record_signed_verdict("task-1", signed)
            self.assertEqual(lease.issued_at, now)
            self.assertEqual(lease.expires_at, now + timedelta(seconds=20))

    def test_shorter_policy_rejects_extended_lease_at_reservation(self):
        from engineering_gate_core.authorization_policy import AUTHORIZATION_TIMING_V1, AuthorizationTimingPolicy
        policy = AuthorizationTimingPolicy(max_review_age_seconds=30, max_active_lease_seconds=10)
        store = StateStore(self.path, timing_policy=policy)
        with self.assertRaises(AttributeError):
            store.timing_policy = AUTHORIZATION_TIMING_V1
        self.assertIs(store.timing_policy, policy)
        self.registry = __import__("engineering_gate_core.mutation_authority", fromlist=["ReviewerKeyRegistry"]).ReviewerKeyRegistry(store)
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, issued = self.verdict()
        store._record_verified_verdict("task-1", verified, payload, signature,
            authorization_id="auth-short", issued_at=issued, expires_at=issued + timedelta(seconds=10))
        connection = store._connect()
        connection.execute("UPDATE mutation_leases SET expires_at=? WHERE authorization_id=?",
            ((issued + timedelta(seconds=11)).strftime("%Y-%m-%dT%H:%M:%SZ"), "auth-short"))
        connection.commit()
        connection.close()
        with self.assertRaises(StateStoreError):
            store.reserve_mutation_lease("task-1", "auth-short", "b" * 64, issued)

    def test_timing_policy_cannot_exceed_v1_ceilings(self):
        from engineering_gate_core.authorization_policy import AuthorizationTimingPolicy
        with self.assertRaises(ValueError):
            AuthorizationTimingPolicy(max_review_age_seconds=301, max_active_lease_seconds=300)
        with self.assertRaises(ValueError):
            AuthorizationTimingPolicy(max_review_age_seconds=300, max_active_lease_seconds=301)

    def test_issue_persistence_uses_lease_limit_not_review_limit(self):
        from engineering_gate_core.authorization_policy import AuthorizationTimingPolicy
        from engineering_gate_core.signed_authorization import (
            DOMAIN_PREFIX, SignedMutationVerdict, canonical_signed_verdict, verify_signed_verdict,
        )
        policy = AuthorizationTimingPolicy(max_review_age_seconds=1, max_active_lease_seconds=30)
        store = StateStore(self.path, timing_policy=policy)
        self.registry.register_reviewer_key(self.key)
        issued = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=5)
        payload = {
            "schema_version": 1, "signature_algorithm": "Ed25519", "key_id": "key-1",
            "review_id": "review-issue-window", "reviewer_id": "reviewer", "reviewer_provider": "provider",
            "implementer_id": "implementer", "task_id": "task-1", "plan_revision": 1,
            "plan_digest": "a" * 64, "proposal_digest": "b" * 64, "verdict": "approve",
            "reviewed_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        encoded = canonical_signed_verdict(payload)
        signed = SignedMutationVerdict(encoded, self.private_key.sign(DOMAIN_PREFIX + encoded))
        verified = verify_signed_verdict(signed, self.key, now=issued,
            implementer_id="implementer", timing_policy=policy)

        lease = store._record_verified_verdict("task-1", verified, encoded, signed.signature,
            authorization_id="auth-issue-window", issued_at=issued, expires_at=issued + timedelta(seconds=30))

        self.assertEqual(lease.expires_at, issued + timedelta(seconds=30))

    def test_zero_review_age_remains_a_valid_stricter_policy(self):
        from engineering_gate_core.authorization_policy import AuthorizationTimingPolicy
        policy = AuthorizationTimingPolicy(max_review_age_seconds=0, max_active_lease_seconds=1)
        self.assertEqual(policy.max_review_age_seconds, 0)

    def test_authority_rejects_custom_timing_configuration(self):
        from engineering_gate_core.mutation_authority import GateMutationAuthority
        with self.assertRaises(TypeError):
            GateMutationAuthority(self.store, implementer_id="implementer", max_review_age_seconds=1)
        with self.assertRaises(TypeError):
            GateMutationAuthority(self.store, implementer_id="implementer", max_lease_seconds=1)

    def test_gate_authority_binds_persisted_workflow_and_lease_context(self):
        from dataclasses import replace
        from engineering_gate_core.models import (AcceptanceCriterion, ApprovalReceipt, ApprovalRequest,
            ExecutionPermit, MutationProposal, MutationScope, NormalizedOperation, OperationKind,
            Plan, PlanReview, PlanRevision, RequesterIdentity, ReviewVerdict, Task, TaskState, TaskStateRecord)
        from engineering_gate_core.mutation_authority import GateMutationAuthority, ReviewerKeyRegistry
        from engineering_gate_core.workflow import (canonical_plan_digest, canonical_mutation_proposal_digest,
            mutation_argument_digest, capture_workspace_identity)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "write")
        with tempfile.TemporaryDirectory() as workspace:
            plan = Plan("change", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",),
                        workspace_root=str(Path(workspace).resolve()))
            plan = replace(plan, workspace_identity=capture_workspace_identity(plan.workspace_root))
            digest = canonical_plan_digest(plan)
            task = Task("task-1", "change", RequesterIdentity("requester"))
            proposal = MutationProposal("proposal", "task-1", 1, digest, op, mutation_argument_digest("x"), "reviewed")
            state = TaskStateRecord(task, TaskState.IMPLEMENTING, PlanRevision(1), (TaskState.IMPLEMENTING,),
                plan=plan, plan_digest=digest, plan_review=PlanReview(ReviewVerdict.APPROVED),
                approval_request=ApprovalRequest("task-1", 1, digest, "request"),
                approval=ApprovalReceipt("request", "task-1", 1, digest, task.requester, True),
                permit=ExecutionPermit("task-1", 1, digest, MutationScope((op,))), mutation_proposal=proposal)
            from engineering_gate_core.workflow import new_task
            self.store.create(new_task("task-1", "change", task.requester))
            connection = self.store._connect()
            connection.execute("UPDATE task_state SET payload=? WHERE task_id=?", (__import__("engineering_gate_core.state_store", fromlist=["_record_json"])._record_json(state), "task-1"))
            connection.commit()
            connection.close()
            self.registry.register_reviewer_key(self.key)
            authority = GateMutationAuthority(self.store, implementer_id="implementer")
            authority._now = lambda: now
            from engineering_gate_core.signed_authorization import DOMAIN_PREFIX, SignedMutationVerdict, canonical_signed_verdict
            payload = {"schema_version": 1, "signature_algorithm": "Ed25519", "key_id": "key-1",
                "review_id": "review-authority", "reviewer_id": "reviewer", "reviewer_provider": "provider",
                "implementer_id": "implementer", "task_id": "task-1", "plan_revision": 1,
                "plan_digest": digest, "proposal_digest": canonical_mutation_proposal_digest(proposal),
                "verdict": "approve", "reviewed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
            encoded = canonical_signed_verdict(payload)
            signed = SignedMutationVerdict(encoded, self.private_key.sign(DOMAIN_PREFIX + encoded))
            lease = authority.record_signed_verdict("task-1", signed)
            self.assertEqual(lease.status, AuthorizationLeaseStatus.ACTIVE)
            active = authority.get_active_authorization("task-1", proposal)
            self.assertEqual(active.authorization_id, lease.authorization_id)
            with authority.acquire_write_lease("task-1", lease.authorization_id, proposal) as reserved:
                self.assertEqual(reserved.reservation_id, self.store.get_authorization(lease.authorization_id).reservation_id)
                reserved.mark_replacement_attempted()
                reserved.finalize("uncertain")
            self.assertEqual(self.store.get_authorization(lease.authorization_id).status, AuthorizationLeaseStatus.CONSUMED_UNCERTAIN)

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.store = StateStore(self.path)
        from engineering_gate_core.mutation_authority import ReviewerKeyRegistry
        self.registry = ReviewerKeyRegistry(self.store)
        self.private_key = Ed25519PrivateKey.generate()
        public = self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key = ReviewerPublicKey("key-1", "reviewer", "provider", public)

    def verdict(self, review_id="review-1", verdict="approve"):
        from engineering_gate_core.signed_authorization import DOMAIN_PREFIX, canonical_signed_verdict
        now = datetime.now(timezone.utc).replace(microsecond=0)
        payload = {"schema_version": 1, "signature_algorithm": "Ed25519", "key_id": "key-1",
            "review_id": review_id, "reviewer_id": "reviewer", "reviewer_provider": "provider",
            "implementer_id": "implementer", "task_id": "task-1", "plan_revision": 1,
            "plan_digest": "a" * 64, "proposal_digest": "b" * 64, "verdict": verdict,
            "reviewed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
        encoded = canonical_signed_verdict(payload)
        signature = self.private_key.sign(DOMAIN_PREFIX + encoded)
        from engineering_gate_core.signed_authorization import SignedMutationVerdict, verify_signed_verdict
        verified = verify_signed_verdict(SignedMutationVerdict(encoded, signature), self.key,
            now=now, implementer_id="implementer")
        return verified, encoded, signature, now

    def test_key_registration_and_revocation_persist(self):
        self.registry.register_reviewer_key(self.key)
        self.assertEqual(self.store.get_reviewer_key("key-1"), self.key)
        self.registry.revoke_reviewer_key("key-1", reason="rotation")
        self.assertTrue(self.store.get_reviewer_key("key-1").revoked)
        self.assertEqual(self.store.list_authorization_audit(key_id="key-1")[0][3:5], ("KEY_REVOKED", "rotation"))

    def test_approved_verdict_is_persisted_and_reserved_once(self):
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, issued = self.verdict()
        lease = self.store._record_verified_verdict("task-1", verified, payload, signature,
            authorization_id="auth-1", issued_at=issued, expires_at=issued + timedelta(seconds=300))
        self.assertIsInstance(lease, MutationLeaseRecord)
        self.assertEqual(lease.status, AuthorizationLeaseStatus.ACTIVE)
        active = self.store.get_active_authorization("task-1", "b" * 64)
        self.assertEqual(active.authorization_id, "auth-1")
        reserved = self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64, issued)
        self.assertEqual(reserved.status, AuthorizationLeaseStatus.RESERVED)
        with self.assertRaises(Exception):
            self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64, issued)

    def test_reject_verdict_is_audited_without_lease(self):
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, now = self.verdict(verdict="reject")
        self.assertIsNone(self.store._record_verified_verdict("task-1", verified,
            payload, signature, authorization_id=None, issued_at=None, expires_at=None))
        self.assertEqual(len(self.store.list_signed_verdicts("task-1")), 1)

    def test_key_revocation_blocks_existing_active_authorization(self):
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, issued = self.verdict()
        self.store._record_verified_verdict("task-1", verified, payload, signature,
            authorization_id="auth-1", issued_at=issued, expires_at=issued + timedelta(seconds=300))
        self.registry.revoke_reviewer_key("key-1", reason="compromised")
        self.assertEqual(self.store.get_authorization("auth-1").status, AuthorizationLeaseStatus.REVOKED)
        with self.assertRaises(Exception):
            self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64, issued)

    def test_revocation_after_reservation_does_not_expire_or_reuse_lease(self):
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, issued = self.verdict()
        self.store._record_verified_verdict("task-1", verified, payload, signature,
            authorization_id="auth-1", issued_at=issued, expires_at=issued + timedelta(seconds=300))
        reserved = self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64, datetime.now(timezone.utc))
        self.registry.revoke_reviewer_key("key-1", reason="rotation")
        current = self.store.get_authorization("auth-1")
        self.assertEqual(current.status, AuthorizationLeaseStatus.RESERVED)
        self.assertEqual(current.reservation_id, reserved.reservation_id)
        with self.assertRaises(Exception):
            self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64, datetime.now(timezone.utc))

    def test_reservation_and_key_revocation_serialize(self):
        import threading
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, issued = self.verdict()
        self.store._record_verified_verdict("task-1", verified, payload, signature,
            authorization_id="auth-1", issued_at=issued, expires_at=issued + timedelta(seconds=300))
        barrier = threading.Barrier(2)
        outcomes = []
        def reserve():
            barrier.wait()
            try:
                self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64, datetime.now(timezone.utc))
                outcomes.append("reserved")
            except Exception:
                outcomes.append("blocked")
        def revoke():
            barrier.wait()
            try:
                self.registry.revoke_reviewer_key("key-1", reason="race")
                outcomes.append("revoked")
            except Exception:
                outcomes.append("revoke-failed")
        threads = [threading.Thread(target=reserve), threading.Thread(target=revoke)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(5)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        status = self.store.get_authorization("auth-1").status
        self.assertIn(status, (AuthorizationLeaseStatus.REVOKED, AuthorizationLeaseStatus.RESERVED))
        self.assertIn("revoked", outcomes)
        if status is AuthorizationLeaseStatus.RESERVED:
            self.assertIn("reserved", outcomes)
        else:
            self.assertIn("blocked", outcomes)

    def test_known_completion_burns_reservation(self):
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, issued = self.verdict()
        self.store._record_verified_verdict("task-1", verified, payload, signature,
            authorization_id="auth-1", issued_at=issued, expires_at=issued + timedelta(seconds=300))
        reserved = self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64, datetime.now(timezone.utc))
        finished = self.store.finish_mutation_lease("auth-1", reserved.reservation_id, outcome="completed")
        self.assertEqual(finished.status, AuthorizationLeaseStatus.CONSUMED)
        with self.assertRaises(Exception):
            self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64, datetime.now(timezone.utc))

    def test_expired_active_lease_is_not_reservable(self):
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, issued = self.verdict()
        self.store._record_verified_verdict("task-1", verified, payload, signature,
            authorization_id="auth-1", issued_at=issued, expires_at=issued + timedelta(seconds=1))
        with self.assertRaises(Exception):
            self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64,
                issued + timedelta(seconds=2))
        self.assertEqual(self.store.get_authorization("auth-1").status, AuthorizationLeaseStatus.EXPIRED)

    def test_reservation_rejects_persisted_lease_with_extended_expiry(self):
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, issued = self.verdict()
        self.store._record_verified_verdict("task-1", verified, payload, signature,
            authorization_id="auth-1", issued_at=issued, expires_at=issued + timedelta(seconds=300))
        connection = self.store._connect()
        connection.execute("UPDATE mutation_leases SET expires_at=? WHERE authorization_id=?",
            ((issued + timedelta(seconds=301)).strftime("%Y-%m-%dT%H:%M:%SZ"), "auth-1"))
        connection.commit()
        connection.close()
        with self.assertRaises(Exception):
            self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64, issued)

    def test_reserved_lease_is_not_expired_by_later_clock(self):
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, issued = self.verdict()
        self.store._record_verified_verdict("task-1", verified, payload, signature,
            authorization_id="auth-1", issued_at=issued, expires_at=issued + timedelta(seconds=1))
        reserved = self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64,
            datetime.now(timezone.utc))
        # Finalization does not inspect wall-clock expiry after reservation.
        finished = self.store.finish_mutation_lease("auth-1", reserved.reservation_id, outcome="failed")
        self.assertEqual(finished.status, AuthorizationLeaseStatus.CONSUMED)

    def test_restart_consumes_reserved_lease_as_uncertain(self):
        self.registry.register_reviewer_key(self.key)
        verified, payload, signature, issued = self.verdict()
        self.store._record_verified_verdict("task-1", verified, payload, signature,
            authorization_id="auth-1", issued_at=issued, expires_at=issued + timedelta(seconds=300))
        self.store.reserve_mutation_lease("task-1", "auth-1", "b" * 64, issued)
        reopened = StateStore(self.path)
        self.assertEqual(reopened.get_authorization("auth-1").status, AuthorizationLeaseStatus.CONSUMED_UNCERTAIN)


if __name__ == "__main__":
    unittest.main()
