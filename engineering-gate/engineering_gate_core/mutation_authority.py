"""Gate-owned signed reviewer authority and durable one-shot WRITE leases."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4


from .models import AuthorizationLeaseStatus, MutationLeaseRecord, MutationProposal, TaskState
from .signed_authorization import SignedMutationVerdict, verify_signed_verdict
from .state_store import StateStore
from .workflow import canonical_mutation_proposal_digest, canonical_plan_digest


class MutationAuthorityError(ValueError):
    """Signed authorization cannot be accepted or used in the current workflow."""


class ReviewerKeyRegistry:
    """Trusted operator capability for provisioning reviewer signing keys."""
    def __init__(self, store):
        if type(store) is not StateStore:
            raise ValueError("StateStore is required")
        self._store = store

    def register_reviewer_key(self, key_record):
        self._store._register_reviewer_key(key_record)

    def revoke_reviewer_key(self, key_id, *, reason):
        self._store._revoke_reviewer_key(key_id, reason=reason)


@dataclass
class MutationLease:
    """A durably reserved, one-use lease held around one WRITE attempt."""
    record: MutationLeaseRecord
    _replacement_attempted: bool = False
    _outcome: str | None = None

    @property
    def authorization_id(self):
        return self.record.authorization_id

    @property
    def reservation_id(self):
        return self.record.reservation_id

    def mark_replacement_attempted(self):
        self._replacement_attempted = True

    def finalize(self, outcome):
        if outcome not in ("completed", "failed", "uncertain"):
            raise ValueError("outcome must be completed, failed, or uncertain")
        self._outcome = outcome

    def complete(self):
        self.finalize("completed")

    def fail(self):
        self.finalize("failed")


class GateMutationAuthority:
    def __init__(self, store, *, implementer_id):
        if type(store) is not StateStore or type(implementer_id) is not str or not implementer_id.strip():
            raise ValueError("StateStore and immutable implementer_id are required")
        self._store = store
        self._implementer_id = implementer_id
        self._clock_high_water = None

    def _now(self):
        now = datetime.now(timezone.utc)
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise MutationAuthorityError("trusted clock must return UTC-aware time")
        now = now.astimezone(timezone.utc).replace(microsecond=0)
        if self._clock_high_water is not None and now < self._clock_high_water:
            raise MutationAuthorityError("trusted UTC clock moved backwards")
        self._clock_high_water = now
        return now

    def is_bound_to(self, store):
        """Check binding without exposing the underlying store capability."""
        return self._store is store

    @staticmethod
    def _current_binding(state, task_id, proposal):
        if (state.state is not TaskState.IMPLEMENTING or state.plan is None
                or state.mutation_proposal is None or state.plan_digest != canonical_plan_digest(state.plan)
                or state.plan.workspace_identity is None):
            raise MutationAuthorityError("task must have a current implementing plan and proposal")
        request, receipt, permit = state.approval_request, state.approval, state.permit
        digest = state.plan_digest
        if (state.task_id != str(task_id) or state.plan_review is None
                or getattr(state.plan_review.verdict, "value", None) != "approved"
                or request is None or receipt is None or not receipt.approved
                or (request.task_id, request.revision, request.digest) != (state.task_id, state.revision, digest)
                or (receipt.request_id, receipt.task_id, receipt.revision, receipt.digest, receipt.requester)
                   != (request.request_id, state.task_id, state.revision, digest, state.task.requester)
                or permit is None or (permit.task_id, permit.revision, permit.digest) != (state.task_id, state.revision, digest)
                or state.mutation_proposal.task_id != state.task_id
                or state.mutation_proposal.revision != state.revision
                or state.mutation_proposal.plan_digest != digest
                or state.mutation_proposal.operation not in state.plan.operations):
            raise MutationAuthorityError("task lacks current independent requester approval and scoped plan permit")
        if proposal is not None and (type(proposal) is not MutationProposal
                or canonical_mutation_proposal_digest(proposal) != canonical_mutation_proposal_digest(state.mutation_proposal)):
            raise MutationAuthorityError("proposal does not exactly match current task proposal")
        if state.mutation_proposal.operation not in permit.scope.operations:
            raise MutationAuthorityError("proposal is outside current permit scope")
        return state, canonical_mutation_proposal_digest(state.mutation_proposal)


    def record_signed_verdict(self, task_id, verdict):
        if type(verdict) is not SignedMutationVerdict:
            raise MutationAuthorityError("SignedMutationVerdict required")
        now = self._now()
        state = self._store.load(task_id)
        state, proposal_digest = self._current_binding(state, task_id, None)
        key_id = self._payload_key_id(verdict)
        key = self._store.get_reviewer_key(key_id)
        verified = verify_signed_verdict(verdict, key, now=now, implementer_id=self._implementer_id,
            timing_policy=self._store.timing_policy)
        if (verified.task_id != str(task_id) or verified.plan_revision != int(state.revision)
                or verified.plan_digest != str(state.plan_digest) or verified.proposal_digest != proposal_digest):
            raise MutationAuthorityError("signed verdict does not match current task, plan, or proposal")
        if verified.verdict == "reject":
            self._store._record_verified_verdict(task_id, verified, verdict.canonical_payload,
                verdict.signature, authorization_id=None, issued_at=None, expires_at=None)
            return None
        issued = now
        return self._store._record_verified_verdict(task_id, verified, verdict.canonical_payload,
            verdict.signature, authorization_id=uuid4().hex, issued_at=issued,
            expires_at=issued + timedelta(seconds=self._store.timing_policy.max_active_lease_seconds))

    @staticmethod
    def _payload_key_id(verdict):
        import json
        from .signed_authorization import _pairs_no_duplicates
        try:
            payload = json.loads(verdict.canonical_payload.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
            key_id = payload.get("key_id") if type(payload) is dict else None
        except Exception as exc:
            raise MutationAuthorityError("malformed signed verdict") from exc
        if type(key_id) is not str or not key_id:
            raise MutationAuthorityError("signed verdict key_id is required")
        return key_id

    def get_active_authorization(self, task_id, proposal):
        state = self._store.load(task_id)
        state, proposal_digest = self._current_binding(state, task_id, proposal)
        now = self._now()
        record = self._store.get_active_authorization(task_id, proposal_digest)
        if (record.status is not AuthorizationLeaseStatus.ACTIVE or record.expires_at <= now
                or record.plan_revision != int(state.revision) or record.plan_digest != str(state.plan_digest)
                or record.implementer_id != self._implementer_id):
            raise MutationAuthorityError("no unexpired exact current ACTIVE authorization")
        return record

    def revoke(self, authorization_id, *, reason):
        return self._store.revoke_mutation_authorization(authorization_id, reason=reason)

    @contextmanager
    def acquire_write_lease(self, task_id, authorization_id, proposal):
        state = self._store.load(task_id)
        state, proposal_digest = self._current_binding(state, task_id, proposal)
        now = self._now()
        current = self._store.get_authorization(authorization_id)
        if (current.task_id != str(task_id) or current.proposal_digest != proposal_digest
                or current.plan_revision != int(state.revision) or current.plan_digest != str(state.plan_digest)
                or current.implementer_id != self._implementer_id):
            raise MutationAuthorityError("authorization binding does not match current proposal")
        reserved = self._store.reserve_mutation_lease(task_id, authorization_id, proposal_digest, now)
        lease = MutationLease(reserved)
        try:
            yield lease
        except BaseException:
            self._store.finish_mutation_lease(authorization_id, reserved.reservation_id,
                outcome="uncertain" if lease._replacement_attempted else "failed")
            raise
        else:
            outcome = lease._outcome or ("uncertain" if lease._replacement_attempted else "failed")
            self._store.finish_mutation_lease(authorization_id, reserved.reservation_id, outcome=outcome)


__all__ = ["GateMutationAuthority", "MutationAuthorityError", "MutationLease", "ReviewerKeyRegistry"]
