"""Fail-closed final write interception with an instance-local Gate tracer."""
from __future__ import annotations

import hashlib
import json
import time
import uuid

from ._core_import import import_core


class GateExecutionAdapter:
    """Profile-bound executor; absent reviewer provider always blocks."""

    def __init__(self, *, profile_home, profile_id, state_store_provider, approval_sidecar):
        self.profile_home = profile_home
        self.profile_id = profile_id
        self.state_store_provider = state_store_provider
        self.approval_sidecar = approval_sidecar
        self._reviewer_verdict_provider = None

    def intercept_write(self, tool_name, args, **context):
        from hermes_cli.plugins import ExecutionDecision
        try:
            result = self._execute(tool_name, args, context)
            return ExecutionDecision.handled(result)
        except Exception as exc:
            self._last_error = repr(exc)
            return ExecutionDecision.block("Gate write authorization is unavailable.")

    def _execute(self, tool_name, args, context):
        return self._execute_inner(tool_name, args, context)

    def _execute_inner(self, tool_name, args, context):
        if tool_name != "write_file" or type(args) is not dict or set(args) != {"path", "content"}:
            raise PermissionError("unsupported write shape")
        from .context import TrustedTelegramContext
        from .approval_sidecar import ApprovalSidecar
        models = import_core("models")
        ExecutionPermit, MutationScope, MutationProposal = models.ExecutionPermit, models.MutationScope, models.MutationProposal
        OperationKind, TaskState = models.OperationKind, models.TaskState
        workflow = import_core("workflow")
        Event, mutation_argument_digest, canonical_plan_digest = workflow.Event, workflow.mutation_argument_digest, workflow.canonical_plan_digest
        GateMutationAuthority = import_core("mutation_authority").GateMutationAuthority
        GateWriteService = import_core("a3_execution").GateWriteService
        GateVerificationRunner = import_core("verification_execution").GateVerificationRunner
        from pathlib import Path
        trusted = TrustedTelegramContext.resolve(context, plugin_profile=self.profile_id)
        task_id = context.get("task_id")
        if (trusted is None
                or not isinstance(task_id, str) or not task_id or task_id.strip() != task_id
                or context.get("turn_id") != trusted.turn_id
                or context.get("tool_call_id") != trusted.tool_call_id):
            raise PermissionError("untrusted write context")
        record = self.approval_sidecar.find_unique_approved_for_context(
            self.profile_id, trusted.session_id, trusted.requester_id, int(trusted.chat_id))
        if record is None or task_id != record["task_id"]:
            raise PermissionError("no unique matching delivered approval")
        store = self.state_store_provider(self.profile_id)
        task_id = record["task_id"]
        state = store.load(task_id)
        request = state.approval_request
        if (state.state is not TaskState.APPROVED or state.plan is None or request is None
                or state.task.requester.subject != f"telegram:{trusted.requester_id}"
                or (request.task_id, request.revision, request.digest) !=
                   (state.task_id, state.revision, state.plan_digest)
                or canonical_plan_digest(state.plan) != state.plan_digest
                or state.plan.workspace_identity is None):
            raise PermissionError("no current approved task")
        if record["approval_request_id"] != request.request_id:
            raise PermissionError("sidecar request does not match current Gate request")
        from dataclasses import asdict
        canonical_plan_digest = import_core("workflow").canonical_plan_digest
        displayed_plan = json.dumps(asdict(state.plan), sort_keys=True, separators=(",", ":")) + "\n\nCanonical plan digest: " + canonical_plan_digest(state.plan)
        expected_display_digest = hashlib.sha256(displayed_plan.encode("utf-8")).hexdigest()
        if record is None or record.get("plan_display_digest") != expected_display_digest:
            raise PermissionError("Stage-1 displayed plan digest does not match current approved plan")
        if record.get("expires_at", 0) <= time.time():
            raise PermissionError("Stage-1 approval has expired")
        if not record["delivered"] or any(record.get(k) != v for k,v in {
            "session_id":trusted.session_id,"telegram_user_id":trusted.requester_id,
            "telegram_chat_id":int(trusted.chat_id),"plan_revision":int(state.revision),
            "plan_digest":str(state.plan_digest),"approval_request_id":request.request_id,
            "workspace_identity":{"canonical_path":state.plan.workspace_identity.canonical_path,
                "device":state.plan.workspace_identity.device,"inode":state.plan.workspace_identity.inode}}.items()):
            raise PermissionError("no unique matching delivered approval")
        # Current route is checked against Telegram's live SessionStore via the host adapter.
        from gateway import session_context
        from gateway.session import SessionStore
        from gateway.config import GatewayConfig
        route_store = SessionStore(Path(self.profile_home)/"sessions", GatewayConfig())
        if route_store.peek_session_id(trusted.session_key) != trusted.session_id:
            raise PermissionError("live Telegram route does not match approved session")
        provider = self._reviewer_verdict_provider
        if not callable(provider):
            raise PermissionError("reviewer verdict provider is not configured")
        target, content = args["path"], args["content"]
        if type(target) is not str or type(content) is not str:
            raise PermissionError("invalid write arguments")
        operation = next((op for op in state.plan.operations
                          if op.kind is OperationKind.WRITE and op.target == target), None)
        if operation is None:
            raise PermissionError("final rewritten target is outside the approved plan")
        if state.state is TaskState.APPROVED:
            permit = ExecutionPermit(state.task_id, state.revision, state.plan_digest, MutationScope(tuple(state.plan.operations)))
            state = store.transition(task_id, Event.IMPLEMENTATION_STARTED, permit)
        proposal = MutationProposal(uuid.uuid4().hex, state.task_id, state.revision, state.plan_digest,
            operation, mutation_argument_digest(content), "Write exact final dispatcher arguments")
        store.record_mutation_proposal(task_id, proposal)
        authority = GateMutationAuthority(store, implementer_id="engineering-gate-hermes")
        try:
            verdict = provider(task_id, proposal)
            authority.record_signed_verdict(task_id, verdict)
        except Exception:
            # No safe retry transition exists in the frozen core. Fail the task
            # terminally so a later dispatch cannot reuse an ambiguous proposal.
            store.transition(task_id, Event.FAIL)
            raise
        root = Path(state.plan.workspace_identity.canonical_path)
        with GateWriteService(root, state_store=store, mutation_authority=authority) as writer:
            permit = writer.issue_permit(task_id=task_id, operation=operation, arguments={"content":content})
            written = writer.execute(permit, task_id=task_id, operation=operation, arguments={"content":content})
        if written.read_bytes() != content.encode("utf-8"):
            raise PermissionError("Gate readback mismatch")
        try:
            verification = GateVerificationRunner(store).run_all(task_id)
            if not verification.verification or not all(item.passed for item in verification.verification):
                raise PermissionError("Gate verification failed")
        except Exception:
            # Bytes are already committed and the lease/audit consumed. Return
            # an explicit partial-success result; never present it as a block.
            return json.dumps({"gate_owned": True, "target": target,
                "bytes": len(content.encode("utf-8")), "write_committed": True,
                "verification": "failed", "further_mutation": "blocked"})
        return __import__("json").dumps({"gate_owned":True,"target":target,"bytes":len(content.encode("utf-8"))})


__all__ = ["GateExecutionAdapter"]
