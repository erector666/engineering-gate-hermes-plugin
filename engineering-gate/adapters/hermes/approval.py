"""Gate-owned Telegram DM approval broker; never delegates consent to Hermes EA."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import fields, is_dataclass
from enum import Enum

from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import CallbackQueryHandler

from ._core_import import import_core
from .approval_sidecar import ApprovalSidecar

_models = import_core("models")
ApprovalReceipt, Plan, TaskState = _models.ApprovalReceipt, _models.Plan, _models.TaskState
TaskStateRecord = _models.TaskStateRecord
StateStoreError = import_core("state_store").StateStoreError
_workflow = import_core("workflow")
canonical_plan_digest = _workflow.canonical_plan_digest
capture_workspace_identity = _workflow.capture_workspace_identity

_APPROVAL_PACKET_KEYS = frozenset({"task_objective", "inspection_evidence", "analysis", "plan", "blast_radius", "plan_review", "plan_revision", "plan_digest", "workspace_identity", "approval_request_id", "profile_id"})


def _valid_approval_packet(body, digest):
    if type(body) is not str or type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return False
    try:
        packet = json.loads(body)
        if type(packet) is not dict or set(packet) != _APPROVAL_PACKET_KEYS:
            return False
        canonical = json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return False
    return canonical == body and hashlib.sha256(body.encode("utf-8")).hexdigest() == digest


def _canonical_value(value):
    """Convert core values to deterministic, JSON-safe structures."""
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _canonical_value(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise TypeError("approval packet contains a non-serializable value")


def canonical_approval_packet(state, profile_id=None):
    """Build the exact packet disclosed to a reviewer and Stage-1 digest binding."""
    plan = state.plan
    workspace = None if plan is None else plan.workspace_identity
    request = state.approval_request
    packet = {
        "task_objective": state.task.objective,
        "inspection_evidence": state.inspection,
        "analysis": state.analysis,
        "plan": plan,
        "blast_radius": state.blast_radius,
        "plan_review": state.plan_review,
        "plan_revision": state.revision,
        "plan_digest": state.plan_digest,
        "workspace_identity": None if workspace is None else {
            "canonical_path": workspace.canonical_path, "device": workspace.device, "inode": workspace.inode,
        },
        "approval_request_id": None if request is None else request.request_id,
        "profile_id": profile_id,
    }
    body = json.dumps(_canonical_value(packet), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return body, hashlib.sha256(body.encode("utf-8")).hexdigest()


def _state_packet_binding(*, approval_state, profile_id, task_id, plan_revision,
                          plan_payload, plan_digest, workspace_identity,
                          approval_request_id, telegram_user_id,
                          approval_packet_body, approval_packet_digest):
    """Fail closed unless all separately supplied fields bind to this state packet."""
    if type(approval_state) is not TaskStateRecord:
        return False
    try:
        state = approval_state
        plan = state.plan
        request = state.approval_request
        identity = plan.workspace_identity if plan is not None else None
        if (state.state is not TaskState.AWAITING_APPROVAL or plan is None or request is None
                or identity is None or state.task_id != task_id
                or int(state.revision) != plan_revision or plan != plan_payload
                or str(state.plan_digest) != plan_digest
                or request.request_id != approval_request_id
                or type(workspace_identity) is not dict
                or workspace_identity != {"canonical_path": identity.canonical_path,
                                          "device": identity.device, "inode": identity.inode}
                or state.task.requester.subject != f"telegram:{telegram_user_id}"):
            return False
        expected_body, expected_digest = canonical_approval_packet(state, profile_id)
        return (approval_packet_body == expected_body
                and approval_packet_digest == expected_digest
                and _valid_approval_packet(approval_packet_body, approval_packet_digest))
    except Exception:
        return False


class GateApprovalService:
    """Create and consume approvals bound to a fully delivered Telegram prompt."""

    def __init__(self, profile_home, *, bot, render_plan, clock=None,
                 profile_id=None, state_store_provider=None):
        self.sidecar = ApprovalSidecar(profile_home)
        self.bot = bot
        self.render_plan = render_plan
        self.clock = clock or time.time
        self.profile_id = profile_id
        self.state_store_provider = state_store_provider
        self.futures = {}

    @staticmethod
    def _binding(*, profile_id, session_id, telegram_user_id, telegram_chat_id,
                 task_id, plan_revision, plan_digest, workspace_identity,
                 approval_request_id, approval_packet_digest):
        return dict(profile_id=profile_id, session_id=session_id,
                    telegram_user_id=telegram_user_id, telegram_chat_id=telegram_chat_id,
                    task_id=task_id, plan_revision=plan_revision, plan_digest=plan_digest,
                    workspace_identity=workspace_identity,
                    approval_request_id=approval_request_id,
                    approval_packet_digest=approval_packet_digest)

    def create_pending(self, *, profile_id, session_id, telegram_user_id, telegram_chat_id,
                       task_id, plan_revision, plan_payload, plan_digest,
                       workspace_identity, approval_request_id, plan_text, timeout_seconds,
                       approval_state, approval_packet_body, approval_packet_digest):
        try:
            if (type(telegram_user_id) is not int or telegram_user_id <= 0
                    or type(telegram_chat_id) is not int or telegram_chat_id != telegram_user_id
                    or type(plan_revision) is not int or plan_revision < 0
                    or type(timeout_seconds) not in (int, float) or timeout_seconds <= 0
                    or type(plan_payload) is not Plan
                    or str(canonical_plan_digest(plan_payload)) != plan_digest):
                return None
            if not _state_packet_binding(approval_state=approval_state, profile_id=profile_id,
                    task_id=task_id, plan_revision=plan_revision, plan_payload=plan_payload,
                    plan_digest=plan_digest, workspace_identity=workspace_identity,
                    approval_request_id=approval_request_id, telegram_user_id=telegram_user_id,
                    approval_packet_body=approval_packet_body,
                    approval_packet_digest=approval_packet_digest):
                return None
            if type(approval_packet_digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", approval_packet_digest):
                return None
            if type(plan_text) is not str or not plan_text:
                return None
            exact_suffix = "\n\nApproval packet digest: " + approval_packet_digest
            if not plan_text.endswith(exact_suffix):
                return None
            packet_body = plan_text[:-len(exact_suffix)]
            if not _valid_approval_packet(packet_body, approval_packet_digest):
                return None
            now = self.clock()
            binding = self._binding(profile_id=profile_id, session_id=session_id,
                telegram_user_id=telegram_user_id, telegram_chat_id=telegram_chat_id,
                task_id=task_id, plan_revision=plan_revision, plan_digest=plan_digest,
                workspace_identity=workspace_identity, approval_request_id=approval_request_id,
                approval_packet_digest=approval_packet_digest)
            data = dict(binding,
                        created_at=now, expires_at=now + timeout_seconds)
            nonce = self.sidecar.create_pending(**data)
            return type("Pending", (), {"nonce": nonce, "data": data})()
        except Exception:
            return None

    def consume_callback(self, nonce, *, actor_id, chat_id, chat_type, choice, expected_context):
        return self.sidecar.consume_callback(nonce, actor_id=actor_id, chat_id=chat_id,
            chat_type=chat_type, choice=choice, expected_context=expected_context)

    async def request(self, *, profile_id, session_id, telegram_user_id, telegram_chat_id,
                      task_id, plan_revision, plan_payload, plan_digest, workspace_identity,
                      approval_request_id, timeout_seconds, approval_state,
                      approval_packet_body, approval_packet_digest):
        try:
            if type(plan_payload) is not Plan or str(canonical_plan_digest(plan_payload)) != plan_digest:
                return False
            if not _valid_approval_packet(approval_packet_body, approval_packet_digest):
                return False
            if not _state_packet_binding(approval_state=approval_state, profile_id=profile_id,
                    task_id=task_id, plan_revision=plan_revision, plan_payload=plan_payload,
                    plan_digest=plan_digest, workspace_identity=workspace_identity,
                    approval_request_id=approval_request_id, telegram_user_id=telegram_user_id,
                    approval_packet_body=approval_packet_body,
                    approval_packet_digest=approval_packet_digest):
                return False
            text = approval_packet_body + "\n\nApproval packet digest: " + approval_packet_digest
            if not text or len(text) > 1_000_000:
                return False
            chunks = [text[i:i + 4096] for i in range(0, len(text), 4096)]
            binding = self._binding(profile_id=profile_id, session_id=session_id,
                telegram_user_id=telegram_user_id, telegram_chat_id=telegram_chat_id,
                task_id=task_id, plan_revision=plan_revision, plan_digest=plan_digest,
                workspace_identity=workspace_identity, approval_request_id=approval_request_id,
                approval_packet_digest=approval_packet_digest)
            pending = self.create_pending(**binding, plan_payload=plan_payload,
                                          plan_text=text, timeout_seconds=timeout_seconds,
                                          approval_state=approval_state,
                                          approval_packet_body=approval_packet_body)
            if pending is None:
                return False
            future = asyncio.get_running_loop().create_future()
            self.futures[pending.nonce] = (future, asyncio.get_running_loop(), dict(pending.data))
            for chunk in chunks:
                sent = await self.bot.send_message(chat_id=telegram_chat_id, text=chunk)
                if (type(getattr(sent, "message_id", None)) is not int or sent.message_id <= 0
                        or getattr(getattr(sent, "chat", None), "id", None) != telegram_chat_id):
                    raise RuntimeError("plan chunk delivery not confirmed in destination chat")
            keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("Approve once", callback_data=f"eg1:{pending.nonce}:approve_once"),
                InlineKeyboardButton("Deny", callback_data=f"eg1:{pending.nonce}:deny")]])
            prompt = await self.bot.send_message(chat_id=telegram_chat_id,
                text="Approve this exact Engineering Gate approval packet?", reply_markup=keyboard)
            prompt_id = getattr(prompt, "message_id", None)
            if (type(prompt_id) is not int or prompt_id <= 0
                    or getattr(getattr(prompt, "chat", None), "id", None) != telegram_chat_id):
                raise RuntimeError("approval controls delivery not confirmed in destination chat")
            if not self.sidecar.mark_prompt_delivered(pending.nonce, profile_id=profile_id,
                    prompt_message_id=prompt_id, plan_chunks_confirmed=True, buttons_sent=True):
                raise RuntimeError("durable prompt delivery confirmation failed")
            return bool(await asyncio.wait_for(future, timeout=timeout_seconds))
        except asyncio.CancelledError:
            if 'pending' in locals() and pending is not None:
                self.sidecar.invalidate(pending.nonce, profile_id)
            raise
        except Exception:
            if 'pending' in locals() and pending is not None:
                self.sidecar.invalidate(pending.nonce, profile_id)
            return False
        finally:
            if 'pending' in locals() and pending is not None:
                self.futures.pop(pending.nonce, None)

    def register_telegram_handler(self, ctx):
        def factory(application, adapter):
            bot = application.bot
            self.bot = bot
            async def callback(update, context):
                query = getattr(update, "callback_query", None)
                message = getattr(query, "message", None)
                chat = getattr(message, "chat", None)
                user = getattr(query, "from_user", None)
                raw = getattr(query, "data", None)
                match = re.fullmatch(r"eg1:([A-Za-z0-9_-]{43}):(approve_once|deny)", raw or "")
                if not match or getattr(chat, "type", None) != "private":
                    return
                nonce, choice = match.groups()
                if self.profile_id is None or self.state_store_provider is None:
                    return
                record = self.sidecar.get(nonce, profile_id=self.profile_id)
                if (record is None or not record["delivered"] or record["state"] != "pending"
                        or type(getattr(user, "id", None)) is not int
                        or chat.id != record["telegram_chat_id"]
                        or user.id != record["telegram_user_id"]
                        or getattr(message, "message_id", None) != record["prompt_message_id"]):
                    return
                try:
                    source_builder = getattr(adapter, "_source_from_message_for_auth", None)
                    key_builder = getattr(adapter, "_source_session_key", None)
                    session_store = getattr(adapter, "_session_store", None)
                    peek_session_id = getattr(session_store, "peek_session_id", None)
                    if not (callable(source_builder) and callable(key_builder)
                            and callable(peek_session_id)):
                        return
                    source = source_builder(message)
                    callback_profile = getattr(adapter, "_session_key_profile", None)
                    if not callable(callback_profile):
                        return
                    callback_profile_id = callback_profile(source) or "default"
                    if callback_profile_id != record["profile_id"]:
                        return
                    route_key = key_builder(source)
                    if peek_session_id(route_key) != record["session_id"]:
                        return
                    store = self.state_store_provider(self.profile_id)
                    current = store.load(record["task_id"])
                    plan = current.plan
                    if (current.state is not TaskState.AWAITING_APPROVAL or plan is None
                            or current.approval_request is None
                            or current.task.requester.subject != f"telegram:{user.id}"
                            or (current.approval_request.request_id, str(current.approval_request.task_id),
                                int(current.approval_request.revision), str(current.approval_request.digest)) !=
                               (record["approval_request_id"], record["task_id"], record["plan_revision"], record["plan_digest"])
                            or str(current.task_id) != record["task_id"]
                            or int(current.revision) != record["plan_revision"]
                            or str(current.plan_digest) != record["plan_digest"]
                            or str(canonical_plan_digest(plan)) != record["plan_digest"]
                            or canonical_approval_packet(current, record["profile_id"])[1] != record["approval_packet_digest"]
                            or plan.workspace_identity is None
                            or capture_workspace_identity(plan.workspace_root) != plan.workspace_identity
                            or {"canonical_path": plan.workspace_identity.canonical_path,
                                "device": plan.workspace_identity.device, "inode": plan.workspace_identity.inode}
                               != record["workspace_identity"]):
                        return
                    result = self.consume_callback(nonce, actor_id=user.id, chat_id=chat.id,
                        chat_type="private", choice=choice, expected_context={k: record[k]
                            for k in ApprovalSidecar._REQUIRED})
                    if result:
                        receipt = ApprovalReceipt(current.approval_request.request_id,
                            current.task_id, current.revision, current.plan_digest,
                            current.task.requester, bool(result[1]))
                        updated = store.record_approval(current.task_id, receipt)
                        if updated.approval != receipt or updated.state is not (
                                TaskState.APPROVED if result[1] else TaskState.REJECTED):
                            return
                        pending = self.futures.get(nonce)
                        if pending:
                            future, owning_loop = pending[0], pending[1]
                            def resolve_future():
                                if not future.done():
                                    future.set_result(bool(result[1]))
                            owning_loop.call_soon_threadsafe(resolve_future)
                except Exception:
                    return
                try:
                    await query.answer()
                except Exception:
                    pass
            application.add_handler(CallbackQueryHandler(callback, pattern=r"^eg1:"), group=100)
            self.registered_bot = bot
        ctx.register_telegram_handler(factory)


GateApproval = GateApprovalService
__all__ = ["GateApprovalService", "GateApproval"]
