"""Gate-owned Telegram DM approval broker; never delegates consent to Hermes EA."""
from __future__ import annotations

import asyncio
import hashlib
import re
import time

from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import CallbackQueryHandler

from ._core_import import import_core
from .approval_sidecar import ApprovalSidecar

_models = import_core("models")
ApprovalReceipt, Plan, TaskState = _models.ApprovalReceipt, _models.Plan, _models.TaskState
StateStoreError = import_core("state_store").StateStoreError
_workflow = import_core("workflow")
canonical_plan_digest = _workflow.canonical_plan_digest
capture_workspace_identity = _workflow.capture_workspace_identity


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
                 approval_request_id):
        return dict(profile_id=profile_id, session_id=session_id,
                    telegram_user_id=telegram_user_id, telegram_chat_id=telegram_chat_id,
                    task_id=task_id, plan_revision=plan_revision, plan_digest=plan_digest,
                    workspace_identity=workspace_identity,
                    approval_request_id=approval_request_id)

    def create_pending(self, *, profile_id, session_id, telegram_user_id, telegram_chat_id,
                       task_id, plan_revision, plan_payload, plan_digest,
                       workspace_identity, approval_request_id, plan_text, timeout_seconds):
        try:
            if (type(telegram_user_id) is not int or telegram_user_id <= 0
                    or type(telegram_chat_id) is not int or telegram_chat_id != telegram_user_id
                    or type(plan_revision) is not int or plan_revision < 0
                    or type(timeout_seconds) not in (int, float) or timeout_seconds <= 0
                    or type(plan_payload) is not Plan
                    or str(canonical_plan_digest(plan_payload)) != plan_digest):
                return None
            rendered = self.render_plan(plan_payload)
            trusted_text = f"{rendered}\n\nCanonical plan digest: {plan_digest}"
            if type(plan_text) is not str or not plan_text or trusted_text != plan_text:
                return None
            now = self.clock()
            binding = self._binding(profile_id=profile_id, session_id=session_id,
                telegram_user_id=telegram_user_id, telegram_chat_id=telegram_chat_id,
                task_id=task_id, plan_revision=plan_revision, plan_digest=plan_digest,
                workspace_identity=workspace_identity, approval_request_id=approval_request_id)
            data = dict(binding, plan_display_digest=hashlib.sha256(plan_text.encode("utf-8")).hexdigest(),
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
                      approval_request_id, timeout_seconds):
        try:
            if type(plan_payload) is not Plan or str(canonical_plan_digest(plan_payload)) != plan_digest:
                return False
            text = f"{self.render_plan(plan_payload)}\n\nCanonical plan digest: {plan_digest}"
            if not text or len(text) > 1_000_000:
                return False
            chunks = [text[i:i + 4096] for i in range(0, len(text), 4096)]
            binding = self._binding(profile_id=profile_id, session_id=session_id,
                telegram_user_id=telegram_user_id, telegram_chat_id=telegram_chat_id,
                task_id=task_id, plan_revision=plan_revision, plan_digest=plan_digest,
                workspace_identity=workspace_identity, approval_request_id=approval_request_id)
            pending = self.create_pending(**binding, plan_payload=plan_payload,
                                          plan_text=text, timeout_seconds=timeout_seconds)
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
                text="Approve this exact plan?", reply_markup=keyboard)
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
