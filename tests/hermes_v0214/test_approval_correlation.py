import asyncio
import hashlib
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engineering-gate"))
from adapters.hermes.approval import GateApprovalService  # noqa: E402
from adapters.hermes.approval_sidecar import ApprovalSidecar  # noqa: E402
from engineering_gate_core.models import (Plan, NormalizedOperation, OperationKind, AcceptanceCriterion,
    Task, TaskState, TaskStateRecord, PlanRevision, InspectionEvidenceRef, Evidence,
    WorkspaceIdentity, PlanReview, ReviewVerdict, ApprovalRequest, RequesterIdentity)
from engineering_gate_core.workflow import canonical_plan_digest

PLAN = Plan("objective", (NormalizedOperation(OperationKind.READ, "src", "inspect"),),
            (AcceptanceCriterion("c1", "checked", "run tests"),), ("pytest",),
            workspace_root="/workspace", workspace_identity=WorkspaceIdentity("/workspace", 1, 2))

def render_plan(plan):
    return json.dumps(asdict(plan), sort_keys=True, separators=(",", ":"))

def approval_state(analysis="exact evidence"):
    from engineering_gate_core.models import PlanDigest
    plan = PLAN
    return TaskStateRecord(Task("task-1", "objective", RequesterIdentity("telegram:42")),
        TaskState.AWAITING_APPROVAL, PlanRevision(2), (TaskState.AWAITING_APPROVAL,),
        inspection=InspectionEvidenceRef("inspection", "inspected src"),
        analysis=Evidence("analysis", analysis), plan=plan, plan_digest=PlanDigest(str(canonical_plan_digest(plan))),
        blast_radius=Evidence("blast", "limited to src"), plan_review=PlanReview(ReviewVerdict.APPROVED),
        approval_request=ApprovalRequest("task-1", PlanRevision(2), PlanDigest(str(canonical_plan_digest(plan))), "approval-1"))

def packet_data(state):
    from adapters.hermes.approval import canonical_approval_packet
    body, digest = canonical_approval_packet(state, "main")
    return body, digest


def packet_text(body, digest):
    return body + "\n\nApproval packet digest: " + digest


def scope(**overrides):
    data = dict(profile_id="main", session_id="session-1", telegram_user_id=42,
                telegram_chat_id=42, task_id="task-1", plan_revision=2,
                plan_payload=PLAN, plan_digest=str(canonical_plan_digest(PLAN)),
                workspace_identity={"canonical_path": "/workspace", "device": 1, "inode": 2},
                approval_request_id="approval-1")
    data.update(overrides)
    return data

class Bot:
    def __init__(self, fail_at=None): self.calls, self.fail_at = [], fail_at
    async def send_message(self, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) == self.fail_at: raise RuntimeError("send failed")
        return SimpleNamespace(message_id=len(self.calls), chat=SimpleNamespace(id=kwargs["chat_id"]))

def test_create_pending_uses_exact_durable_binding_and_display_hash(tmp_path):
    service = GateApprovalService(tmp_path, bot=None, render_plan=render_plan, clock=lambda: 100)
    state = approval_state()
    body, digest = packet_data(state)
    text = packet_text(body, digest)
    pending = service.create_pending(**scope(), approval_state=state, approval_packet_body=body, approval_packet_digest=digest,
        plan_text=text, timeout_seconds=30)
    assert pending is not None
    record = service.sidecar.get(pending.nonce, profile_id="main")
    assert record == dict(profile_id="main", session_id="session-1", telegram_user_id=42,
        telegram_chat_id=42, task_id="task-1", plan_revision=2, plan_digest=scope()["plan_digest"],
        workspace_identity=scope()["workspace_identity"], approval_request_id="approval-1",
        approval_packet_digest=digest, created_at=100,
        expires_at=130, nonce=pending.nonce, prompt_message_id=None, delivered=False, state="pending")

def test_old_incomplete_api_returns_without_hanging(tmp_path):
    service = GateApprovalService(tmp_path, bot=None, render_plan=render_plan)
    with pytest.raises(TypeError):
        service.create_pending(profile="main", session_key="s", requester_id=42, task_id="t",
            revision=1, plan_payload=PLAN, plan_digest=str(canonical_plan_digest(PLAN)),
            workspace_identity={}, tool_call_id="c", turn_id="u", plan_text="x", chat_id=42,
            timeout_seconds=1)

@pytest.mark.parametrize("bad", [
    {"telegram_chat_id": 43}, {"profile_id": "other"}, {"session_id": "stale"},
    {"task_id": "stale-task"}, {"plan_revision": 3}, {"approval_request_id": "stale-request"},
])
def test_stale_binding_fails_closed(tmp_path, bad):
    service = GateApprovalService(tmp_path, bot=None, render_plan=render_plan, clock=lambda: 100)
    data = scope()
    state = approval_state()
    body, digest = packet_data(state)
    text = packet_text(body, digest)
    p = service.create_pending(**data, approval_state=state, approval_packet_body=body, approval_packet_digest=digest,
        plan_text=text, timeout_seconds=30)
    assert p is not None
    assert service.consume_callback(p.nonce, actor_id=42, chat_id=42, chat_type="private",
        choice="approve_once", expected_context={**{k:v for k,v in data.items() if k != "plan_payload"}, **bad}) is False

def test_request_persists_prompt_only_after_plan_and_controls_confirmed(tmp_path):
    class ConfirmingBot(Bot):
        def __init__(self):
            super().__init__()
            self.prompt_sent = asyncio.Event()
        async def send_message(self, **kwargs):
            result = await super().send_message(**kwargs)
            if "reply_markup" in kwargs:
                self.prompt_sent.set()
            return result

    async def scenario():
        bot = ConfirmingBot()
        service = GateApprovalService(tmp_path, bot=bot, render_plan=render_plan)
        state = approval_state()
        packet_body, packet_digest = packet_data(state)
        task = asyncio.create_task(service.request(**scope(), timeout_seconds=10,
            approval_state=state, approval_packet_body=packet_body, approval_packet_digest=packet_digest))
        await asyncio.wait_for(bot.prompt_sent.wait(), timeout=2)
        nonce = next(iter(service.futures))
        record = service.sidecar.get(nonce, profile_id="main")
        assert record["delivered"] is True
        assert record["prompt_message_id"] == len(bot.calls)
        assert all(call["chat_id"] == 42 for call in bot.calls)
        assert "reply_markup" in bot.calls[-1]
        assert bot.calls[-1]["text"] == "Approve this exact Engineering Gate approval packet?"
        assert "".join(call["text"] for call in bot.calls[:-1]) == (
            packet_body + "\n\nApproval packet digest: " + packet_digest)
        assert record["approval_packet_digest"] == packet_digest
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())

def test_delivery_failure_invalidates_without_controls(tmp_path):
    bot = Bot(fail_at=2)
    service = GateApprovalService(tmp_path, bot=bot, render_plan=render_plan)
    state = approval_state("x" * 8500)
    packet, packet_digest = packet_data(state)
    result = asyncio.run(service.request(**scope(), timeout_seconds=0.2,
        approval_state=state, approval_packet_body=packet, approval_packet_digest=packet_digest))
    assert result is False
    assert not any("reply_markup" in call for call in bot.calls)
    assert service.sidecar.get(next(iter(service.sidecar._db("main").execute("SELECT nonce FROM approvals")))[0], profile_id="main")["state"] == "cancelled"

def test_callback_requires_exact_delivered_prompt_id_and_chat(tmp_path):
    import os
    os.environ["HERMES_HOME"] = str(tmp_path / "hermes-home")
    from gateway.config import GatewayConfig, PlatformConfig, Platform
    from gateway.session import SessionSource, SessionStore
    from plugins.platforms.telegram.adapter import TelegramAdapter

    route_store = SessionStore(tmp_path / "sessions", GatewayConfig())
    adapter = TelegramAdapter(PlatformConfig())
    adapter._session_store = route_store
    route_source = SessionSource(platform=Platform.TELEGRAM, chat_id="42", user_id="42", chat_type="dm")
    route_key = adapter._source_session_key(route_source)
    route_session_id = route_store.get_or_create_session(route_source).session_id
    data = scope(session_id=route_session_id)
    state = approval_state()
    packet_body, packet_digest = packet_data(state)
    service = GateApprovalService(tmp_path, bot=None, render_plan=render_plan)
    p = service.create_pending(**data, approval_state=state, approval_packet_body=packet_body, approval_packet_digest=packet_digest,
        plan_text=packet_text(packet_body, packet_digest), timeout_seconds=30)
    service.sidecar.mark_prompt_delivered(p.nonce, profile_id="main", prompt_message_id=99,
        plan_chunks_confirmed=True, buttons_sent=True)
    loop = asyncio.get_event_loop_policy().new_event_loop()
    future = loop.create_future()
    record = service.sidecar.get(p.nonce, profile_id="main")
    service.futures[p.nonce] = (future, {key: record[key] for key in ApprovalSidecar._REQUIRED})
    handler = []
    service.profile_id = "main"
    service.state_store_provider = lambda _profile: None
    service.register_telegram_handler(SimpleNamespace(register_telegram_handler=lambda factory: factory(
        SimpleNamespace(add_handler=lambda h, group: handler.append(h), bot=object()), adapter)))
    callback = handler[0].callback
    async def invoke(message_id, chat_id):
        q = SimpleNamespace(data=f"eg1:{p.nonce}:approve_once", message=SimpleNamespace(
            chat=SimpleNamespace(id=chat_id, type="private"), message_id=message_id),
            from_user=SimpleNamespace(id=42), answer=lambda: asyncio.sleep(0))
        await callback(SimpleNamespace(callback_query=q), None)
    try:
        loop.run_until_complete(invoke(98, 42))
        assert not future.done()
        assert service.sidecar.get(p.nonce, profile_id="main")["state"] == "pending"

        loop.run_until_complete(invoke(99, 43))
        assert not future.done()
        assert service.sidecar.get(p.nonce, profile_id="main")["state"] == "pending"

        route_store.reset_session(route_key)
        # A matching Telegram callback must be rejected after its live route resets.
        loop.run_until_complete(invoke(99, 42))
        assert not future.done()
        assert service.sidecar.get(p.nonce, profile_id="main")["state"] == "pending"

        # A matching Telegram callback is still not authoritative without the
        # profile-scoped StateStore provider and current task validation.
        loop.run_until_complete(invoke(99, 42))
        assert not future.done()
        assert service.sidecar.get(p.nonce, profile_id="main")["state"] == "pending"
    finally:
        if not future.done():
            future.cancel()
        loop.close()
