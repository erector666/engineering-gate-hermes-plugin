import asyncio
import json
from dataclasses import replace
import sys
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engineering-gate"))
from adapters.hermes.approval import GateApprovalService, canonical_approval_packet
from engineering_gate_core.models import (
    AcceptanceCriterion, ApprovalRequest, Evidence, InspectionEvidenceRef, NormalizedOperation,
    OperationKind, Plan, PlanReview, RequesterIdentity, ReviewVerdict, TaskState,
)
from engineering_gate_core.state_store import StateStore
from engineering_gate_core.workflow import Event, canonical_plan_digest, capture_workspace_identity, new_task


def render(plan):
    return json.dumps(asdict(plan), sort_keys=True, separators=(",", ":"))


def awaiting(store, root):
    store.create(new_task("task-1", "inspect", RequesterIdentity("telegram:42")))
    store.transition("task-1", Event.INSPECTION_RECORDED, InspectionEvidenceRef("i", "inspection"))
    store.transition("task-1", Event.ANALYSIS_RECORDED, Evidence("a", "analysis"))
    plan = Plan("inspect", (NormalizedOperation(OperationKind.READ, "src", "read"),),
                (AcceptanceCriterion("c", "checked", "test"),), ("pytest",),
                workspace_root=str(root.resolve()), workspace_identity=capture_workspace_identity(root))
    store.transition("task-1", Event.PLAN_RECORDED, plan)
    store.transition("task-1", Event.BLAST_RADIUS_RECORDED, Evidence("b", "blast"))
    store.transition("task-1", Event.PLAN_REVIEW_PASSED, PlanReview(ReviewVerdict.APPROVED))
    current = store.load("task-1")
    store.transition("task-1", Event.APPROVAL_REQUESTED,
                     ApprovalRequest(current.task_id, current.revision, current.plan_digest, "request-1"))
    return store.load("task-1")


class Bot:
    async def send_message(self, *, chat_id, **kwargs):
        return SimpleNamespace(message_id=9, chat=SimpleNamespace(id=chat_id))


def matching_adapter(session_id):
    return SimpleNamespace(_source_from_message_for_auth=lambda message: message,
        _source_session_key=lambda source: "telegram:test-route",
        _session_store=SimpleNamespace(peek_session_id=lambda key: session_id))


def disposable_route(tmp_path, monkeypatch, *, user_id=42, chat_id=None):
    if chat_id is None:
        chat_id = user_id
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    from gateway.config import GatewayConfig, Platform, PlatformConfig
    from gateway.session import SessionSource, SessionStore
    from plugins.platforms.telegram.adapter import TelegramAdapter
    routes = SessionStore(tmp_path / "sessions", GatewayConfig(multiplex_profiles=True))
    adapter = TelegramAdapter(PlatformConfig())
    adapter._owner_profile = "main"
    adapter._session_store = routes
    source = SessionSource(platform=Platform.TELEGRAM, chat_id=str(chat_id), user_id=str(user_id), chat_type="dm")
    source.profile = "main"
    entry = routes.get_or_create_session(source)
    assert entry.session_key == adapter._source_session_key(source)
    return adapter, routes, entry


def make_scope(current, profile, root, session_id="s"):
    packet_body, packet_digest = canonical_approval_packet(current, "main")
    return dict(profile_id="main", session_id=session_id, telegram_user_id=42, telegram_chat_id=42,
                task_id="task-1", plan_revision=current.revision, plan_payload=current.plan,
                plan_digest=str(canonical_plan_digest(current.plan)),
                workspace_identity={"canonical_path": str(root.resolve()), "device": root.stat().st_dev,
                                    "inode": root.stat().st_ino},
                approval_request_id="request-1", approval_packet_digest=packet_digest,
                packet_body=packet_body, approval_state=current)


def packet_text(scope):
    return scope["packet_body"] + "\n\nApproval packet digest: " + scope["approval_packet_digest"]


@pytest.mark.parametrize("choice, expected", [("approve_once", TaskState.APPROVED), ("deny", TaskState.REJECTED)])
def test_restart_callback_persists_exact_core_receipt(tmp_path, monkeypatch, choice, expected):
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o700)
    root = tmp_path / "workspace"
    root.mkdir()
    store = StateStore(tmp_path / "state.sqlite3")
    current = awaiting(store, root)
    adapter, routes, route = disposable_route(tmp_path, monkeypatch)
    scope = make_scope(current, profile, root, session_id=route.session_id)
    service = GateApprovalService(profile, bot=Bot(), render_plan=render)
    text = packet_text(scope)
    pending = service.create_pending(**{k:v for k,v in scope.items() if k not in ("packet_body", "approval_state")},
        approval_state=current, approval_packet_body=scope["packet_body"], plan_text=text, timeout_seconds=30)
    assert service.sidecar.mark_prompt_delivered(pending.nonce, profile_id="main",
        prompt_message_id=9, plan_chunks_confirmed=True, buttons_sent=True)
    handler = []
    restarted = GateApprovalService(profile, bot=None, render_plan=render,
        profile_id="main", state_store_provider=lambda profile_id: StateStore(tmp_path / "state.sqlite3"))
    restarted.register_telegram_handler(SimpleNamespace(register_telegram_handler=lambda factory: factory(
        SimpleNamespace(add_handler=lambda h, group: handler.append(h), bot=None), adapter)))
    callback = handler[0].callback
    query = SimpleNamespace(data=f"eg1:{pending.nonce}:{choice}", from_user=SimpleNamespace(id=42),
        message=SimpleNamespace(message_id=9, chat=SimpleNamespace(id=42, type="private")),
        answer=lambda: asyncio.sleep(0))
    asyncio.run(callback(SimpleNamespace(callback_query=query), None))
    updated = StateStore(tmp_path / "state.sqlite3").load("task-1")
    assert updated.state is expected
    assert updated.approval is not None
    assert updated.approval.request_id == "request-1"
    assert updated.approval.task_id == current.task_id
    assert updated.approval.revision == current.revision
    assert updated.approval.digest == current.plan_digest
    assert updated.approval.requester == current.task.requester
    assert updated.approval.approved is (choice == "approve_once")
    assert restarted.sidecar.get(pending.nonce, profile_id="main")["state"] == "approved" if choice == "approve_once" else restarted.sidecar.get(pending.nonce, profile_id="main")["state"] == "denied"


def invoke_callback(tmp_path, profile, store_provider, pending, adapter, actor_id=42, chat_id=42):
    handler = []
    service = GateApprovalService(profile, bot=None, render_plan=render,
        profile_id="main", state_store_provider=store_provider)
    service.register_telegram_handler(SimpleNamespace(register_telegram_handler=lambda factory: factory(
        SimpleNamespace(add_handler=lambda h, group: handler.append(h), bot=None), adapter)))
    query = SimpleNamespace(data=f"eg1:{pending.nonce}:approve_once",
        from_user=SimpleNamespace(id=actor_id),
        message=SimpleNamespace(message_id=9, chat=SimpleNamespace(id=chat_id, type="private")),
        answer=lambda: asyncio.sleep(0))
    asyncio.run(handler[0].callback(SimpleNamespace(callback_query=query), None))
    return service


@pytest.mark.parametrize("field", ["plan_revision", "plan_digest", "approval_request_id"])
def test_stale_sidecar_binding_cannot_write_approval_receipt(tmp_path, monkeypatch, field):
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o700)
    root = tmp_path / "workspace"
    root.mkdir()
    db = tmp_path / "state.sqlite3"
    store = StateStore(db)
    current = awaiting(store, root)
    adapter, _, route = disposable_route(tmp_path, monkeypatch)
    scope = make_scope(current, profile, root, session_id=route.session_id)
    service = GateApprovalService(profile, bot=Bot(), render_plan=render)
    pending = service.create_pending(**{k:v for k,v in scope.items() if k not in ("packet_body", "approval_state")},
        approval_state=current, approval_packet_body=scope["packet_body"],
        plan_text=packet_text(scope), timeout_seconds=30)
    assert pending is not None
    assert service.sidecar.mark_prompt_delivered(pending.nonce, profile_id="main",
        prompt_message_id=9, plan_chunks_confirmed=True, buttons_sent=True)

    if field == "plan_revision":
        changed = replace(current, revision=current.revision + 1)
    elif field == "plan_digest":
        changed_plan = Plan("different inspect", current.plan.operations,
            current.plan.acceptance_criteria, current.plan.verification_commands,
            workspace_root=current.plan.workspace_root,
            workspace_identity=current.plan.workspace_identity)
        changed = replace(current, plan=changed_plan,
                          plan_digest=str(canonical_plan_digest(changed_plan)))
    else:
        changed_request = replace(current.approval_request, request_id="changed-request")
        changed = replace(current, approval_request=changed_request)
    restarted = invoke_callback(tmp_path, profile,
        lambda profile_id: SimpleNamespace(load=lambda task_id: changed), pending, adapter)

    updated = StateStore(db).load("task-1")
    assert updated.state is TaskState.AWAITING_APPROVAL
    assert updated.approval is None
    assert restarted.sidecar.get(pending.nonce, profile_id="main")["state"] == "pending"


def test_callback_rejects_cross_profile_even_when_session_id_matches(tmp_path, monkeypatch):
    """A matching session ID cannot make a callback from another profile valid."""
    from gateway.config import GatewayConfig, PlatformConfig
    from gateway.session import SessionStore
    from plugins.platforms.telegram.adapter import TelegramAdapter

    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    monkeypatch.setenv("HERMES_PROFILE", "other")
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o700)
    root = tmp_path / "workspace"
    root.mkdir()
    store = StateStore(tmp_path / "state.sqlite3")
    current = awaiting(store, root)
    adapter = TelegramAdapter(PlatformConfig())
    routes = SessionStore(tmp_path / "sessions", GatewayConfig(multiplex_profiles=True))
    adapter._session_store = routes
    route_message = SimpleNamespace(from_user=SimpleNamespace(id=42),
        chat=SimpleNamespace(id=42, type="private"), message_thread_id=None,
        is_topic_message=False)
    source = adapter._source_from_message_for_auth(route_message)
    adapter._owner_profile = "other"
    assert adapter._session_key_profile(source) == "other"
    adapter._session_store = SimpleNamespace(
        peek_session_id=lambda key: "same-session",
        _resolve_profile_for_key=routes._resolve_profile_for_key)

    scope = make_scope(current, profile, root, session_id="same-session")
    service = GateApprovalService(profile, bot=Bot(), render_plan=render)
    pending = service.create_pending(**{k:v for k,v in scope.items() if k not in ("packet_body", "approval_state")},
        approval_state=current, approval_packet_body=scope["packet_body"],
        plan_text=packet_text(scope),
        timeout_seconds=30)
    assert pending is not None
    assert service.sidecar.mark_prompt_delivered(pending.nonce, profile_id="main",
        prompt_message_id=9, plan_chunks_confirmed=True, buttons_sent=True)

    restarted = invoke_callback(tmp_path, profile,
        lambda profile_id: StateStore(tmp_path / "state.sqlite3"), pending, adapter)
    updated = StateStore(tmp_path / "state.sqlite3").load("task-1")
    assert updated.state is TaskState.AWAITING_APPROVAL
    assert updated.approval is None
    assert restarted.sidecar.get(pending.nonce, profile_id="main")["state"] == "pending"


def test_callback_rejects_when_current_telegram_route_session_changed(tmp_path, monkeypatch):
    """A valid actor/chat/prompt cannot approve a task after its DM route resets."""
    from gateway.config import GatewayConfig, Platform, PlatformConfig
    from gateway.session import SessionSource, SessionStore
    from plugins.platforms.telegram.adapter import TelegramAdapter

    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    monkeypatch.setenv("HERMES_PROFILE", "main")
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o700)
    root = tmp_path / "workspace"
    root.mkdir()
    store = StateStore(tmp_path / "state.sqlite3")
    current = awaiting(store, root)

    routes = SessionStore(tmp_path / "sessions", GatewayConfig(multiplex_profiles=True))
    adapter = TelegramAdapter(PlatformConfig())
    adapter._owner_profile = "main"
    adapter._session_store = routes
    route_message = SimpleNamespace(from_user=SimpleNamespace(id=42),
        chat=SimpleNamespace(id=42, type="private"), message_thread_id=None,
        is_topic_message=False)
    source = adapter._source_from_message_for_auth(route_message)
    source.profile = "main"
    key = adapter._source_session_key(source)
    route_entry = routes.get_or_create_session(source)
    assert route_entry.session_key == key
    bound_session_id = route_entry.session_id
    scope = make_scope(current, profile, root, session_id=bound_session_id)
    service = GateApprovalService(profile, bot=Bot(), render_plan=render)
    text = packet_text(scope)
    pending = service.create_pending(**{k:v for k,v in scope.items() if k not in ("packet_body", "approval_state")},
        approval_state=current, approval_packet_body=scope["packet_body"],
        plan_text=text,
        timeout_seconds=30)
    assert service.sidecar.mark_prompt_delivered(pending.nonce, profile_id="main",
        prompt_message_id=9, plan_chunks_confirmed=True, buttons_sent=True)

    assert bound_session_id is not None
    routes.reset_session(key)
    assert routes.peek_session_id(key) != bound_session_id

    restarted = GateApprovalService(profile, bot=None, render_plan=render,
        profile_id="main", state_store_provider=lambda profile_id: StateStore(tmp_path / "state.sqlite3"))
    handler = []
    restarted.register_telegram_handler(SimpleNamespace(register_telegram_handler=lambda factory: factory(
        SimpleNamespace(add_handler=lambda h, group: handler.append(h), bot=None), adapter)))
    query = SimpleNamespace(data=f"eg1:{pending.nonce}:approve_once",
        from_user=SimpleNamespace(id=42),
        message=SimpleNamespace(message_id=9, from_user=SimpleNamespace(id=42),
                                chat=SimpleNamespace(id=42, type="private")),
        answer=lambda: asyncio.sleep(0))
    asyncio.run(handler[0].callback(SimpleNamespace(callback_query=query), None))
    updated = StateStore(tmp_path / "state.sqlite3").load("task-1")
    assert updated.state is TaskState.AWAITING_APPROVAL
    assert updated.approval is None
    assert restarted.sidecar.get(pending.nonce, profile_id="main")["state"] == "pending"


def test_callback_requester_must_match_persisted_task_requester(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o700)
    root = tmp_path / "workspace"
    root.mkdir()
    store = StateStore(tmp_path / "state.sqlite3")
    current = awaiting(store, root)
    adapter, routes, route = disposable_route(tmp_path, monkeypatch, user_id=42, chat_id=42)
    scope = make_scope(current, profile, root, session_id=route.session_id)
    service = GateApprovalService(profile, bot=Bot(), render_plan=render)
    pending = service.create_pending(**{k:v for k,v in scope.items() if k not in ("packet_body", "approval_state")},
        approval_state=current, approval_packet_body=scope["packet_body"],
        plan_text=packet_text(scope),
        timeout_seconds=30)
    assert pending is not None
    assert service.sidecar.mark_prompt_delivered(pending.nonce, profile_id="main",
        prompt_message_id=9, plan_chunks_confirmed=True, buttons_sent=True)
    restarted = invoke_callback(tmp_path, profile,
        lambda profile_id: StateStore(tmp_path / "state.sqlite3"), pending, adapter, actor_id=43, chat_id=43)
    updated = StateStore(tmp_path / "state.sqlite3").load("task-1")
    assert updated.state is TaskState.AWAITING_APPROVAL
    assert updated.approval is None
    assert restarted.sidecar.get(pending.nonce, profile_id="main")["state"] == "pending"


def test_callback_denies_when_approval_evidence_changes_after_delivery(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o700)
    root = tmp_path / "workspace"
    root.mkdir()
    db = tmp_path / "state.sqlite3"
    store = StateStore(db)
    current = awaiting(store, root)
    adapter, _, route = disposable_route(tmp_path, monkeypatch)
    scope = make_scope(current, profile, root, session_id=route.session_id)
    service = GateApprovalService(profile, bot=Bot(), render_plan=render)
    pending = service.create_pending(**{k: v for k, v in scope.items() if k not in ("packet_body", "approval_state")},
        approval_state=current, approval_packet_body=scope["packet_body"],
        plan_text=packet_text(scope), timeout_seconds=30)
    assert pending is not None
    assert service.sidecar.mark_prompt_delivered(pending.nonce, profile_id="main",
        prompt_message_id=9, plan_chunks_confirmed=True, buttons_sent=True)

    changed = replace(current, analysis=Evidence("analysis", "changed after delivery"))
    restarted = invoke_callback(tmp_path, profile,
        lambda profile_id: SimpleNamespace(load=lambda task_id: changed), pending, adapter)

    updated = StateStore(db).load("task-1")
    assert updated.state is TaskState.AWAITING_APPROVAL
    assert updated.approval is None
    assert restarted.sidecar.get(pending.nonce, profile_id="main")["state"] == "pending"


def test_record_approval_failure_leaves_no_receipt_and_consumes_sidecar(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o700)
    root = tmp_path / "workspace"
    root.mkdir()
    db = tmp_path / "state.sqlite3"
    store = StateStore(db)
    current = awaiting(store, root)
    adapter, routes, route = disposable_route(tmp_path, monkeypatch)
    scope = make_scope(current, profile, root, session_id=route.session_id)
    service = GateApprovalService(profile, bot=Bot(), render_plan=render)
    pending = service.create_pending(**{k:v for k,v in scope.items() if k not in ("packet_body", "approval_state")},
        approval_state=current, approval_packet_body=scope["packet_body"],
        plan_text=packet_text(scope),
        timeout_seconds=30)
    assert pending is not None
    assert service.sidecar.mark_prompt_delivered(pending.nonce, profile_id="main",
        prompt_message_id=9, plan_chunks_confirmed=True, buttons_sent=True)

    class FailingStore:
        def load(self, task_id):
            return StateStore(db).load(task_id)

        def record_approval(self, task_id, receipt):
            raise OSError("simulated receipt persistence failure")

    restarted = invoke_callback(tmp_path, profile, lambda profile_id: FailingStore(), pending, adapter)
    updated = StateStore(db).load("task-1")
    assert updated.state is TaskState.AWAITING_APPROVAL
    assert updated.approval is None
    assert restarted.sidecar.get(pending.nonce, profile_id="main")["state"] == "approved"
