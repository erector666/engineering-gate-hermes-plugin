import os
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERMES = Path("/home/uss/.hermes/hermes-agent")
sys.path.insert(0, str(ROOT / "engineering-gate"))
sys.path.insert(0, str(HERMES))
os.environ["HERMES_HOME"] = "/home/uss/.hermes/test-profile"

from gateway.session_context import clear_session_vars, set_session_vars
from adapters.hermes.context import TrustedTelegramContext


def bind(**changes):
    values = dict(platform="telegram", chat_type="dm", chat_id="987654", user_id="123",
                  session_key="telegram:987654", session_id="sid-1", profile="profile-a")
    values.update(changes)
    return set_session_vars(**values)


def trusted_kwargs(**changes):
    values = dict(session_id="sid-1", turn_id="turn-1", tool_call_id="call-1")
    values.update(changes)
    return values


def bind_coordinates(**changes):
    from tools.approval_context import set_current_observability_context
    values = dict(turn_id="turn-1", tool_call_id="call-1", session_id="sid-1")
    values.update(changes)
    return set_current_observability_context(**values)


def reset_coordinates(tokens):
    from tools.approval_context import reset_current_observability_context
    reset_current_observability_context(tokens)


def test_resolves_actual_host_bound_telegram_dm_and_exact_coordinates():
    tokens = bind()
    call_tokens = bind_coordinates()
    try:
        context = TrustedTelegramContext.resolve(trusted_kwargs(), plugin_profile="profile-a")
        assert context.requester_id == 123
        assert context.chat_id == "987654"  # distinct from sender id by design
        assert (context.session_key, context.profile, context.turn_id, context.tool_call_id) == (
            "telegram:987654", "profile-a", "turn-1", "call-1")
        try:
            context.chat_id = "model-controlled"
            assert False, "context must be immutable"
        except FrozenInstanceError:
            pass
    finally:
        reset_coordinates(call_tokens)
        clear_session_vars(tokens)


def test_rejects_non_dm_surfaces_and_invalid_or_unbound_source():
    for changes in ({"chat_type": "group"}, {"chat_type": "channel"}, {"platform": "cli"},
                    {"user_id": "01"}, {"user_id": "+1"}, {"user_id": "١"}, {"user_id": "0"},
                    {"chat_id": ""}, {"session_key": ""}):
        tokens = bind(**changes)
        try:
            assert TrustedTelegramContext.resolve(trusted_kwargs(), plugin_profile="profile-a") is None
        finally:
            clear_session_vars(tokens)


def test_requires_exact_handler_coordinates_and_profile_agreement():
    tokens = bind()
    call_tokens = bind_coordinates()
    try:
        for kwargs in ({}, {"session_id": "wrong", "turn_id": "t", "tool_call_id": "c"}):
            assert TrustedTelegramContext.resolve(kwargs, plugin_profile="profile-a") is None
        context = TrustedTelegramContext.resolve({"session_id": "sid-1"}, plugin_profile="profile-a")
        assert (context.turn_id, context.tool_call_id) == ("turn-1", "call-1")
        wrong_call_tokens = bind_coordinates(session_id="other-session")
        try:
            assert TrustedTelegramContext.resolve(trusted_kwargs(), plugin_profile="profile-a") is None
        finally:
            reset_coordinates(wrong_call_tokens)
        assert TrustedTelegramContext.resolve(trusted_kwargs(), plugin_profile="other") is None
        assert TrustedTelegramContext.resolve(trusted_kwargs(), plugin_profile="") is None
    finally:
        reset_coordinates(call_tokens)
        clear_session_vars(tokens)


def test_contextvar_context_reaches_registered_handler_execution_thread():
    import asyncio
    tokens = bind()
    call_tokens = bind_coordinates()
    try:
        async def invoke_like_gateway_tool_handler():
            return await asyncio.to_thread(
                TrustedTelegramContext.resolve, trusted_kwargs(), plugin_profile="profile-a")
        result = asyncio.run(invoke_like_gateway_tool_handler())
        assert result is not None and result.requester_id == 123 and result.chat_id == "987654"
    finally:
        reset_coordinates(call_tokens)
        clear_session_vars(tokens)


def test_blank_host_profile_uses_only_explicit_plugin_context_profile():
    tokens = bind(profile="")
    call_tokens = bind_coordinates()
    try:
        assert TrustedTelegramContext.resolve(trusted_kwargs(), plugin_profile="profile-a").profile == "profile-a"
        assert TrustedTelegramContext.resolve(trusted_kwargs(), plugin_profile="") is None
    finally:
        reset_coordinates(call_tokens)
        clear_session_vars(tokens)


def test_model_arguments_are_irrelevant_and_cleared_context_masks_environment():
    os.environ.update(HERMES_SESSION_PLATFORM="telegram", HERMES_SESSION_CHAT_TYPE="dm",
                      HERMES_SESSION_CHAT_ID="987654", HERMES_SESSION_USER_ID="123",
                      HERMES_SESSION_KEY="telegram:987654", HERMES_SESSION_ID="sid-1",
                      HERMES_SESSION_PROFILE="profile-a")
    tokens = bind()
    call_tokens = bind_coordinates()
    clear_session_vars(tokens)
    reset_coordinates(call_tokens)
    assert TrustedTelegramContext.resolve(trusted_kwargs(), plugin_profile="profile-a") is None
    tokens = bind()
    call_tokens = bind_coordinates()
    try:
        kwargs = trusted_kwargs(user_id="999", chat_id="model-chat", args={"user_id": "999"})
        context = TrustedTelegramContext.resolve(kwargs, plugin_profile="profile-a")
        assert context.requester_id == 123
        assert context.chat_id == "987654"
    finally:
        reset_coordinates(call_tokens)
        clear_session_vars(tokens)


def test_pinned_tool_execution_exposes_per_call_ids_inside_sync_and_async_handlers():
    import asyncio
    import model_tools
    from tools.registry import registry

    name = "_engineering_gate_contextvar_probe"
    schema = {"description": "test probe", "parameters": {"type": "object", "properties": {}}}
    seen = []

    def sync_handler(args, **kwargs):
        from tools.approval_context import _approval_turn_id, _approval_tool_call_id
        context = TrustedTelegramContext.resolve(kwargs, plugin_profile="profile-a")
        seen.append(("sync", _approval_turn_id.get(), _approval_tool_call_id.get(), kwargs, context))
        return "ok"

    async def async_handler(args, **kwargs):
        from tools.approval_context import _approval_turn_id, _approval_tool_call_id
        context = TrustedTelegramContext.resolve(kwargs, plugin_profile="profile-a")
        seen.append(("async", _approval_turn_id.get(), _approval_tool_call_id.get(), kwargs, context))
        return "ok"

    tokens = bind()
    try:
        for suffix, handler, is_async in (("sync", sync_handler, False), ("async", async_handler, True)):
            tool_name = f"{name}_{suffix}"
            registry.register(tool_name, "engineering-gate-test", schema, handler, is_async=is_async)
            ids = model_tools._CallIds(task_id="task-1", session_id="sid-1",
                                       tool_call_id=f"call-{suffix}", turn_id=f"turn-{suffix}")
            try:
                def execute():
                    return model_tools._execute_tool(
                        tool_name, {}, {}, ids, user_task=None, enabled_tools=None,
                        skip_tool_execution_middleware=True)
                if is_async:
                    async def inside_running_loop():
                        return execute()
                    result = asyncio.run(inside_running_loop())
                else:
                    result = execute()
                assert result == "ok"
            finally:
                registry.deregister(tool_name)

        assert [(item[0], item[1], item[2]) for item in seen] == [
            ("sync", "turn-sync", "call-sync"), ("async", "turn-async", "call-async")]
        assert all(item[3].get("session_id") == "sid-1" and item[3].get("task_id") == "task-1"
                   for item in seen)
        assert [(item[4].turn_id, item[4].tool_call_id) for item in seen] == [
            ("turn-sync", "call-sync"), ("turn-async", "call-async")]
        from tools.approval_context import _approval_turn_id, _approval_tool_call_id
        assert _approval_turn_id.get() == "" and _approval_tool_call_id.get() == ""
    finally:
        clear_session_vars(tokens)


def test_parallel_pinned_dispatch_keeps_call_and_gateway_identities_isolated():
    import threading
    from concurrent.futures import ThreadPoolExecutor
    import model_tools
    from tools.registry import registry

    name = "_engineering_gate_parallel_context_probe"
    schema = {"description": "test probe", "parameters": {"type": "object", "properties": {}}}
    barrier = threading.Barrier(2)
    seen = []

    def handler(args, **kwargs):
        barrier.wait(timeout=5)
        context = TrustedTelegramContext.resolve(kwargs, plugin_profile="profile-a")
        seen.append(context)
        return "ok"

    registry.register(name, "engineering-gate-test", schema, handler)

    def invoke(suffix):
        session_id = f"sid-{suffix}"
        session_tokens = bind(session_id=session_id, user_id=str(100 + int(suffix)),
                              chat_id=f"chat-{suffix}", session_key=f"key-{suffix}")
        ids = model_tools._CallIds(task_id=f"task-{suffix}", session_id=session_id,
                                   tool_call_id=f"call-{suffix}", turn_id=f"turn-{suffix}")
        try:
            return model_tools._execute_tool(
                name, {}, {}, ids, user_task=None, enabled_tools=None,
                skip_tool_execution_middleware=True)
        finally:
            clear_session_vars(session_tokens)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert list(pool.map(invoke, ("1", "2"))) == ["ok", "ok"]
        assert {(item.session_id, item.turn_id, item.tool_call_id, item.requester_id,
                 item.chat_id, item.session_key, item.task_id) for item in seen} == {
            ("sid-1", "turn-1", "call-1", 101, "chat-1", "key-1", "task-1"),
            ("sid-2", "turn-2", "call-2", 102, "chat-2", "key-2", "task-2"),
        }
    finally:
        registry.deregister(name)
