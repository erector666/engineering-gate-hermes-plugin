"""Trusted, task-local Telegram DM context for registered tool handlers."""
from dataclasses import dataclass
import re
from typing import Any


_REQUIRED_VARS = (
    "HERMES_SESSION_PLATFORM", "HERMES_SESSION_CHAT_TYPE", "HERMES_SESSION_CHAT_ID",
    "HERMES_SESSION_USER_ID", "HERMES_SESSION_KEY", "HERMES_SESSION_ID",
)


def _clean(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and value.strip() == value


@dataclass(frozen=True, slots=True)
class TrustedTelegramContext:
    """Immutable host-originated requester and routing data for this tool invocation."""

    requester_id: int
    chat_id: str
    session_key: str
    profile: str
    session_id: str
    turn_id: str
    tool_call_id: str
    task_id: str

    @classmethod
    def resolve(cls, handler_kwargs: dict, *, plugin_profile: str):
        """Extract current Hermes ContextVars; never consult model arguments for identity."""
        if not isinstance(handler_kwargs, dict):
            return None
        try:
            from gateway import session_context
        except ImportError:
            return None

        # get_session_env falls back to os.environ when a var was never bound. A
        # messaging authorization must prove every required var is task-bound.
        for name in _REQUIRED_VARS + ("HERMES_SESSION_PROFILE",):
            var = session_context._VAR_MAP.get(name)
            if var is None or var.get() is session_context._UNSET:
                return None
        values = {name: session_context.get_session_env(name, "") for name in _REQUIRED_VARS}
        platform = values["HERMES_SESSION_PLATFORM"]
        chat_type = values["HERMES_SESSION_CHAT_TYPE"]
        chat_id = values["HERMES_SESSION_CHAT_ID"]
        sender = values["HERMES_SESSION_USER_ID"]
        session_key = values["HERMES_SESSION_KEY"]
        session_id = values["HERMES_SESSION_ID"]

        if platform != "telegram" or chat_type != "dm":
            return None
        if not all(_clean(value) for value in (chat_id, session_key, session_id)):
            return None
        if not isinstance(sender, str) or re.fullmatch(r"[1-9][0-9]*", sender, flags=re.ASCII) is None:
            return None
        try:
            from tools import approval_context
            turn_id = approval_context._approval_turn_id.get()
            tool_call_id = approval_context._approval_tool_call_id.get()
            approval_session_id = approval_context._approval_session_id.get()
        except (ImportError, AttributeError):
            return None
        if not all(_clean(value) for value in (turn_id, tool_call_id, approval_session_id)):
            return None
        if handler_kwargs.get("session_id") != session_id or approval_session_id != session_id:
            return None
        if not all(_clean(value) for value in (session_id, turn_id, tool_call_id)):
            return None

        context_profile = session_context.get_session_env("HERMES_SESSION_PROFILE", "")
        if not isinstance(context_profile, str):
            return None
        profile = context_profile if context_profile else plugin_profile
        if not _clean(profile) or (_clean(context_profile) and plugin_profile != context_profile):
            return None

        task_id = handler_kwargs.get("task_id", "")
        if task_id and not _clean(task_id):
            return None
        try:
            requester_id = int(sender)
        except (ValueError, OverflowError):
            return None
        return cls(requester_id, chat_id, session_key, profile, session_id,
                   turn_id, tool_call_id, task_id)
