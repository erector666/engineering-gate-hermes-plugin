"""Hermes v0.21.4 Stage 1 approval-only adapter."""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import stat
from pathlib import Path

from ._core_import import import_core
from .approval import GateApprovalService
from .context import TrustedTelegramContext
from .hooks import register_hooks
from .execution import GateExecutionAdapter


def _profile_identity():
    """Resolve the active profile against the current Hermes home on every call."""
    from hermes_constants import get_hermes_home
    from hermes_cli.profiles import get_active_profile
    home = Path(get_hermes_home()).expanduser().resolve()
    profile = get_active_profile(home)
    if profile == "default":
        return home, profile, home
    return home, profile, (home / "profiles" / profile).resolve()


def _render_plan(plan):
    from dataclasses import asdict
    return json.dumps(asdict(plan), sort_keys=True, separators=(",", ":"))


def register(ctx) -> None:
    """Register the approval tool and a per-context, fail-closed write readiness hook."""
    set_write_ready, make_readiness_binding = register_hooks(ctx)
    try:
        StateStore = import_core("state_store").StateStore

        # Capture this manager's concrete, canonical profile/config binding. The value is
        # deliberately independent of sessions, tasks, approvals, and reviewer data.
        profile_home = Path(ctx._manager.home_path).expanduser().resolve(strict=True)
        profile_id = profile_home.name if profile_home.parent.name == "profiles" else "default"
        state_path = (profile_home / "engineering-gate-state.sqlite3").resolve()
        sidecar_path = (profile_home / "engineering-gate-approvals.sqlite3").resolve()
        if (not profile_id or profile_home.is_symlink()
                or state_path.parent != profile_home or sidecar_path.parent != profile_home
                or state_path.name != "engineering-gate-state.sqlite3"
                or sidecar_path.name != "engineering-gate-approvals.sqlite3"):
            return
        mode = profile_home.stat().st_mode
        if not stat.S_ISDIR(mode) or not os.access(profile_home, os.R_OK | os.W_OK | os.X_OK):
            return
        def validate_existing_db(path, tables, version=None):
            if not path.exists():
                return not path.is_symlink()
            if path.is_symlink() or not path.is_file():
                return False
            uri = path.as_uri() + "?mode=ro"
            try:
                with sqlite3.connect(uri, uri=True) as db:
                    names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
                    if names != tables:
                        return False
                    if version is not None:
                        rows = db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchall()
                        if rows != [(version,)]:
                            return False
                    check = db.execute("PRAGMA quick_check").fetchone()
                    if check != ("ok",):
                        return False
                return True
            except (sqlite3.Error, OSError, ValueError):
                return False
        if not validate_existing_db(state_path, {"metadata", "task_state", "execution_audit", "reviewer_keys", "signed_verdicts", "mutation_leases", "authorization_audit"}, "5"):
            return
        if not validate_existing_db(sidecar_path, {"approvals"}):
            return
        readiness_binding = make_readiness_binding(profile_id, str(profile_home), str(state_path), str(sidecar_path))

        def store_for_active_profile(profile_id):
            home, active, active_home = _profile_identity()
            if profile_id != active:
                raise PermissionError("profile changed during approval")
            return StateStore(active_home / "engineering-gate-state.sqlite3")

        service = GateApprovalService(
            profile_home, bot=None, render_plan=_render_plan,
            state_store_provider=store_for_active_profile,
        )
        service.profile_id = profile_id
        service.register_telegram_handler(ctx)
        from .approval_sidecar import ApprovalSidecar
        execution_adapter = GateExecutionAdapter(profile_home=profile_home, profile_id=profile_id,
            state_store_provider=store_for_active_profile, approval_sidecar=ApprovalSidecar(profile_home))

        async def gate_approve_plan(args, **kwargs):
            if type(args) is not dict or set(args) != {"task_id"}:
                return json.dumps({"approved": False, "error": "invalid arguments"})
            trusted = TrustedTelegramContext.resolve(kwargs, plugin_profile=_profile_identity()[1])
            if (trusted is None or not isinstance(trusted.task_id, str) or not trusted.task_id
                    or trusted.task_id.strip() != trusted.task_id or args["task_id"] != trusted.task_id):
                return json.dumps({"approved": False, "error": "untrusted or stale task context"})
            home, active_profile, active_home = _profile_identity()
            if trusted.profile != active_profile:
                return json.dumps({"approved": False, "error": "profile mismatch"})
            from .approval_sidecar import ApprovalSidecar
            service.profile_id = active_profile
            service.sidecar = ApprovalSidecar(active_home)
            store = StateStore(active_home / "engineering-gate-state.sqlite3")
            try:
                current = store.load(trusted.task_id)
                request = current.approval_request
                plan = current.plan
                if (request is None or plan is None or current.state.value != "awaiting_approval"
                        or current.task.requester.subject != f"telegram:{trusted.requester_id}"):
                    return json.dumps({"approved": False, "error": "task is not approvable"})
                workspace = plan.workspace_identity
                if workspace is None:
                    return json.dumps({"approved": False, "error": "workspace identity missing"})
                approved = await service.request(
                    profile_id=active_profile, session_id=trusted.session_id,
                    telegram_user_id=trusted.requester_id, telegram_chat_id=int(trusted.chat_id),
                    task_id=str(current.task_id), plan_revision=int(current.revision),
                    plan_payload=plan, plan_digest=str(current.plan_digest),
                    workspace_identity={"canonical_path": workspace.canonical_path,
                                        "device": workspace.device, "inode": workspace.inode},
                    approval_request_id=request.request_id, timeout_seconds=300,
                )
                return json.dumps({"approved": bool(approved)})
            except Exception:
                return json.dumps({"approved": False, "error": "approval unavailable"})

        ctx.register_tool(
            name="gate_approve_plan", toolset="engineering_gate",
            schema={"type": "object", "properties": {"task_id": {"type": "string"}},
                    "required": ["task_id"], "additionalProperties": False},
            handler=gate_approve_plan, is_async=True,
        )
        register_interceptor = getattr(ctx, "register_tool_execution_interceptor", None)
        if not callable(register_interceptor):
            return
        register_interceptor(execution_adapter.intercept_write, tool_names={"write_file"})
        # The closure is exclusively owned by this context; binding remains captured for
        # the lifetime of its registration and never becomes authorization.
        if readiness_binding and profile_home == Path(ctx._manager.home_path).resolve(strict=True):
            set_write_ready(True, readiness_binding)
    except Exception:
        # Missing APIs, invalid paths, or failed registrations leave this instance denied.
        set_write_ready(False)
        return


__all__ = ["register"]
