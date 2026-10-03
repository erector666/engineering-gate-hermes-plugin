"""Pinned real-dispatch identity, approval-correlation, tamper, and replay denials."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

HERMES = Path("/home/uss/.hermes/cache/scratch/hermes-v0214-execution-interception")
PYTHON = Path("/home/uss/.hermes/hermes-agent/venv/bin/python")
HERMES_PIN = "d3b25b52ad1318c526bdb259b600eeca3d5f38e6"
GATE_ROOT = Path(__file__).resolve().parents[2]
GATE_CORE = GATE_ROOT / "engineering-gate" / "engineering_gate_core"
ROOT = GATE_ROOT
GATE_CORE_HEAD = "27e8b4bdf2695c82322066af592f555223e7b059"
PLUGIN = ROOT / "engineering-gate"
TESTS = ROOT / "tests" / "hermes_v0214"


def run_scenario(tmp_path, body):
    head = subprocess.check_output(["git", "-C", str(HERMES), "rev-parse", "HEAD"], text=True).strip()
    assert head == HERMES_PIN
    gate_head = subprocess.check_output(["git", "-C", str(GATE_ROOT), "rev-parse", "HEAD"], text=True).strip()
    assert gate_head == GATE_CORE_HEAD
    frozen_core = subprocess.run(["git", "-C", str(GATE_ROOT), "diff", "--quiet", "HEAD", "--", str(GATE_CORE)], check=False)
    assert frozen_core.returncode == 0, "Gate frozen core has working-tree changes"
    script = r'''
import json, os, model_tools
from pathlib import Path
from stage2_dispatch_harness import create_harness
h = create_harness(final_path=os.environ.get("FINAL_PATH", "B"))
target = h.workspace / os.environ.get("FINAL_PATH", "B")
initial_target = target.read_bytes() if target.exists() else None
def denied(out):
    assert isinstance(out, str) and ("block" in out.lower() or "den" in out.lower() or "authoriz" in out.lower()), out
    assert h.native_calls == [], h.native_calls
    assert (target.read_bytes() if target.exists() else None) == initial_target, target
'''+body+r'''
h.close()
'''
    home = tmp_path / "hermes-home"
    workspace = tmp_path / "workspace"
    env = os.environ.copy()
    env.update(HERMES_HOME=str(home), WORKSPACE=str(workspace), PLUGIN_PATH=str(PLUGIN),
               PYTHONPATH=os.pathsep.join((str(ROOT / "engineering-gate"), str(TESTS), str(HERMES))))
    result = subprocess.run([str(PYTHON), "-c", script], env=env, text=True, capture_output=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("scenario", ["middleware_rewrite", "missing_approval", "stale_revision", "stale_digest", "foreign_profile", "foreign_session", "wrong_user", "corrupt_json", "approval_turn_mismatch", "approval_call_mismatch", "missing_task_id", "blank_task_id"])
def test_real_dispatch_denies_invalid_stage1_identity_or_correlation(tmp_path, scenario):
    cases = {
        "middleware_rewrite": r'''
# Existing execution middleware rewrites A to B; append a final rewrite to unapproved C.
h.manager._middleware["tool_execution"].append(lambda **p: p["next_call"]({**p["args"], "path":"C"}) if p["tool_name"]=="write_file" else p["next_call"]())
h.set_provider(h.provider); out=h.dispatch(); denied(out)
assert h.provider.used is False
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
assert h.fixture.store.load("task-stage2").mutation_proposal is None
assert not (h.workspace/"C").exists()
''',
        "missing_approval": r'''
h.set_provider(h.provider)
with h.sidecar._db("default") as db: db.execute("DELETE FROM approvals WHERE nonce=?", (h._record_id,))
out=h.dispatch(); denied(out)
assert h.provider.used is False and h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
''',
        "stale_revision": r'''
h.set_provider(h.provider)
with h.sidecar._db("default") as db:
 row=db.execute("SELECT data FROM approvals WHERE nonce=?",(h._record_id,)).fetchone(); rec=json.loads(row[0]); rec["plan_revision"] += 1
 db.execute("UPDATE approvals SET data=? WHERE nonce=?",(json.dumps(rec),h._record_id))
out=h.dispatch(); denied(out)
assert h.provider.used is False and h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
''',
        "stale_digest": r'''
h.set_provider(h.provider); h.tamper_display_digest()
out=h.dispatch(); denied(out)
assert h.provider.used is False and h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
''',
        "foreign_profile": r'''
h.set_provider(h.provider)
with h.sidecar._db("default") as db:
 row=db.execute("SELECT data FROM approvals WHERE nonce=?",(h._record_id,)).fetchone(); rec=json.loads(row[0]); rec["profile_id"]="foreign-profile"
 db.execute("UPDATE approvals SET data=? WHERE nonce=?",(json.dumps(rec),h._record_id))
out=h.dispatch(); denied(out)
assert h.provider.used is False and h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
''',
        "foreign_session": r'''
import model_tools
h.set_provider(h.provider)
out=model_tools.handle_function_call('write_file', {'path':'B','content':'approved bytes'}, task_id='task-stage2', session_id='foreign-session', turn_id='turn-stage2', tool_call_id='call-stage2', api_request_id='request-stage2'); denied(out)
assert h.native_calls == []
assert h.provider.used is False and h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
assert not (h.workspace/"B").exists()
''',
        "wrong_user": r'''
from gateway import session_context
h.set_provider(h.provider)
session_context.set_session_vars(platform="telegram",chat_type="dm",chat_id="42",user_id="43",session_key=h.entry.session_key,session_id=h.entry.session_id,profile="default")
out=h.dispatch(); denied(out)
assert h.provider.used is False and h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
''',
        "corrupt_json": r'''
h.set_provider(h.provider)
with h.sidecar._db("default") as db: db.execute("UPDATE approvals SET data=? WHERE nonce=?",("{malformed",h._record_id))
out=h.dispatch(); denied(out)
assert h.provider.used is False and h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
''',
        "approval_turn_mismatch": r'''
# Leave trusted ContextVars untouched; corrupt only dispatcher-supplied identity kwargs.
original = h.manager.dispatch_tool_execution_interceptors
def mismatched(tool_name, args, **identity):
 identity["turn_id"] = "other-turn"
 return original(tool_name, args, **identity)
h.manager.dispatch_tool_execution_interceptors = mismatched
out=h.dispatch(); denied(out)
assert h.adapter._last_error == "PermissionError('untrusted write context')"
assert h.adapter._reviewer_verdict_provider is None
assert h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
assert not h.fixture.store.list_execution_audits("task-stage2")
assert h.sidecar.find_unique_approved("default", "task-stage2", h.fixture.request.request_id)["plan_display_digest"] == h._original_display_digest
''',
        "approval_call_mismatch": r'''
# Leave trusted ContextVars untouched; corrupt only dispatcher-supplied identity kwargs.
original = h.manager.dispatch_tool_execution_interceptors
def mismatched(tool_name, args, **identity):
 identity["tool_call_id"] = "other-call"
 return original(tool_name, args, **identity)
h.manager.dispatch_tool_execution_interceptors = mismatched
out=h.dispatch(); denied(out)
assert h.adapter._last_error == "PermissionError('untrusted write context')"
assert h.adapter._reviewer_verdict_provider is None
assert h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
assert not h.fixture.store.list_execution_audits("task-stage2")
assert h.sidecar.find_unique_approved("default", "task-stage2", h.fixture.request.request_id)["plan_display_digest"] == h._original_display_digest
''',
        "missing_task_id": r'''
h.set_provider(h.provider)
out=model_tools.handle_function_call('write_file', {'path':'B','content':'approved bytes'}, session_id=h.entry.session_id, turn_id='turn-stage2', tool_call_id='call-stage2', api_request_id='request-stage2'); denied(out)
assert h.provider.used is False and h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
assert not h.fixture.store.list_execution_audits("task-stage2")
''',
        "blank_task_id": r'''
h.set_provider(h.provider)
out=model_tools.handle_function_call('write_file', {'path':'B','content':'approved bytes'}, task_id=' ', session_id=h.entry.session_id, turn_id='turn-stage2', tool_call_id='call-stage2', api_request_id='request-stage2'); denied(out)
assert h.provider.used is False and h.fixture.store.load("task-stage2").mutation_proposal is None
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
assert not h.fixture.store.list_execution_audits("task-stage2")
''',
    }
    run_scenario(tmp_path, cases[scenario])


@pytest.mark.parametrize("scenario", ["stale_revision", "stale_digest", "workspace_identity", "live_route", "exact_identity"])
def test_provider_unconfigured_is_checked_after_stage2_identity_validation(tmp_path, scenario):
    cases = {
        "stale_revision": r'''
with h.sidecar._db("default") as db:
 row=db.execute("SELECT data FROM approvals WHERE nonce=?",(h._record_id,)).fetchone(); rec=json.loads(row[0]); rec["plan_revision"] += 1
 db.execute("UPDATE approvals SET data=? WHERE nonce=?",(json.dumps(rec),h._record_id))
out=h.dispatch(); denied(out)
assert h.adapter._last_error == "PermissionError('no unique matching delivered approval')"
''',
        "stale_digest": r'''
h.tamper_display_digest()
out=h.dispatch(); denied(out)
assert h.adapter._last_error == "PermissionError('Stage-1 displayed plan digest does not match current approved plan')"
''',
        "workspace_identity": r'''
with h.sidecar._db("default") as db:
 row=db.execute("SELECT data FROM approvals WHERE nonce=?",(h._record_id,)).fetchone(); rec=json.loads(row[0]); rec["workspace_identity"]["inode"] += 1
 db.execute("UPDATE approvals SET data=? WHERE nonce=?",(json.dumps(rec),h._record_id))
out=h.dispatch(); denied(out)
assert h.adapter._last_error == "PermissionError('no unique matching delivered approval')"
''',
        "live_route": r'''
h.routes.reset_session(h.entry.session_key)
out=h.dispatch(); denied(out)
assert h.adapter._last_error == "PermissionError('live Telegram route does not match approved session')"
''',
        "exact_identity": r'''
out=h.dispatch(); denied(out)
assert h.adapter._last_error == "PermissionError('reviewer verdict provider is not configured')"
''',
    }
    run_scenario(tmp_path, r'''
assert h.adapter._reviewer_verdict_provider is None
assert h.provider.used is False
''' + cases[scenario] + r'''
assert h.adapter._reviewer_verdict_provider is None
assert h.provider.used is False
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
assert h.fixture.store.load("task-stage2").mutation_proposal is None
assert not h.fixture.store.list_execution_audits("task-stage2")
assert h.sidecar.find_unique_approved("default", "task-stage2", h.fixture.request.request_id) is not None
''')


@pytest.mark.parametrize("scenario,expected", [
    ("runtime_profile", "PermissionError('untrusted write context')"),
    ("runtime_session", "PermissionError('untrusted write context')"),
    ("wrong_task", "PermissionError('no unique matching delivered approval')"),
    ("request_binding", "PermissionError('sidecar request does not match current Gate request')"),
    ("wrong_chat", "PermissionError('no unique matching delivered approval')"),
    ("wrong_user", "PermissionError('no unique matching delivered approval')"),
    ("missing_task_id", "PermissionError('untrusted write context')"),
    ("stale_plan_digest", "PermissionError('no unique matching delivered approval')"),
    ("ambiguous_approval", "PermissionError('no unique matching delivered approval')"),
    ("missing_turn", "PermissionError('untrusted write context')"),
    ("missing_call", "PermissionError('untrusted write context')"),
])
def test_no_provider_real_dispatch_rejects_current_identity_mismatches(tmp_path, scenario, expected):
    cases = {
        "runtime_profile": r'''
from gateway import session_context
session_context.set_session_vars(platform="telegram",chat_type="dm",chat_id="42",user_id="42",session_key=h.entry.session_key,session_id=h.entry.session_id,profile="foreign-profile")
out=h.dispatch(); denied(out)
''',
        "runtime_session": r'''
from gateway import session_context
session_context.set_session_vars(platform="telegram",chat_type="dm",chat_id="42",user_id="42",session_key=h.entry.session_key,session_id="foreign-session",profile="default")
out=h.dispatch(); denied(out)
''',
        "wrong_task": r'''
import model_tools
out=model_tools.handle_function_call('write_file', {'path':'B','content':'approved bytes'}, task_id='model-task-is-not-authoritative', session_id=h.entry.session_id, turn_id='turn-stage2', tool_call_id='call-stage2', api_request_id='request-stage2'); denied(out)
''',
        "request_binding": r'''
with h.sidecar._db("default") as db:
 row=db.execute("SELECT data FROM approvals WHERE nonce=?",(h._record_id,)).fetchone(); rec=json.loads(row[0]); rec["approval_request_id"]="different-request"
 db.execute("UPDATE approvals SET data=? WHERE nonce=?",(json.dumps(rec),h._record_id))
out=h.dispatch(); denied(out)
''',
        "wrong_chat": r'''
from gateway import session_context
session_context.set_session_vars(platform="telegram",chat_type="dm",chat_id="999",user_id="42",session_key=h.entry.session_key,session_id=h.entry.session_id,profile="default")
out=h.dispatch(); denied(out)
''',
        "wrong_user": r'''from gateway import session_context
session_context.set_session_vars(platform="telegram",chat_type="dm",chat_id="42",user_id="43",session_key=h.entry.session_key,session_id=h.entry.session_id,profile="default")
out=h.dispatch(); denied(out)
''',
        "missing_task_id": r'''import model_tools
out=model_tools.handle_function_call('write_file', {'path':'B','content':'approved bytes'}, session_id=h.entry.session_id, turn_id='turn-stage2', tool_call_id='call-stage2', api_request_id='request-stage2'); denied(out)
''',
        "stale_plan_digest": r'''with h.sidecar._db("default") as db:
 row=db.execute("SELECT data FROM approvals WHERE nonce=?",(h._record_id,)).fetchone(); rec=json.loads(row[0]); rec["plan_digest"]="0"*64
 db.execute("UPDATE approvals SET data=? WHERE nonce=?",(json.dumps(rec),h._record_id))
out=h.dispatch(); denied(out)
''',
        "ambiguous_approval": r'''with h.sidecar._db("default") as db:
 row=db.execute("SELECT nonce,data FROM approvals WHERE nonce=?",(h._record_id,)).fetchone()
 duplicate="z"*43
 rec=json.loads(row[1]); rec["nonce"]=duplicate
 db.execute("INSERT INTO approvals VALUES (?, ?, 'approved')",(duplicate,json.dumps(rec)))
out=h.dispatch(); denied(out)
''',
        "missing_turn": r'''
original=h.manager.dispatch_tool_execution_interceptors
def missing(tool_name,args,**identity):
 identity.pop("turn_id",None); return original(tool_name,args,**identity)
h.manager.dispatch_tool_execution_interceptors=missing
out=h.dispatch(); denied(out)
''',
        "missing_call": r'''
original=h.manager.dispatch_tool_execution_interceptors
def missing(tool_name,args,**identity):
 identity.pop("tool_call_id",None); return original(tool_name,args,**identity)
h.manager.dispatch_tool_execution_interceptors=missing
out=h.dispatch(); denied(out)
''',
    }
    run_scenario(tmp_path, r'''
assert h.adapter._reviewer_verdict_provider is None and h.provider.used is False
''' + cases[scenario] + r'''
assert h.adapter._last_error == EXPECTED, h.adapter._last_error
assert h.adapter._reviewer_verdict_provider is None and h.provider.used is False
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
assert h.fixture.store.load("task-stage2").mutation_proposal is None
assert not h.fixture.store.list_execution_audits("task-stage2")
assert not list(h.workspace.iterdir())
'''.replace("EXPECTED", repr(expected)))


@pytest.mark.parametrize("field", [
    "HERMES_SESSION_PLATFORM", "HERMES_SESSION_CHAT_TYPE", "HERMES_SESSION_CHAT_ID",
    "HERMES_SESSION_USER_ID", "HERMES_SESSION_KEY", "HERMES_SESSION_ID",
    "HERMES_SESSION_PROFILE", "_approval_session_id", "_approval_turn_id",
    "_approval_tool_call_id",
])
def test_no_provider_real_dispatch_fails_closed_when_authoritative_context_is_unbound(tmp_path, field):
    run_scenario(tmp_path, r'''
import gateway.session_context as session_context
import tools.approval_context as approval_context
field = FIELD_VALUE
if field.startswith("HERMES_SESSION_"):
    variable = session_context._VAR_MAP[field]
    missing_value = session_context._UNSET
else:
    variable = getattr(approval_context, field)
    missing_value = None
original = h.manager.dispatch_tool_execution_interceptors
def unbound_context(tool_name, args, **identity):
    token = variable.set(missing_value)
    try:
        return original(tool_name, args, **identity)
    finally:
        variable.reset(token)
h.manager.dispatch_tool_execution_interceptors = unbound_context
assert h.adapter._reviewer_verdict_provider is None and h.provider.used is False
out=h.dispatch(); denied(out)
assert h.adapter._last_error == "PermissionError('untrusted write context')", h.adapter._last_error
assert h.adapter._reviewer_verdict_provider is None and h.provider.used is False
assert h.fixture.store.load("task-stage2").state.name == "APPROVED"
assert h.fixture.store.load("task-stage2").mutation_proposal is None
assert not h.fixture.store.list_execution_audits("task-stage2")
assert not list(h.workspace.iterdir())
assert h.native_calls == []
'''.replace("FIELD_VALUE", repr(field)))


def test_real_dispatch_consumes_approved_task_and_denies_replay(tmp_path):
    run_scenario(tmp_path, r'''
h.set_provider(h.provider)
out=h.dispatch(); assert "block" not in out.lower() and "den" not in out.lower(), out
assert h.native_calls == []
task = h.fixture.store.load("task-stage2")
assert task.mutation_proposal is not None
assert h.provider.used is True
assert task.state.name == "VERIFYING", task.state
first_audits = h.fixture.store.list_execution_audits("task-stage2")
assert len(first_audits) == 1
first_authorization = h.fixture.store.get_authorization(first_audits[0].authorization_id)
assert first_authorization and first_authorization.status.value == "CONSUMED", first_authorization
assert (h.workspace/"B").read_bytes() == b"approved bytes"
second=h.dispatch(); assert isinstance(second,str) and ("block" in second.lower() or "den" in second.lower() or "authoriz" in second.lower()),second
assert h.native_calls == []
assert (h.workspace/"B").read_bytes() == b"approved bytes"
audits = h.fixture.store.list_execution_audits("task-stage2")
assert len(audits) == 1
assert audits[0].authorization_id == first_audits[0].authorization_id
authorization = h.fixture.store.get_authorization(audits[0].authorization_id)
assert authorization and authorization.status.value == "CONSUMED", authorization
assert h.provider.used is True
''')
