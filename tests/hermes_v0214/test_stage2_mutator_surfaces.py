"""Forbidden mutation surfaces are stopped by the pinned real dispatcher."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

HERMES = Path("/home/uss/.hermes/cache/scratch/hermes-v0214-execution-interception")
PYTHON = Path("/home/uss/.hermes/hermes-agent/venv/bin/python")
PINNED_HEAD = "d3b25b52ad1318c526bdb259b600eeca3d5f38e6"
ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "engineering-gate"


def test_forbidden_mutators_block_before_native_and_read_file_continues(tmp_path):
    head = subprocess.check_output(["git", "-C", str(HERMES), "rev-parse", "HEAD"], text=True).strip()
    assert head == PINNED_HEAD
    script = r'''
import json, os
from pathlib import Path
from tools.registry import registry
import model_tools
import stage2_dispatch_harness as harness
h=harness.create_harness()
home=Path(os.environ["HERMES_HOME"])

# The source-registered tool names are verified against live entries and their native
# handlers are replaced by fail-fast spies before actual model dispatcher invocation.
mutators={"patch", "execute_code", "delegate_task", "terminal"}
spy_calls={}
for name in mutators:
 entry=registry.get_entry(name,scope=str(home)); assert entry is not None, name
 calls=[]; spy_calls[name]=calls
 def forbidden(*a,_calls=calls,_name=name,**k):
  _calls.append((_name,a,k)); raise AssertionError("native mutator invoked: "+_name)
 entry.handler=forbidden

# Hermes exposes DELETE and MOVE/RENAME as V4A patch operations, not separate
# registry tools. Exercise each through the actual registered patch dispatcher.
patch=registry.get_entry("patch",scope=str(home))
for operation in ("*** Delete File: victim.txt", "*** Move to: renamed.txt"):
 args={"path":"source.txt","patch":"*** Begin Patch\n*** Update File: source.txt\n"+operation+"\n*** End Patch"}
 out=model_tools.handle_function_call("patch",args,task_id="task-stage2",session_id=h.entry.session_id,turn_id="turn-stage2",tool_call_id="mutator",api_request_id="request")
 assert any(word in out.lower() for word in ("block", "denied", "authorization", "permits only", "not permitted", "not allowed")),(operation,out)
 assert spy_calls["patch"]==[],spy_calls["patch"]

cases={
 "execute_code":{"code":"raise SystemExit('must not run')"},
 "delegate_task":{"goal":"must not spawn","task":"must not spawn"},
 "terminal":{"command":"touch /tmp/must-not-run"},
}
for name,args in cases.items():
 out=model_tools.handle_function_call(name,args,task_id="task-stage2",session_id=h.entry.session_id,turn_id="turn-stage2",tool_call_id="mutator",api_request_id="request")
 assert any(word in out.lower() for word in ("block", "denied", "authorization", "permits only", "not permitted", "not allowed", "must be handled by the agent loop")),(name,out)
 assert spy_calls[name]==[],name

# Add a disposable registered surface to prove name-agnostic denial. It has no side
# effects; its spy fails if dispatch reaches the native handler.
name="stage2_unknown_mutator"
unknown_calls=[]
def unknown_handler(args,**kwargs):
 unknown_calls.append((args,kwargs)); raise AssertionError("unknown native tool invoked")
registry.register(name,"stage2-test",{"type":"object","properties":{"action":{"type":"string"}},"required":["action"]},unknown_handler,description="test-only mutator")
assert registry.get_entry(name,scope=str(home)) is not None
out=model_tools.handle_function_call(name,{"action":"mutate"},task_id="task-stage2",session_id=h.entry.session_id,turn_id="turn-stage2",tool_call_id="mutator",api_request_id="request")
assert any(word in out.lower() for word in ("block", "denied", "authorization", "permits only", "not permitted", "not allowed", "must be handled by the agent loop")),(name,out)
assert unknown_calls==[],unknown_calls

# Ordinary read_file continues through dispatch to the actual native read handler.
file=home/"readme.txt"; file.write_text("expected read contents\n",encoding="utf-8")
read=registry.get_entry("read_file",scope=str(home)); assert read
original=read.handler; reads=[]
def read_spy(args,**kwargs):
 reads.append(dict(args)); return original(args,**kwargs)
read.handler=read_spy
from tools.file_tools_read_tracking import reset_file_dedup
reset_file_dedup("task-stage2")
out=model_tools.handle_function_call("read_file",{"path":str(file)},task_id="task-stage2",session_id=h.entry.session_id,turn_id="turn-stage2",tool_call_id="read-call",api_request_id="read-request")
assert len(reads)==1 and reads[0]["path"]==str(file),reads
assert "expected read contents" in out,out
assert not any(item[0]=="read_file" for item in h.intercepted),h.intercepted
h.close()
'''
    env = os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path / "hermes-home"), WORKSPACE=str(tmp_path / "workspace"),
               PLUGIN_PATH=str(PLUGIN),
               PYTHONPATH=os.pathsep.join((str(ROOT / "engineering-gate"), str(ROOT / "tests/hermes_v0214"), str(HERMES))))
    result = subprocess.run([str(PYTHON), "-c", script], env=env, text=True, capture_output=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr


def test_delegate_task_blocked_on_real_agent_concurrent_invoke_path(tmp_path):
    """The registered Gate hook must stop delegate_task before its agent inline executor."""
    head = subprocess.check_output(["git", "-C", str(HERMES), "rev-parse", "HEAD"], text=True).strip()
    assert head == PINNED_HEAD
    script = r'''
import json, os
from pathlib import Path
from unittest.mock import patch
from agent.agent_runtime_helpers import invoke_tool
import run_agent
import stage2_dispatch_harness as harness
h=harness.create_harness()
home=Path(os.environ["HERMES_HOME"])
task_before=h.fixture.store.load("task-stage2")
request_before=h.fixture.store.load("task-stage2").approval_request
approval_before=h.sidecar.find_unique_approved("default","task-stage2",request_before.request_id)
assert approval_before is not None
delegate_entry=__import__("tools.registry",fromlist=["registry"]).registry.get_entry("delegate_task",scope=str(home))
assert delegate_entry is not None
native_calls=[]
def forbidden_native(*a,**k):
 native_calls.append((a,k)); raise AssertionError("delegate registry handler invoked")
delegate_entry.handler=forbidden_native
inline_calls=[]
agent=run_agent.AIAgent.__new__(run_agent.AIAgent)
agent.session_id=h.entry.session_id
agent._current_turn_id="turn-stage2"
agent._current_api_request_id="request-stage2"
agent.valid_tool_names=["delegate_task"]
agent.enabled_toolsets=None; agent.disabled_toolsets=None
agent._delegate_spinner=None
def forbidden_inline(*a,**k):
 inline_calls.append((a,k)); raise AssertionError("agent delegate executor reached")
args={"goal":"must remain blocked","task":"must remain blocked"}
with patch.object(run_agent.AIAgent,"_dispatch_delegate_task",forbidden_inline):
 result=invoke_tool(agent,"delegate_task",args,"task-stage2","delegate-call",messages=[])
decoded=json.loads(result)
assert set(decoded)=={"error"} and any(word in decoded["error"].lower() for word in ("block","denied","authorization","not permitted","not allowed","permits only")),result
assert inline_calls==[] and native_calls==[],(inline_calls,native_calls)
assert h.provider.used is False and h.execution_seen==[]
assert h.request_seen in ([],[args]),h.request_seen
assert h.intercepted==[] and h.native_calls==[]
task_after=h.fixture.store.load("task-stage2")
assert task_after==task_before
request_after=h.fixture.store.load("task-stage2").approval_request
assert request_after==request_before
approval_after=h.sidecar.find_unique_approved("default","task-stage2",request_after.request_id)
assert approval_after==approval_before
h.close()
'''
    env = os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path / "hermes-home"), WORKSPACE=str(tmp_path / "workspace"),
               PLUGIN_PATH=str(PLUGIN),
               PYTHONPATH=os.pathsep.join((str(ROOT / "engineering-gate"), str(ROOT / "tests/hermes_v0214"), str(HERMES))))
    result = subprocess.run([str(PYTHON), "-c", script], env=env, text=True, capture_output=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
