"""Real pinned Hermes dispatch proves final args and native mutation suppression."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

HERMES = Path("/home/uss/.hermes/cache/scratch/hermes-v0214-execution-interception")
PYTHON = Path("/home/uss/.hermes/hermes-agent/venv/bin/python")
PINNED_HEAD = "d3b25b52ad1318c526bdb259b600eeca3d5f38e6"
ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "engineering-gate"


def test_real_dispatch_uses_rewritten_write_args_but_continues_read_file(tmp_path):
    head = subprocess.check_output(["git", "-C", str(HERMES), "rev-parse", "HEAD"], text=True).strip()
    assert head == PINNED_HEAD
    script = r'''
import json, os
from pathlib import Path
from hermes_cli.plugins import get_plugin_manager
from hermes_cli.plugins_manifest import PluginManifest
from tools.registry import registry
import model_tools
home=Path(os.environ["HERMES_HOME"]); home.mkdir(parents=True,exist_ok=True)
(home/"existing.txt").write_text("real read result\\n",encoding="utf-8")
manager=get_plugin_manager()
manager._load_plugin(PluginManifest(name="engineering-gate",version="0.1.0",path=os.environ["PLUGIN_PATH"],source="project"))
loaded=manager._plugins["engineering-gate"]; assert not loaded.error,loaded.error
assert len(manager._tool_execution_interceptors)==1
interceptor=manager._tool_execution_interceptors[0][1]
seen=[]
def observe(name,args,**context):
 seen.append((name,dict(args),context))
 return interceptor(name,args,**context)
manager._tool_execution_interceptors[0]=(manager._tool_execution_interceptors[0][0],observe,manager._tool_execution_interceptors[0][2])
request_seen=[]
def request_middleware(**payload):
 request_seen.append((payload["tool_name"],dict(payload["args"])))
 return {"args":payload["args"]}
execution_seen=[]
def execution_middleware(**payload):
 execution_seen.append((payload["tool_name"],dict(payload["args"])))
 if payload["tool_name"]=="write_file":
  return payload["next_call"]({**payload["args"],"path":"B","content":"final"})
 return payload["next_call"]()
manager._middleware.setdefault("tool_request",[]).append(request_middleware)
manager._middleware.setdefault("tool_execution",[]).append(execution_middleware)
write=registry.get_entry("write_file",scope=str(home)); assert write
write_calls=[]; orig_write=write.handler
def write_spy(*a,**k):
 write_calls.append((a,k)); raise AssertionError("native write handler invoked")
write.handler=write_spy
try:
 out=model_tools.handle_function_call("write_file",{"path":"A","content":"initial"},task_id="task-7",session_id="session-8",turn_id="turn-9",tool_call_id="call-10",api_request_id="request-11")
 assert write_calls==[],write_calls
 assert request_seen and request_seen[-1]==("write_file",{"path":"A","content":"initial"}),request_seen
 assert execution_seen and execution_seen[-1]==("write_file",{"path":"A","content":"initial"}),execution_seen
 assert seen and seen[-1][0]=="write_file" and seen[-1][1]=={"path":"B","content":"final"},seen
 assert {k:seen[-1][2].get(k) for k in ("task_id","session_id","turn_id","tool_call_id","api_request_id")}=={"task_id":"task-7","session_id":"session-8","turn_id":"turn-9","tool_call_id":"call-10","api_request_id":"request-11"},seen[-1]
 assert "block" in out.lower() or "authorization" in out.lower(),out
finally: write.handler=orig_write
read=registry.get_entry("read_file",scope=str(home)); assert read
read_calls=[]; orig_read=read.handler
from tools.file_tools_read_tracking import reset_file_dedup
reset_file_dedup("task-7")
def read_spy(args,**kw):
 read_calls.append(dict(args)); return orig_read(args,**kw)
read.handler=read_spy
try:
 out=model_tools.handle_function_call("read_file",{"path":str(Path(os.environ["HERMES_HOME"])/"existing.txt")},task_id="task-7",session_id="session-8",turn_id="turn-9",tool_call_id="read-call",api_request_id="read-request")
 assert len(read_calls)==1 and read_calls[0]["path"].endswith("existing.txt"),read_calls
 assert "real read result" in out,out
finally: read.handler=orig_read
'''
    env = os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path / "hermes-home"), PLUGIN_PATH=str(PLUGIN),
               PYTHONPATH=os.pathsep.join((str(ROOT / "engineering-gate"), str(HERMES))))
    result = subprocess.run([str(PYTHON), "-c", script], env=env, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
