"""Actual pinned Hermes dispatcher and Telegram callback Stage 1 tracer."""
from __future__ import annotations
import os, subprocess
from pathlib import Path
HERMES=Path("/home/uss/.hermes/hermes-agent")
PYTHON=HERMES/"venv/bin/python"
PINNED_HEAD="d3b25b52ad1318c526bdb259b600eeca3d5f38e6"
ROOT=Path(__file__).resolve().parents[2]
PLUGIN=ROOT/"engineering-gate"

def test_model_tools_dispatch_roundtrips_approval_and_blocks_native_write(tmp_path):
 script=r'''
import asyncio, json, os
from pathlib import Path
from types import SimpleNamespace
from hermes_cli.plugins import get_plugin_manager
from hermes_cli.plugins_manifest import PluginManifest
from tools.registry import registry
from hermes_cli.lifecycle import invoke_hook
from engineering_gate_core.models import *
from engineering_gate_core.workflow import Event, capture_workspace_identity, new_task
from engineering_gate_core.state_store import StateStore
import model_tools
home=Path(os.environ["HERMES_HOME"]); home.mkdir(parents=True,exist_ok=True)
# The pinned model_tools lifecycle resolves hooks through this profile-global manager.
manager=get_plugin_manager()
workspace=home/"workspace"; workspace.mkdir(); profile=home
store=StateStore(profile/"engineering-gate-state.sqlite3")
store.create(new_task("task-1","inspect",RequesterIdentity("telegram:42")))
store.transition("task-1",Event.INSPECTION_RECORDED,InspectionEvidenceRef("i","inspection"))
store.transition("task-1",Event.ANALYSIS_RECORDED,Evidence("a","analysis"))
plan=Plan("inspect",(NormalizedOperation(OperationKind.READ,"src","read"),),(AcceptanceCriterion("c","checked","test"),),("pytest",),workspace_root=str(workspace),workspace_identity=capture_workspace_identity(workspace))
store.transition("task-1",Event.PLAN_RECORDED,plan); store.transition("task-1",Event.BLAST_RADIUS_RECORDED,Evidence("b","blast")); store.transition("task-1",Event.PLAN_REVIEW_PASSED,PlanReview(ReviewVerdict.APPROVED))
c=store.load("task-1"); req=ApprovalRequest(c.task_id,c.revision,c.plan_digest,"request-1"); store.transition("task-1",Event.APPROVAL_REQUESTED,req)
manifest=PluginManifest(name="engineering-gate",version="0.1.0",path=os.environ["PLUGIN_PATH"],source="project"); manager._load_plugin(manifest)
assert not manager._plugins["engineering-gate"].error
handler=[]
class Bot:
 def __init__(self): self.messages=[]
 async def send_message(self,**kw):
  self.messages.append(kw); return SimpleNamespace(message_id=len(self.messages),chat=SimpleNamespace(id=kw["chat_id"],type="private"))
class App:
 bot=Bot()
 def add_handler(self,h,group=0): handler.append(h)
app=App()
# Build the same routing objects used by the host, entirely under the temporary home.
from gateway.config import GatewayConfig, PlatformConfig
from gateway.session import SessionSource, SessionStore
from plugins.platforms.telegram.adapter import TelegramAdapter
session_store=SessionStore(home/"sessions",GatewayConfig())
adapter=TelegramAdapter(PlatformConfig())
adapter._session_store=session_store
route_message=SimpleNamespace(chat=SimpleNamespace(id=42,type="private",is_forum=False),from_user=SimpleNamespace(id=42,username="user",is_bot=False),sender_chat=None,message_thread_id=None,is_topic_message=False)
source=adapter._source_from_message_for_auth(route_message)
entry=session_store.get_or_create_session(source)
manager._platform_handler_factories["telegram"][0][0](app,adapter)
# Bind exact host route session and approval values in the parent context; copy into worker.
import gateway.session_context as sc
session_key=adapter._source_session_key(source)
assert session_store.peek_session_id(session_key)==entry.session_id
sc.set_session_vars(platform="telegram",chat_type="dm",chat_id="42",user_id="42",session_key=entry.session_key,session_id=entry.session_id,profile="default")
from tools import approval_context
approval_context._approval_session_id.set(entry.session_id); approval_context._approval_turn_id.set("turn-1"); approval_context._approval_tool_call_id.set("call-1")
gate_entry=registry.get_entry("gate_approve_plan",scope=str(home)); assert gate_entry and gate_entry.handler
querybox={}
async def send_message(**kw):
 app.bot.messages.append(kw); mid=len(app.bot.messages)
 if "reply_markup" in kw:
  querybox["query"]=SimpleNamespace(data=kw["reply_markup"].inline_keyboard[0][0].callback_data,from_user=SimpleNamespace(id=42),message=SimpleNamespace(message_id=mid,chat=SimpleNamespace(id=42,type="private",is_forum=False),from_user=SimpleNamespace(id=42,username="user",is_bot=False),sender_chat=None,message_thread_id=None,is_topic_message=False),answer=lambda:asyncio.sleep(0))
 return SimpleNamespace(message_id=mid,chat=SimpleNamespace(id=kw["chat_id"],type="private"))
app.bot.send_message=send_message
import concurrent.futures, time
pool=concurrent.futures.ThreadPoolExecutor(1)
def dispatch():
 return model_tools.handle_function_call("gate_approve_plan",{"task_id":"task-1"},task_id="task-1",session_id=entry.session_id,turn_id="turn-1",tool_call_id="call-1")
from contextvars import copy_context
f=pool.submit(copy_context().run,dispatch)
for _ in range(150):
 if "query" in querybox: break
 time.sleep(.02)
if "query" not in querybox:
 raise AssertionError("no approval prompt; dispatcher result="+str(f.result(timeout=3)))
# Verify Telegram's registered callback filter accepts this approval token and
# rejects a receipt token before invoking the actual registered handler.
callback_handler=handler[0]
assert callback_handler.pattern.match(querybox["query"].data)
assert not callback_handler.pattern.match("ea:receipt-1")
# A wrong actor/chat must not consume the pending approval callback.
wrong=SimpleNamespace(data=querybox["query"].data,from_user=SimpleNamespace(id=99),message=SimpleNamespace(message_id=querybox["query"].message.message_id,chat=SimpleNamespace(id=99,type="private")),answer=lambda:asyncio.sleep(0))
asyncio.run(callback_handler.callback(SimpleNamespace(callback_query=wrong),None))
assert not f.done(),"wrong actor/chat consumed the pending callback"
asyncio.run(callback_handler.callback(SimpleNamespace(callback_query=querybox["query"]),None))
result=json.loads(f.result(timeout=3)); assert result["approved"] is True,result
c=store.load("task-1"); assert c.state is TaskState.APPROVED and c.approval is not None and c.approval.request_id=="request-1"
# Replay same concrete callback cannot produce a second receipt.
receipts_before=len([e for e in store.load("task-1").history if e is TaskState.APPROVED])
asyncio.run(callback_handler.callback(SimpleNamespace(callback_query=querybox["query"]),None)); assert store.load("task-1").approval==c.approval
assert len([e for e in store.load("task-1").history if e is TaskState.APPROVED])==receipts_before
# The native write handler must not run before approval.
entryw=registry.get_entry("write_file",scope=str(home)); assert entryw
calls=[]
orig=entryw.handler
entryw.handler=lambda *a,**k:(calls.append(1),(_ for _ in ()).throw(AssertionError("native writer invoked")))[1]
try:
 out=model_tools.handle_function_call("write_file",{"path":"blocked.txt","content":"x"},task_id="task-1",session_id=entry.session_id,turn_id="turn-1",tool_call_id="write-before-approval")
 assert calls==[],calls
 assert "block" in str(out).lower() or "approval" in str(out).lower(),out
 # After plan approval, a write still needs an execution grant; no native writer call.
 out=model_tools.handle_function_call("write_file",{"path":"blocked.txt","content":"x"},task_id="task-1",session_id=entry.session_id,turn_id="turn-1",tool_call_id="write-after-approval")
 assert calls==[],calls
finally: entryw.handler=orig
pool.shutdown(wait=True)
'''
 env=os.environ.copy(); env["HERMES_HOME"]=str(tmp_path/"hermes-home"); env["PLUGIN_PATH"]=str(PLUGIN); env["PYTHONPATH"]=str(ROOT/"engineering-gate")+os.pathsep+str(HERMES)
 head=subprocess.check_output(["git","-C",str(HERMES),"rev-parse","HEAD"],text=True).strip(); assert head==PINNED_HEAD
 result=subprocess.run([str(PYTHON),"-c",script],env=env,text=True,capture_output=True,timeout=15)
 assert result.returncode==0,result.stdout+result.stderr
