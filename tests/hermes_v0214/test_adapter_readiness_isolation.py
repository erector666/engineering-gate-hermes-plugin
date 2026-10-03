"""Behavior regressions for per-context, fail-closed write readiness."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERMES = Path("/home/uss/.hermes/cache/scratch/hermes-v0214-execution-interception")
PYTHON = Path("/home/uss/.hermes/hermes-agent/venv/bin/python")


def _run(tmp_path, script):
    env = os.environ.copy()
    env.update(
        HERMES_HOME=str(tmp_path / "home"),
        PLUGIN_PATH=str(ROOT / "engineering-gate"),
        HERMES_SOURCE_ROOT=str(HERMES),
        PYTHONPATH=os.pathsep.join((str(ROOT / "engineering-gate"), str(HERMES))),
    )
    result = subprocess.run(
        [str(PYTHON), "-c", script], env=env, text=True, capture_output=True, timeout=45,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_readiness_isolated_across_profiles_and_same_session_id(tmp_path):
    _run(tmp_path, r'''
import os
from pathlib import Path
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from adapters.hermes.hooks import pre_tool_call, register_hooks
base=Path(os.environ['HERMES_HOME']); manifest=PluginManifest(name='engineering-gate',path=os.environ['PLUGIN_PATH'],source='project')
def make(profile):
    home=(base/'profiles'/profile).resolve()
    home.mkdir(parents=True)
    manager=PluginManager(scope_key=str(home)); ctx=PluginContext(manifest,manager)
    set_ready,make_binding=register_hooks(ctx)
    binding=make_binding(profile,str(home),str(home/'engineering-gate-state.sqlite3'),str(home/'engineering-gate-approvals.sqlite3'))
    return manager,set_ready,binding,manager._hooks['pre_tool_call'][0]
a,ready_a,binding_a,hook_a=make('a')
b,ready_b,binding_b,hook_b=make('b')
assert pre_tool_call('write_file', {'path':'x','content':'x'})['action']=='block'
assert hook_a('write_file', {'path':'x','content':'x'})['action']=='block'
# A's sealed manager-bound binding cannot arm B.
ready_b(True,binding_a)
assert hook_b('write_file',{'path':'x','content':'x'})['action']=='block'
ready_a(True,binding_a)
assert hook_a('write_file', {'path':'x','content':'x'}, session_id='same') is None
assert hook_b('write_file', {'path':'x','content':'x'}, session_id='same')['action']=='block'
hook_a('write_file', {'path':'x','content':'x'}, task_id='approved-task', approval=True)
assert hook_b('write_file', {'path':'x','content':'x'}, task_id='approved-task', approval=True)['action']=='block'
ready_b(True,binding_b)
assert hook_a('write_file', {'path':'x','content':'x'}) is None
assert hook_b('write_file', {'path':'x','content':'x'}) is None
a.unload()
assert hook_a('write_file', {'path':'x','content':'x'})['action']=='block'
assert hook_b('write_file', {'path':'x','content':'x'}) is None
''')


def test_ready_hook_allows_only_write_file_shape_and_interceptor_still_blocks(tmp_path):
    _run(tmp_path, r'''
import os
from pathlib import Path
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from adapters.hermes.execution import GateExecutionAdapter
from adapters.hermes.hooks import register_hooks
home=(Path(os.environ['HERMES_HOME'])/'profile').resolve(); home.mkdir(parents=True)
manager=PluginManager(scope_key=str(home))
ctx=PluginContext(PluginManifest(name='engineering-gate',path=os.environ['PLUGIN_PATH'],source='project'),manager)
ready,make_binding=register_hooks(ctx)
ready(True,make_binding('profile',str(home),str(home/'engineering-gate-state.sqlite3'),str(home/'engineering-gate-approvals.sqlite3')))
hook=manager._hooks['pre_tool_call'][0]
assert hook('write_file', {'path':'x','content':'x'}) is None
for name,args in [
 ('write_file',{'path':'x'}),('write_file',{'path':'x','content':'x','extra':1}),
 ('patch',{}),('delete',{}),('rename',{}),('execute',{}),('delegate_task',{}),('unknown',{})]:
    assert hook(name,args)['action']=='block', (name,args)
adapter=GateExecutionAdapter(profile_home=str(home), profile_id='profile', state_store_provider=lambda: (_ for _ in ()).throw(AssertionError('provider must not be reached')), approval_sidecar=None)
decision=adapter.intercept_write('write_file',{'path':'x','content':'x'})
assert decision.action=='BLOCK'
assert adapter._reviewer_verdict_provider is None
''')


def test_concurrent_readiness_changes_and_unload_are_instance_local(tmp_path):
    _run(tmp_path, r'''
import os, concurrent.futures, threading
from pathlib import Path
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from adapters.hermes.hooks import register_hooks
base=Path(os.environ['HERMES_HOME']); manifest=PluginManifest(name='engineering-gate',path=os.environ['PLUGIN_PATH'],source='project')
def make(profile):
    home=(base/'profiles'/profile).resolve(); home.mkdir(parents=True)
    manager=PluginManager(scope_key=str(home)); ctx=PluginContext(manifest,manager)
    ready,make_binding=register_hooks(ctx)
    binding=make_binding(profile,str(home),str(home/'engineering-gate-state.sqlite3'),str(home/'engineering-gate-approvals.sqlite3'))
    return manager,ready,binding,manager._hooks['pre_tool_call'][0]
a,ra,ba,ha=make('a'); b,rb,bb,hb=make('b')
ra(True,ba); rb(True,bb)
barrier=threading.Barrier(3)
def cycle(toggle, own, binding):
    barrier.wait()
    for _ in range(200):
        toggle(False); assert own('write_file',{'path':'x','content':'x'})['action']=='block'
        toggle(True,binding); assert own('write_file',{'path':'x','content':'x'}) is None
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    futures=[pool.submit(cycle,ra,ha,ba),pool.submit(cycle,rb,hb,bb)]
    barrier.wait()
    for future in futures: future.result()
a.unload()
assert ha('write_file',{'path':'x','content':'x'})['action']=='block'
assert hb('write_file',{'path':'x','content':'x'}) is None
''')
