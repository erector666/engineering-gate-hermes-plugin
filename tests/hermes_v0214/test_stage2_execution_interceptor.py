"""Stage 2 real-dispatcher tracer for the pinned disposable Hermes host."""
from __future__ import annotations
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERMES = Path("/home/uss/.hermes/cache/scratch/hermes-v0214-execution-interception")
PYTHON = Path("/home/uss/.hermes/hermes-agent/venv/bin/python")


def test_plugin_registers_final_write_interceptor_in_real_plugin_manager(tmp_path):
    script = r'''
import os
from pathlib import Path
from hermes_cli.plugins import get_plugin_manager
from hermes_cli.plugins_manifest import PluginManifest
home=Path(os.environ['HERMES_HOME']); home.mkdir(parents=True,exist_ok=True)
manager=get_plugin_manager()
manifest=PluginManifest(name='engineering-gate',version='0.1.0',path=os.environ['PLUGIN_PATH'],source='project')
manager._load_plugin(manifest)
loaded=manager._plugins['engineering-gate']
assert not loaded.error, loaded.error
assert manager._plugin_tool_names == {'gate_approve_plan'}
assert len(manager._tool_execution_interceptors) == 1, manager._tool_execution_interceptors
assert manager._tool_execution_interceptors[0][0] == frozenset({'write_file'})
'''
    env=os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path/'hermes-home'),PLUGIN_PATH=str(ROOT/'engineering-gate'),
               HERMES_SOURCE_ROOT=str(HERMES),PYTHONPATH=os.pathsep.join((str(ROOT/'engineering-gate'),str(HERMES))))
    result=subprocess.run([str(PYTHON),'-c',script],env=env,text=True,capture_output=True,timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr




def test_write_hook_readiness_is_scoped_to_each_plugin_context(tmp_path):
    script = r'''
import os
from pathlib import Path
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from adapters.hermes.hooks import register_hooks
base=Path(os.environ['HERMES_HOME']); base.mkdir(parents=True,exist_ok=True)
manifest=PluginManifest(name="engineering-gate",path=str(Path(os.environ['PLUGIN_PATH'])),source="project")
home_a=(base/"profile-a").resolve(); home_a.mkdir()
home_b=(base/"profile-b").resolve(); home_b.mkdir()
manager_a=PluginManager(scope_key=str(home_a)); manager_b=PluginManager(scope_key=str(home_b))
ctx_a=PluginContext(manifest,manager_a); ctx_b=PluginContext(manifest,manager_b)
set_ready_a,make_binding_a=register_hooks(ctx_a)
set_ready_b,make_binding_b=register_hooks(ctx_b)
binding_a=make_binding_a("profile-a",str(home_a),str(home_a/"engineering-gate-state.sqlite3"),str(home_a/"engineering-gate-approvals.sqlite3"))
binding_b=make_binding_b("profile-b",str(home_b),str(home_b/"engineering-gate-state.sqlite3"),str(home_b/"engineering-gate-approvals.sqlite3"))
set_ready_b(True,binding_a)
callback_a=manager_a._hooks["pre_tool_call"][0]; callback_b=manager_b._hooks["pre_tool_call"][0]
assert callback_a(tool_name="write_file",args={"path":"x","content":"x"})["action"] == "block"
assert callback_b(tool_name="write_file",args={"path":"x","content":"x"})["action"] == "block"
set_ready_a(True,binding_a); set_ready_b(True,binding_b)
assert callback_a(tool_name="write_file",args={"path":"x","content":"x"}) is None
assert callback_b(tool_name="write_file",args={"path":"x","content":"x"}) is None
manager_a.unload()
assert callback_a(tool_name="write_file",args={"path":"x","content":"x"})["action"] == "block"
assert callback_b(tool_name="write_file",args={"path":"x","content":"x"}) is None
assert callback_a(tool_name="read_file",args={"path":"x"}) is None
'''
    env=os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path/"home"),PLUGIN_PATH=str(ROOT/"engineering-gate"),PYTHONPATH=os.pathsep.join((str(ROOT/"engineering-gate"),str(HERMES))))
    result=subprocess.run([str(PYTHON),"-c",script],env=env,text=True,capture_output=True,timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
