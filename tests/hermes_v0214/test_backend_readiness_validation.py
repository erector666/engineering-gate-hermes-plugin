"""Real pinned-Hermes plugin-load checks for fail-closed backend validation."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERMES = Path("/home/uss/.hermes/hermes-agent")
PYTHON = HERMES / "venv/bin/python"


def test_corrupt_existing_backend_never_arms_write_hook(tmp_path):
    script = r'''
import os
from pathlib import Path
from hermes_cli.plugins import PluginManager
from hermes_cli.plugins_manifest import PluginManifest
home=Path(os.environ['HERMES_HOME']); home.mkdir(parents=True,exist_ok=True)
(home/'engineering-gate-state.sqlite3').write_bytes(b'not a sqlite database')
manager=PluginManager(scope_key=str(home))
manifest=PluginManifest(name='engineering-gate',version='0.1.0',path=os.environ['PLUGIN_PATH'],source='project')
manager._load_plugin(manifest)
loaded=manager._plugins['engineering-gate']
assert not loaded.error, loaded.error
hook=manager._hooks['pre_tool_call'][0]
assert hook('write_file',{'path':'x','content':'x'})['action']=='block'
'''
    env = os.environ.copy()
    env.update(
        HERMES_HOME=str(tmp_path / "disposable-hermes-home"),
        PLUGIN_PATH=str(ROOT / "engineering-gate"),
        PYTHONPATH=os.pathsep.join((str(ROOT / "engineering-gate"), str(HERMES))),
    )
    result = subprocess.run([str(PYTHON), "-c", script], env=env, text=True, capture_output=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
