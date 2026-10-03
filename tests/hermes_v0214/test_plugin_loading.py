"""Pinned Hermes v0.21.4 plugin-loader contract tests."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

HERMES = Path("/home/uss/.hermes/hermes-agent")
PATCHED_HERMES = Path("/home/uss/.hermes/cache/scratch/hermes-v0214-execution-interception")
PYTHON = HERMES / "venv/bin/python"
PINNED_HEAD = "d3b25b52ad1318c526bdb259b600eeca3d5f38e6"
PLUGIN = Path(__file__).resolve().parents[2] / "engineering-gate"


def test_installed_plugin_discovery_loads_gate_registrations(tmp_path):
    home = tmp_path / "hermes-home"
    installed_plugin = home / "plugins" / "engineering-gate"
    shutil.copytree(
        PLUGIN,
        installed_plugin,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    config = home / "config.yaml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("plugins:\n  enabled:\n    - engineering-gate\n")
    bundled_plugins = tmp_path / "empty-bundled-plugins"
    bundled_plugins.mkdir()
    neutral_cwd = tmp_path / "neutral-cwd"
    neutral_cwd.mkdir()

    script = r'''
import os
from hermes_cli.plugins import PluginManager

home = os.environ["HERMES_HOME"]
manager = PluginManager(scope_key=home)
manager.discover_and_load()
assert "engineering-gate" in manager._plugins
loaded = manager._plugins["engineering-gate"]
assert not loaded.error, loaded.error
assert manager._plugin_tool_names == {"gate_approve_plan"}, manager._plugin_tool_names
assert set(manager._hooks) == {"pre_tool_call"}, manager._hooks
assert manager._tool_execution_interceptors, manager._tool_execution_interceptors
'''
    env = os.environ.copy()
    env["HERMES_HOME"] = str(home)
    env["HERMES_BUNDLED_PLUGINS"] = str(bundled_plugins)
    env["PYTHONPATH"] = str(PATCHED_HERMES)
    result = subprocess.run(
        [str(PYTHON), "-c", script],
        cwd=neutral_cwd,
        env=env,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_plugin_loads_in_multiple_hermes_manager_scopes(tmp_path):
    script = r'''
import os
from hermes_cli.plugins import PluginManager
from hermes_cli.plugins_manifest import PluginManifest

plugin_path = os.environ["PLUGIN_PATH"]
for scope in ("profile-one", "profile-two"):
    manager = PluginManager(scope_key=scope)
    manifest = PluginManifest(
        name="engineering-gate", version="0.1.0", path=plugin_path,
        source="project",
    )
    manager._load_plugin(manifest)
    assert "engineering-gate" in manager._plugins, manager._plugins
    loaded = manager._plugins["engineering-gate"]
    assert not loaded.error, loaded.error
    assert manager._plugin_tool_names == {"gate_approve_plan"}, manager._plugin_tool_names
    assert set(manager._hooks) == {"pre_tool_call"}, manager._hooks
    assert manager._tool_execution_interceptors, manager._tool_execution_interceptors
'''
    env = os.environ.copy()
    env["PLUGIN_PATH"] = str(PLUGIN)
    env["PYTHONPATH"] = str(PATCHED_HERMES)
    result = subprocess.run(
        [str(PYTHON), "-c", script],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_plugin_loads_with_pinned_hermes_api_and_defaults_to_deny(tmp_path):
    head = subprocess.check_output(
        ["git", "-C", str(HERMES), "rev-parse", "HEAD"], text=True
    ).strip()
    assert head == PINNED_HEAD

    script = r'''
import os
from pathlib import Path
from hermes_cli.plugins import PluginManager, PluginContext
from hermes_cli.plugins_manifest import PluginManifest

for name in ("register_tool", "register_hook", "register_telegram_handler"):
    assert callable(getattr(PluginContext, name, None)), name

home = Path(os.environ["HERMES_HOME"])
manager = PluginManager(scope_key=str(home))
manifest = PluginManifest(
    name="engineering-gate", version="0.1.0", path=os.environ["PLUGIN_PATH"],
    source="project",
)
manager._load_plugin(manifest)
assert "engineering-gate" in manager._plugins
loaded = manager._plugins["engineering-gate"]
assert not loaded.error, loaded.error
assert set(manager._hooks) == {"pre_tool_call"}, manager._hooks
callback = manager._hooks["pre_tool_call"][0]
assert callback(tool_name="gate_approve_plan", args={"task_id": "t"}) is None
for tool_name in ("read_file", "write_file", "terminal", "execute_code", "delegate_task", "unknown_tool"):
    decision = callback(tool_name=tool_name, args={})
    assert isinstance(decision, dict) and decision.get("action") == "block", (tool_name, decision)
assert manager._plugin_tool_names == {"gate_approve_plan"}, manager._plugin_tool_names
assert set(manager._platform_handler_factories) == {"telegram"}, manager._platform_handler_factories
'''
    env = os.environ.copy()
    env["HERMES_HOME"] = str(tmp_path / "hermes-home")
    env["PLUGIN_PATH"] = str(PLUGIN)
    env["PYTHONPATH"] = str(HERMES) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [str(PYTHON), "-c", script], env=env, text=True, capture_output=True
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_manifest_declares_gate_runtime_dependencies():
    script = r'''
from pathlib import Path
from hermes_cli.plugin_python_deps import read_declaration

plugin_dir = Path("engineering-gate")
declaration = read_declaration(plugin_dir)
assert "cryptography>=46,<51" in declaration.specs, declaration.specs
assert "python-telegram-bot>=22.6,<23" in declaration.specs, declaration.specs
'''
    env = os.environ.copy()
    env["PYTHONPATH"] = str(HERMES) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [str(PYTHON), "-c", script],
        cwd=PLUGIN.parent,
        env=env,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
