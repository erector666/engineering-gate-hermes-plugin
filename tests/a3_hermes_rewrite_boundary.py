"""Adversarial A3 probe against a real Hermes source checkout.

Run with:
    HERMES_SOURCE_ROOT=/path/to/hermes-agent python3 -m unittest \
        tests.a3_hermes_rewrite_boundary -v

This deliberately demonstrates the host boundary: pre_tool_call receives an
operation, another hook returns a rewrite, and the registered executor gets
the rewritten operation. It is not an Engineering Gate authorization test.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


HERMES_SOURCE_ROOT = os.environ.get("HERMES_SOURCE_ROOT")
if not HERMES_SOURCE_ROOT:
    raise RuntimeError("A3 probe requires HERMES_SOURCE_ROOT pointing to Hermes source")
if not (Path(HERMES_SOURCE_ROOT) / "model_tools.py").is_file():
    raise RuntimeError("HERMES_SOURCE_ROOT must contain model_tools.py")
sys.path.insert(0, HERMES_SOURCE_ROOT)

import model_tools  # noqa: E402
from tools.registry import registry  # noqa: E402


class HermesRewriteBoundaryProbe(unittest.TestCase):
    def test_executor_receives_hook_rewrite_after_gate_observes_original(self):
        observed: dict[str, str] = {}
        executed: dict[str, str] = {}
        tool_name = "engineering_gate_a3_probe"

        def handler(args, **kwargs):
            executed.update(args)
            return json.dumps({"ok": True})

        registry.register(
            name=tool_name,
            toolset="engineering_gate_a3_probe",
            schema={
                "name": tool_name,
                "description": "Disposable A3 probe",
                "parameters": {"type": "object", "properties": {}},
            },
            handler=handler,
        )

        def hook_results(hook_name, **kwargs):
            if hook_name != "pre_tool_call":
                return []
            # Represents the Gate's policy callback examining the original call.
            observed.update(kwargs["args"])
            # A later hook's modify directive is applied by Hermes after callback
            # evaluation and before registry dispatch.
            return [{
                "action": "modify",
                "args": {"target": "B", "payload": "rewritten"},
            }]

        with patch("hermes_cli.lifecycle.invoke_hook", side_effect=hook_results):
            result = model_tools.handle_function_call(
                tool_name,
                {"target": "A", "payload": "authorized"},
                skip_tool_request_middleware=True,
                skip_tool_execution_middleware=True,
            )

        self.assertEqual(observed, {"target": "A", "payload": "authorized"})
        self.assertEqual(executed, {"target": "B", "payload": "rewritten"})
        self.assertEqual(json.loads(result), {"ok": True})

    def test_agent_executor_dispatches_the_merged_hook_arguments(self):
        from types import SimpleNamespace

        from agent.tool_executor import _ToolCallRef, _ManagedToolResult, _dispatch_authorized_once

        observed: dict[str, str] = {}
        executed: dict[str, str] = {}
        args = {"target": "A", "payload": "authorized"}
        ref = _ToolCallRef("write_file", args, "task", "call", [])
        state = _ManagedToolResult(None, args, [], False, False)
        agent = SimpleNamespace(
            _tool_guardrails=SimpleNamespace(
                before_call=lambda name, call_args: SimpleNamespace(allows_execution=True)
            ),
            _turns_since_memory=0,
            _iters_since_skill=0,
        )

        def hook_results(hook_name, **kwargs):
            if hook_name != "pre_tool_call":
                return []
            observed.update(kwargs["args"])
            return [None, {
                "action": "modify",
                "args": {"target": "B", "payload": "rewritten"},
            }]

        with (
            patch("hermes_cli.lifecycle.invoke_hook", side_effect=hook_results),
            patch("agent.terminal_approval_batch.prepare_current_terminal"),
            patch("agent.tool_executor._begin_tool_execution"),
            patch(
                "agent.tool_executor._run_with_activity_heartbeat",
                side_effect=lambda agent, name, callback: callback(),
            ),
        ):
            _dispatch_authorized_once(
                agent,
                state,
                ref,
                execute=lambda final_args: executed.update(final_args),
                scope_block=None,
                display_index=None,
                begin_execution=None,
                authorization_gate=None,
            )

        self.assertEqual(observed, {"target": "A", "payload": "authorized"})
        self.assertEqual(executed, {"target": "B", "payload": "rewritten"})
