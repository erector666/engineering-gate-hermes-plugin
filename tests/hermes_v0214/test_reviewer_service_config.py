"""Offline construction tests for the active-profile reviewer identity binding."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from adapters.hermes import _build_reviewer_client


def fake_context(setting):
    class Context:
        def __init__(self):
            self._manager = SimpleNamespace(home_path=None)
        def get_config(self, key, default=None):
            assert key == "reviewer_provider"
            return setting
    return Context()


def write_sidecar(home, content):
    (home / "engineering-gate-reviewer-service.json").write_text(content, encoding="utf-8")


def test_client_uses_active_config_identity_not_transport_sidecar(tmp_path):
    write_sidecar(tmp_path, json.dumps({"socket_path":"/fake/reviewer.sock", "key_id":"test-key", "timeout_seconds":75}))
    client = _build_reviewer_client(fake_context("anthropic:claude-reviewer"), tmp_path)
    assert client is not None
    assert client.reviewer_provider == "anthropic:claude-reviewer"
    assert client.reviewer_id == "engineering-gate-reviewer-v1"


def test_sidecar_cannot_inject_reviewer_provider(tmp_path):
    write_sidecar(tmp_path, json.dumps({"socket_path":"/fake/reviewer.sock", "key_id":"test-key", "timeout_seconds":75,
                                        "reviewer_provider":"evil:identity"}))
    assert _build_reviewer_client(fake_context("anthropic:claude-reviewer"), tmp_path) is None


def test_duplicate_sidecar_fields_fail_closed(tmp_path):
    write_sidecar(tmp_path, '{"socket_path":"/fake/a","socket_path":"/fake/b","key_id":"k","timeout_seconds":75}')
    assert _build_reviewer_client(fake_context("anthropic:claude-reviewer"), tmp_path) is None


def test_absent_or_malformed_active_identity_fails_closed(tmp_path):
    write_sidecar(tmp_path, json.dumps({"socket_path":"/fake/reviewer.sock", "key_id":"test-key", "timeout_seconds":75}))
    for setting in (None, "", "no-colon", ":model", "provider:", "a:b:c", 42):
        assert _build_reviewer_client(fake_context(setting), tmp_path) is None


def test_malformed_or_duplicate_sidecar_fails_closed(tmp_path):
    for text in ('{not-json', '{"socket_path":"/a","key_id":"k","key_id":"other","timeout_seconds":75}'):
        write_sidecar(tmp_path, text)
        assert _build_reviewer_client(fake_context("anthropic:claude-reviewer"), tmp_path) is None
