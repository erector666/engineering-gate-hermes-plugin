import base64
import json
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engineering-gate"))
from adapters.hermes.approval_sidecar import ApprovalSidecar


def binding(**overrides):
    now = time.time()
    value = dict(
        profile_id="main", session_id="session-1", telegram_user_id=42,
        telegram_chat_id=42, task_id="task-1", plan_revision=3,
        plan_digest="a" * 64,
        workspace_identity={"canonical_path": "/work", "device": 1, "inode": 2},
        approval_request_id="request-1", approval_packet_digest="b" * 64,
        created_at=now, expires_at=now + 3600,
    )
    value.update(overrides)
    return value


def deliver(sidecar, nonce):
    return sidecar.mark_prompt_delivered(
        nonce, profile_id="main", prompt_message_id=99,
        plan_chunks_confirmed=True, buttons_sent=True,
    )


def consume(sidecar, nonce, scope=None, **overrides):
    scope = scope or binding()
    args = dict(actor_id=42, chat_id=42, chat_type="private",
                choice="approve_once", expected_context=scope)
    args.update(overrides)
    return sidecar.consume_callback(nonce, **args)


def test_create_persists_fully_bound_pending_record_and_nonce_is_32_random_bytes(tmp_path):
    sidecar = ApprovalSidecar(tmp_path / "profile-main")
    nonce = sidecar.create_pending(**binding())
    raw = base64.urlsafe_b64decode(nonce + "=" * (-len(nonce) % 4))
    assert len(raw) == 32
    reopened = ApprovalSidecar(tmp_path / "profile-main")
    record = reopened.get(nonce, profile_id="main")
    assert record["state"] == "pending"
    assert record["approval_packet_digest"] == binding()["approval_packet_digest"]
    assert "plan_display_digest" not in record
    assert record["workspace_identity"] == binding()["workspace_identity"]
    assert (tmp_path / "profile-main" / "engineering-gate-approvals.sqlite3").stat().st_mode & 0o777 == 0o600


def test_find_unique_approved_for_context_resolves_only_exact_live_identity(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    scope = binding()
    nonce = sidecar.create_pending(**scope)
    deliver(sidecar, nonce)
    consume(sidecar, nonce, scope)
    assert sidecar.find_unique_approved_for_context("main", "session-1", 42, 42) == sidecar.get(nonce, profile_id="main")
    assert sidecar.find_unique_approved_for_context("main", "other-session", 42, 42) is None


def test_workspace_identity_requires_exact_canonical_mapping(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    for invalid in (
        "dev:1:2:/work", {"canonical_path": "/work", "device": "1", "inode": 2},
        {"canonical_path": "/work", "device": True, "inode": 2},
        {"canonical_path": "/work", "device": -1, "inode": 2},
        {"canonical_path": "", "device": 1, "inode": 2},
        {"canonical_path": "/work", "device": 1, "inode": 2, "extra": 3},
    ):
        with pytest.raises(ValueError):
            sidecar.create_pending(**binding(workspace_identity=invalid))


def test_duplicate_active_scope_is_rejected_transactionally(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    sidecar.create_pending(**binding())
    with pytest.raises((ValueError, sqlite3.IntegrityError)):
        sidecar.create_pending(**binding())
    assert len(list_pending_records(tmp_path)) == 1


def list_pending_records(root):
    with sqlite3.connect(root / "engineering-gate-approvals.sqlite3") as conn:
        return conn.execute("SELECT nonce FROM approvals WHERE state='pending'").fetchall()


def test_two_instances_cannot_create_same_active_scope(tmp_path):
    sides = [ApprovalSidecar(tmp_path), ApprovalSidecar(tmp_path)]
    barrier = threading.Barrier(2)
    def create(side):
        barrier.wait()
        try:
            return side.create_pending(**binding())
        except (ValueError, sqlite3.IntegrityError):
            return None
    with __import__("concurrent.futures").futures.ThreadPoolExecutor(2) as pool:
        results = list(pool.map(create, sides))
    assert sum(item is not None for item in results) == 1
    assert len(list_pending_records(tmp_path)) == 1


def test_get_rejects_corrupt_json_and_row_data_state_disagreement(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    nonce = sidecar.create_pending(**binding())
    with sqlite3.connect(tmp_path / "engineering-gate-approvals.sqlite3") as conn:
        conn.execute("UPDATE approvals SET data='{' WHERE nonce=?", (nonce,))
    assert sidecar.get(nonce, profile_id="main") is None

    isolated = ApprovalSidecar(tmp_path / "second")
    nonce = isolated.create_pending(**binding(task_id="task-2"))
    with sqlite3.connect(tmp_path / "second" / "engineering-gate-approvals.sqlite3") as conn:
        data = json.loads(conn.execute("SELECT data FROM approvals WHERE nonce=?", (nonce,)).fetchone()[0])
        data["state"] = "approved"
        conn.execute("UPDATE approvals SET data=? WHERE nonce=?", (json.dumps(data), nonce))
    assert isolated.get(nonce, profile_id="main") is None


def test_get_rejects_legacy_or_incomplete_rows(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    nonce = sidecar.create_pending(**binding())
    with sqlite3.connect(tmp_path / "engineering-gate-approvals.sqlite3") as conn:
        data = json.loads(conn.execute("SELECT data FROM approvals WHERE nonce=?", (nonce,)).fetchone()[0])
        del data["plan_digest"]
        conn.execute("UPDATE approvals SET data=? WHERE nonce=?", (json.dumps(data), nonce))
    assert sidecar.get(nonce, profile_id="main") is None


def test_delivery_requires_complete_plan_and_buttons_and_exact_positive_id(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    for prompt_id in (0, -1, True, "99"):
        nonce = sidecar.create_pending(**binding(task_id=f"delivery-{prompt_id}"))
        assert not sidecar.mark_prompt_delivered(nonce, profile_id="main", prompt_message_id=prompt_id,
            plan_chunks_confirmed=True, buttons_sent=True)
    nonce = sidecar.create_pending(**binding())
    assert not sidecar.mark_prompt_delivered(nonce, profile_id="main", prompt_message_id=99,
        plan_chunks_confirmed=False, buttons_sent=True)
    assert not sidecar.mark_prompt_delivered(nonce, profile_id="main", prompt_message_id=99,
        plan_chunks_confirmed=True, buttons_sent=False)
    assert deliver(sidecar, nonce)
    assert sidecar.get(nonce, profile_id="main")["prompt_message_id"] == 99
    assert not deliver(sidecar, nonce)


def test_reopened_delivered_record_can_be_consumed_once_and_denial_is_distinct(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    scope = binding()
    nonce = sidecar.create_pending(**scope)
    assert deliver(sidecar, nonce)
    reopened = ApprovalSidecar(tmp_path)
    assert consume(reopened, nonce, scope) == (True, True)
    assert reopened.get(nonce, profile_id="main")["state"] == "approved"
    assert consume(reopened, nonce, scope) is False

    scope2 = binding(task_id="task-deny")
    denied_nonce = sidecar.create_pending(**scope2)
    deliver(sidecar, denied_nonce)
    assert consume(sidecar, denied_nonce, scope2, choice="deny") == (True, False)
    assert sidecar.get(denied_nonce, profile_id="main")["state"] == "denied"
    assert consume(sidecar, denied_nonce, scope2) is False


def test_callback_rejects_wrong_scope_actor_or_chat(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    scope = binding()
    nonce = sidecar.create_pending(**scope)
    deliver(sidecar, nonce)
    assert consume(sidecar, nonce, binding(task_id="other")) is False
    assert consume(sidecar, nonce, scope, actor_id=43) is False
    assert consume(sidecar, nonce, scope, chat_id=43) is False
    assert consume(sidecar, nonce, scope, chat_type="group") is False
    assert sidecar.get(nonce, profile_id="main")["state"] == "pending"


def test_expired_cancelled_and_terminal_requests_are_non_consumable(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    old = time.time() - 20
    expired_scope = binding(created_at=old, expires_at=old + 1)
    expired = sidecar.create_pending(**expired_scope)
    deliver(sidecar, expired)
    assert consume(sidecar, expired, expired_scope) is False
    assert sidecar.get(expired, profile_id="main")["state"] == "pending"

    cancelled_scope = binding(task_id="cancelled")
    cancelled = sidecar.create_pending(**cancelled_scope)
    deliver(sidecar, cancelled)
    sidecar.invalidate(cancelled, "main")
    assert consume(sidecar, cancelled, cancelled_scope) is False
    assert sidecar.get(cancelled, profile_id="main")["state"] == "cancelled"


def test_competing_instances_only_consume_once_after_restart(tmp_path):
    first = ApprovalSidecar(tmp_path)
    scope = binding()
    nonce = first.create_pending(**scope)
    deliver(first, nonce)
    instances = [ApprovalSidecar(tmp_path), ApprovalSidecar(tmp_path)]
    barrier = threading.Barrier(2)
    def use(side):
        barrier.wait()
        return consume(side, nonce, scope)
    with __import__("concurrent.futures").futures.ThreadPoolExecutor(2) as pool:
        results = list(pool.map(use, instances))
    assert results.count((True, True)) == 1
    assert results.count(False) == 1
    assert ApprovalSidecar(tmp_path).get(nonce, profile_id="main")["state"] == "approved"


def test_find_unique_approved_survives_callback_consumption_and_restart(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    scope = binding()
    nonce = sidecar.create_pending(**scope)
    assert deliver(sidecar, nonce)
    assert consume(sidecar, nonce, scope) == (True, True)

    reopened = ApprovalSidecar(tmp_path)
    record = reopened.find_unique_approved("main", "task-1", "request-1")
    assert record["nonce"] == nonce
    assert record["session_id"] == "session-1"
    assert record["state"] == "approved"
    assert record["delivered"] is True


def test_find_unique_approved_rejects_wrong_scope(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    scope = binding()
    nonce = sidecar.create_pending(**scope)
    assert deliver(sidecar, nonce)
    assert consume(sidecar, nonce, scope) == (True, True)

    assert sidecar.find_unique_approved("main", "other-task", "request-1") is None
    assert sidecar.find_unique_approved("main", "task-1", "other-request") is None
    assert sidecar.find_unique_approved("other-profile", "task-1", "request-1") is None


def test_find_unique_approved_rejects_non_approved_states(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    for state in ("pending", "denied", "cancelled"):
        scope = binding(task_id=f"task-{state}", approval_request_id=f"request-{state}")
        nonce = sidecar.create_pending(**scope)
        assert deliver(sidecar, nonce)
        if state == "denied":
            assert consume(sidecar, nonce, scope, choice="deny") == (True, False)
        elif state == "cancelled":
            sidecar.invalidate(nonce, "main")
        assert sidecar.find_unique_approved("main", scope["task_id"], scope["approval_request_id"]) is None


def test_find_unique_approved_fails_closed_on_ambiguous_records(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    scope = binding()
    nonce = sidecar.create_pending(**scope)
    assert deliver(sidecar, nonce)
    assert consume(sidecar, nonce, scope) == (True, True)
    with sqlite3.connect(tmp_path / "engineering-gate-approvals.sqlite3") as conn:
        data = json.loads(conn.execute("SELECT data FROM approvals WHERE nonce=?", (nonce,)).fetchone()[0])
        duplicate = "z" * 43
        data["nonce"] = duplicate
        conn.execute("INSERT INTO approvals VALUES (?, ?, 'approved')", (duplicate, json.dumps(data)))

    assert sidecar.find_unique_approved("main", "task-1", "request-1") is None


def test_find_unique_approved_fails_closed_on_corrupt_or_invalid_matching_rows(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    scope = binding()
    nonce = sidecar.create_pending(**scope)
    assert deliver(sidecar, nonce)
    assert consume(sidecar, nonce, scope) == (True, True)
    with sqlite3.connect(tmp_path / "engineering-gate-approvals.sqlite3") as conn:
        data = json.loads(conn.execute("SELECT data FROM approvals WHERE nonce=?", (nonce,)).fetchone()[0])
        data["task_id"] = "different-task"
        conn.execute("UPDATE approvals SET data=? WHERE nonce=?", (json.dumps(data), nonce))

    assert sidecar.find_unique_approved("main", "task-1", "request-1") is None


def test_find_unique_approved_fails_closed_on_corrupt_json(tmp_path):
    sidecar = ApprovalSidecar(tmp_path)
    scope = binding()
    nonce = sidecar.create_pending(**scope)
    assert deliver(sidecar, nonce)
    assert consume(sidecar, nonce, scope) == (True, True)
    with sqlite3.connect(tmp_path / "engineering-gate-approvals.sqlite3") as conn:
        conn.execute("UPDATE approvals SET data='{' WHERE nonce=?", (nonce,))

    assert sidecar.find_unique_approved("main", "task-1", "request-1") is None
