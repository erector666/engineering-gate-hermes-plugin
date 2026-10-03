from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from stage2_fixture import seed_approved_fixture


def test_seed_approved_fixture_persists_exact_receipt_and_delivered_sidecar(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fixture = seed_approved_fixture(tmp_path, workspace)

    current = fixture.store.load(fixture.task_id)
    assert current.state.value == "approved"
    assert current.approval is not None and current.approval.approved is True
    assert current.approval.request_id == fixture.request.request_id
    assert current.approval.task_id == current.task_id
    assert current.approval.revision == current.revision
    assert current.approval.digest == current.plan_digest
    assert current.approval.requester == current.task.requester
    assert current.task.requester.subject == "telegram:42"
    assert len(current.plan.operations) == 1
    assert current.plan.operations[0].kind.value == "write"
    assert current.plan.operations[0].target == "B"
    assert current.plan.verification_commands

    record = fixture.sidecar.find_unique_approved(
        fixture.profile_id, fixture.task_id, fixture.request.request_id
    )
    assert record is not None
    expected = {
        "profile_id": fixture.profile_id,
        "session_id": fixture.session_id,
        "telegram_user_id": 42,
        "telegram_chat_id": 42,
        "task_id": fixture.task_id,
        "plan_revision": current.revision,
        "plan_digest": current.plan_digest,
        "workspace_identity": {"canonical_path": current.plan.workspace_identity.canonical_path,
                              "device": current.plan.workspace_identity.device,
                              "inode": current.plan.workspace_identity.inode},
        "approval_request_id": fixture.request.request_id,
        "delivered": True,
        "prompt_message_id": fixture.prompt_message_id,
    }
    assert {key: record.get(key) for key in expected} == expected
    assert record["state"] == "approved"
    rendered = json.dumps(asdict(current.plan), sort_keys=True, separators=(",", ":"))
    display = f"{rendered}\n\nCanonical plan digest: {current.plan_digest}"
    assert record["plan_display_digest"] == hashlib.sha256(display.encode("utf-8")).hexdigest()
    assert fixture.workspace == workspace.resolve()
    assert fixture.store.path == tmp_path.resolve() / "engineering-gate-state.sqlite3"
    assert fixture.sidecar.profile_home == tmp_path.resolve()
    assert (tmp_path.resolve() / "engineering-gate-approvals.sqlite3").is_file()
    assert fixture.reviewer_authorized is False


def test_fixture_binds_exact_profile_and_host_session(tmp_path):
    profile_home = tmp_path / "profiles" / "research"
    profile_home.mkdir(parents=True, mode=0o700)
    workspace = profile_home / "workspace"
    workspace.mkdir()
    fixture = seed_approved_fixture(
        profile_home, workspace, profile_id="research", session_id="host-session-123",
        user_id=71, chat_id=71,
    )
    assert fixture.profile_id == "research"
    assert fixture.session_id == "host-session-123"
    assert fixture.approval_record["telegram_user_id"] == 71
    assert fixture.approval_record["telegram_chat_id"] == 71
    assert fixture.sidecar.find_unique_approved(
        "research", fixture.task_id, fixture.request.request_id
    )["session_id"] == "host-session-123"
    assert fixture.store.path == profile_home / "engineering-gate-state.sqlite3"
    assert fixture.sidecar.profile_home == profile_home.resolve()
