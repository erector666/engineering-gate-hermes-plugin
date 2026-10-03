import asyncio
import dataclasses
import hashlib
import json
import sys
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "engineering-gate"
sys.path.insert(0, str(PLUGIN))
from adapters.hermes.approval import canonical_approval_packet, GateApprovalService
from engineering_gate_core.models import (AcceptanceCriterion, ApprovalRequest, Evidence, InspectionEvidenceRef, NormalizedOperation, OperationKind, Plan, PlanReview, RequesterIdentity, ReviewVerdict)
from engineering_gate_core.state_store import StateStore
from engineering_gate_core.workflow import Event, capture_workspace_identity, new_task

PACKET_KEYS = {"task_id", "task_objective", "inspection_evidence", "analysis", "plan", "blast_radius", "plan_review", "plan_revision", "plan_digest", "workspace_identity", "approval_request_id", "profile_id"}


def make_approval_state(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    store = StateStore(tmp_path / "state.sqlite3")
    store.create(new_task("packet-task", "Objective A", RequesterIdentity("telegram:42")))
    store.transition("packet-task", Event.INSPECTION_RECORDED, InspectionEvidenceRef("inspect", "Evidence A"))
    store.transition("packet-task", Event.ANALYSIS_RECORDED, Evidence("analysis", "Analysis A"))
    plan = Plan("Objective A", (NormalizedOperation(OperationKind.WRITE, "out.txt", "why"),),
                (AcceptanceCriterion("c", "criterion", "verify"),), ("check",),
                workspace_root=str(workspace), workspace_identity=capture_workspace_identity(workspace))
    store.transition("packet-task", Event.PLAN_RECORDED, plan)
    store.transition("packet-task", Event.BLAST_RADIUS_RECORDED, Evidence("blast", "Blast A"))
    store.transition("packet-task", Event.PLAN_REVIEW_PASSED, PlanReview(ReviewVerdict.APPROVED, ("finding A",)))
    state = store.load("packet-task")
    store.transition("packet-task", Event.APPROVAL_REQUESTED,
                     ApprovalRequest(state.task_id, state.revision, state.plan_digest, "request-A"))
    return store.load("packet-task")


def bound_args(state, profile_id="profile-A"):
    body, digest = canonical_approval_packet(state, profile_id)
    identity = state.plan.workspace_identity
    args = dict(profile_id=profile_id, session_id="s", telegram_user_id=42,
        telegram_chat_id=42, task_id=state.task_id, plan_revision=state.revision,
        plan_payload=state.plan, plan_digest=state.plan_digest,
        workspace_identity={"canonical_path": identity.canonical_path, "device": identity.device, "inode": identity.inode},
        approval_request_id=state.approval_request.request_id, timeout_seconds=60,
        approval_state=state, approval_packet_body=body, approval_packet_digest=digest)
    return body, digest, args


def test_pending_rejects_malformed_packet_before_persisting(tmp_path):
    state = make_approval_state(tmp_path)
    body, digest, args = bound_args(state)
    packet = json.loads(body)
    invalid = ["plain text", "[]", json.dumps({k:v for k,v in packet.items() if k != "profile_id"}, sort_keys=True, separators=(",", ":")),
               json.dumps(dict(packet, extra=1), sort_keys=True, separators=(",", ":")), json.dumps(packet, ensure_ascii=False)]
    service = GateApprovalService(tmp_path, bot=object(), render_plan=str)
    for invalid_body in invalid:
        invalid_digest = hashlib.sha256(invalid_body.encode()).hexdigest()
        assert service.create_pending(**(args | {"approval_packet_body": invalid_body, "approval_packet_digest": invalid_digest}),
            plan_text=invalid_body + "\n\nApproval packet digest: " + invalid_digest) is None
    assert service.create_pending(**(args | {"approval_packet_digest": "A" * 64}),
        plan_text=body + "\n\nApproval packet digest: " + "A" * 64) is None
    assert not (tmp_path / "engineering-gate-approvals.sqlite3").exists()


def test_request_rejects_malformed_packet_before_send_or_sidecar_creation(tmp_path):
    class Bot:
        calls = 0
        async def send_message(self, **kwargs):
            self.calls += 1
            raise AssertionError("malformed approval packet must not be sent")
    state = make_approval_state(tmp_path)
    body, digest, args = bound_args(state)
    packet = json.loads(body)
    missing = json.dumps({k:v for k,v in packet.items() if k != "profile_id"}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    extra = json.dumps(dict(packet, extra=True), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    noncanonical = json.dumps(packet, ensure_ascii=False)
    malformed = [("plain text", digest), ("[]", hashlib.sha256(b"[]").hexdigest()),
        (missing, hashlib.sha256(missing.encode()).hexdigest()), (extra, hashlib.sha256(extra.encode()).hexdigest()),
        (noncanonical, hashlib.sha256(noncanonical.encode()).hexdigest()), (body, "A" * 64), (body, "a" * 63)]
    bot = Bot()
    service = GateApprovalService(tmp_path, bot=bot, render_plan=str)
    for packet_body, packet_digest in malformed:
        assert asyncio.run(service.request(**(args | {"approval_packet_body": packet_body, "approval_packet_digest": packet_digest}))) is False
        assert bot.calls == 0
        assert not (tmp_path / "engineering-gate-approvals.sqlite3").exists()


MISMATCHES = ["profile_id", "task_id", "revision", "plan payload", "plan digest", "workspace identity", "approval request ID", "outside-plan state"]


def mismatched_args(state, mismatch):
    body, digest, args = bound_args(state)
    if mismatch == "profile_id": args["profile_id"] = "profile-B"
    elif mismatch == "task_id": args["task_id"] = "other-task"
    elif mismatch == "revision": args["plan_revision"] += 1
    elif mismatch == "plan payload": args["plan_payload"] = dataclasses.replace(state.plan, exclusions=("changed",))
    elif mismatch == "plan digest": args["plan_digest"] = "0" * 64
    elif mismatch == "workspace identity": args["workspace_identity"] = dict(args["workspace_identity"], inode=args["workspace_identity"]["inode"] + 1)
    elif mismatch == "approval request ID": args["approval_request_id"] = "request-B"
    elif mismatch == "outside-plan state": args["approval_state"] = dataclasses.replace(state, analysis=Evidence("analysis", "Analysis B"))
    return body, digest, args


@pytest.mark.parametrize("mismatch", MISMATCHES)
def test_request_rejects_state_packet_binding_mismatch(tmp_path, mismatch):
    state = make_approval_state(tmp_path)
    _, _, args = mismatched_args(state, mismatch)
    class Bot:
        calls = 0
        async def send_message(self, **kwargs): self.calls += 1
    bot = Bot()
    service = GateApprovalService(tmp_path, bot=bot, render_plan=str)
    assert asyncio.run(service.request(**args)) is False
    assert bot.calls == 0
    assert not (tmp_path / "engineering-gate-approvals.sqlite3").exists()


@pytest.mark.parametrize("mismatch", MISMATCHES)
def test_create_pending_rejects_state_packet_binding_mismatch(tmp_path, mismatch):
    state = make_approval_state(tmp_path)
    body, digest, args = mismatched_args(state, mismatch)
    service = GateApprovalService(tmp_path, bot=object(), render_plan=str)
    assert service.create_pending(**args, plan_text=body + "\n\nApproval packet digest: " + digest) is None
    assert not (tmp_path / "engineering-gate-approvals.sqlite3").exists()


def test_valid_canonical_state_packet_is_accepted(tmp_path):
    state = make_approval_state(tmp_path)
    body, digest, args = bound_args(state)
    service = GateApprovalService(tmp_path, bot=object(), render_plan=str)
    assert service.create_pending(**args, plan_text=body + "\n\nApproval packet digest: " + digest) is not None


def test_canonical_packet_is_stable_and_binds_each_approval_field(tmp_path):
    state = make_approval_state(tmp_path)
    body, digest = canonical_approval_packet(state, "profile-A")
    assert canonical_approval_packet(state, "profile-A") == (body, digest)
    assert digest == hashlib.sha256(body.encode()).hexdigest()
    packet = json.loads(body)
    assert set(packet) == PACKET_KEYS
    assert packet["task_id"] == state.task_id
    mutations = {
      "objective": lambda s: dataclasses.replace(s, task=dataclasses.replace(s.task, objective="Objective B")),
      "inspection evidence": lambda s: dataclasses.replace(s, inspection=InspectionEvidenceRef("inspect", "Evidence B")),
      "analysis": lambda s: dataclasses.replace(s, analysis=Evidence("analysis", "Analysis B")),
      "plan": lambda s: dataclasses.replace(s, plan=dataclasses.replace(s.plan, exclusions=("changed",))),
      "blast radius": lambda s: dataclasses.replace(s, blast_radius=Evidence("blast", "Blast B")),
      "plan-review findings": lambda s: dataclasses.replace(s, plan_review=PlanReview(ReviewVerdict.APPROVED, ("finding B",))),
      "plan-review verdict": lambda s: dataclasses.replace(s, plan_review=PlanReview(ReviewVerdict.NEEDS_CHANGES, ("finding A",))),
      "plan revision": lambda s: dataclasses.replace(s, revision=s.revision + 1),
      "plan digest": lambda s: dataclasses.replace(s, plan_digest="0" * 64),
      "workspace identity": lambda s: dataclasses.replace(s, plan=dataclasses.replace(s.plan, workspace_identity=dataclasses.replace(s.plan.workspace_identity, inode=s.plan.workspace_identity.inode + 1))),
      "approval request ID": lambda s: dataclasses.replace(s, approval_request=dataclasses.replace(s.approval_request, request_id="request-B")),
    }
    for field, mutate in mutations.items(): assert canonical_approval_packet(mutate(state), "profile-A")[1] != digest, field
    assert canonical_approval_packet(state, "profile-B")[1] != digest


def test_pending_requires_exact_approval_packet_suffix(tmp_path):
    state = make_approval_state(tmp_path)
    body, digest, args = bound_args(state)
    service = GateApprovalService(tmp_path, bot=object(), render_plan=str)
    correct = body + "\n\nApproval packet digest: " + digest
    assert service.create_pending(**args, plan_text=correct) is not None
    assert service.create_pending(**args, plan_text=body + "\n\nCanonical plan digest: " + digest) is None
    assert service.create_pending(**args, plan_text=correct + " trailing") is None
