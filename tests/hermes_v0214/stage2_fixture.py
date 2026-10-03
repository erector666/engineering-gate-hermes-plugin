"""Reusable test-only approved Gate task and delivered Telegram approval fixture."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from adapters.hermes.approval_sidecar import ApprovalSidecar
from engineering_gate_core.models import (
    AcceptanceCriterion, ApprovalReceipt, ApprovalRequest, Evidence,
    InspectionEvidenceRef, NormalizedOperation, OperationKind, Plan,
    PlanReview, RequesterIdentity, ReviewVerdict, VerificationCommand,
)
from engineering_gate_core.state_store import StateStore
from engineering_gate_core.workflow import Event, capture_workspace_identity, new_task


@dataclass(frozen=True)
class ApprovedFixture:
    store: StateStore
    task_id: str
    plan: Plan
    request: ApprovalRequest
    sidecar: ApprovalSidecar
    approval_record: dict
    workspace: Path
    profile_id: str
    session_id: str
    prompt_message_id: int
    reviewer_authorized: bool = False


def seed_approved_fixture(
    base: Path,
    workspace: Path,
    *,
    target: str = "B",
    profile_id: str = "default",
    session_id: str = "fixture-session",
    task_id: str = "stage2-fixture-task",
    user_id: int = 42,
    chat_id: int | None = None,
) -> ApprovedFixture:
    """Persist an approved one-WRITE task and its delivered approve_once sidecar."""
    base = Path(base).resolve()
    workspace = Path(workspace).resolve(strict=True)
    chat_id = user_id if chat_id is None else chat_id
    if type(user_id) is not int or user_id <= 0 or type(chat_id) is not int or chat_id != user_id:
        raise ValueError("fixture requires a positive private-DM numeric identity")
    prompt_message_id = 9001
    store = StateStore(base / "engineering-gate-state.sqlite3")
    store.create(new_task(task_id, "Write and verify a fixture artifact", RequesterIdentity(f"telegram:{user_id}")))
    store.transition(task_id, Event.INSPECTION_RECORDED, InspectionEvidenceRef("fixture-inspection", "Disposable fixture workspace"))
    store.transition(task_id, Event.ANALYSIS_RECORDED, Evidence("fixture-analysis", "Single approved write"))
    plan = Plan(
        "Write a fixture artifact", (NormalizedOperation(OperationKind.WRITE, target, "Stage-2 fixture target"),),
        (AcceptanceCriterion("artifact-check", "Python check succeeds", "Run the persisted Python verification command"),),
        ("Run the persisted safe Python check",), workspace_root=str(workspace),
        workspace_identity=capture_workspace_identity(str(workspace)),
        verification_commands=(VerificationCommand(
            (sys.executable, "-c", f"from pathlib import Path; assert Path({target!r}).exists()"),
            ("artifact-check",), 10, 4096),),
    )
    store.transition(task_id, Event.PLAN_RECORDED, plan)
    store.transition(task_id, Event.BLAST_RADIUS_RECORDED, Evidence("fixture-blast", "One target only"))
    store.transition(task_id, Event.PLAN_REVIEW_PASSED, PlanReview(ReviewVerdict.APPROVED))
    current = store.load(task_id)
    request = ApprovalRequest(current.task_id, current.revision, current.plan_digest, "stage2-fixture-request")
    store.transition(task_id, Event.APPROVAL_REQUESTED, request)
    current = store.load(task_id)
    identity = current.plan.workspace_identity
    workspace_binding = {"canonical_path": identity.canonical_path, "device": identity.device, "inode": identity.inode}
    now = time.time()
    rendered = json.dumps(asdict(current.plan), sort_keys=True, separators=(",", ":"))
    displayed_plan = f"{rendered}\n\nCanonical plan digest: {current.plan_digest}"
    binding = dict(
        profile_id=profile_id, session_id=session_id, telegram_user_id=user_id, telegram_chat_id=chat_id,
        task_id=task_id, plan_revision=current.revision, plan_digest=str(current.plan_digest),
        workspace_identity=workspace_binding, approval_request_id=request.request_id,
        plan_display_digest=hashlib.sha256(displayed_plan.encode("utf-8")).hexdigest(),
        created_at=now, expires_at=now + 3600,
    )
    sidecar = ApprovalSidecar(base)
    nonce = sidecar.create_pending(**binding)
    if not sidecar.mark_prompt_delivered(nonce, profile_id=profile_id, prompt_message_id=prompt_message_id,
                                         plan_chunks_confirmed=True, buttons_sent=True):
        raise RuntimeError("fixture sidecar prompt delivery could not be recorded")
    if sidecar.consume_callback(nonce, actor_id=user_id, chat_id=chat_id, chat_type="private",
                               choice="approve_once", expected_context=binding) != (True, True):
        raise RuntimeError("fixture approval callback could not be consumed")
    receipt = ApprovalReceipt(request.request_id, current.task_id, current.revision,
                              current.plan_digest, current.task.requester, True)
    store.record_approval(task_id, receipt)
    record = sidecar.find_unique_approved(profile_id, task_id, request.request_id)
    if record is None:
        raise RuntimeError("fixture did not persist a unique delivered approval")
    return ApprovedFixture(store, task_id, current.plan, request, sidecar, record, workspace,
                           profile_id, session_id, prompt_message_id)
