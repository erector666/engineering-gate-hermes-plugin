"""Pure task lifecycle state machine."""
from dataclasses import replace
from enum import Enum
import hashlib
import json
from datetime import datetime, timezone
import os
import stat
from pathlib import Path

from .models import (ApprovalReceipt, ApprovalRequest, Evidence, ExecutionPermit, Handoff, MutationAuthorization, MutationProposal,
                    InspectionEvidenceRef, Plan, PlanDigest, PlanReview, PlanRevision, RequesterIdentity,
                    ResultReview, ReviewVerdict, Task, TaskID, TaskState, TaskStateRecord, OperationKind,
                    EvidenceProvenance, ObservedCommandEvidence, VerificationCommand, VerificationResult, WorkspaceIdentity)

Stage = TaskState


def canonical_plan_digest(plan: Plan) -> PlanDigest:
    payload = {
        "objective": plan.objective,
        "workspace_root": plan.workspace_root,
        "workspace_identity": None if plan.workspace_identity is None else {
            "canonical_path": plan.workspace_identity.canonical_path,
            "device": plan.workspace_identity.device,
            "inode": plan.workspace_identity.inode,
        },
        "operations": [{"kind": op.kind.value, "target": op.target, "rationale": op.rationale} for op in plan.operations],
        "acceptance_criteria": [{"criterion_id": c.criterion_id, "description": c.description,
                                 "verification_procedure": c.verification_procedure} for c in plan.acceptance_criteria],
        "verification": list(plan.verification), "exclusions": list(plan.exclusions),
        "verification_commands": [{"argv": list(command.argv), "criterion_ids": list(command.criterion_ids),
                                   "timeout_seconds": command.timeout_seconds,
                                   "output_cap_bytes": command.output_cap_bytes}
                                  for command in plan.verification_commands],
    }
    return PlanDigest(hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest())


def resolve_approved_verification_commands(plan: Plan, criterion_ids: tuple[str, ...]) -> tuple[VerificationCommand, ...]:
    """Resolve argv entries from the supplied approved Plan, never from prose."""
    if type(plan) is not Plan or type(criterion_ids) is not tuple or not criterion_ids:
        raise TransitionError("a plan and nonempty criterion ID tuple are required")
    criteria = {criterion.criterion_id for criterion in plan.acceptance_criteria}
    if any(type(cid) is not str or cid not in criteria for cid in criterion_ids):
        raise TransitionError("criterion IDs are not present in the current plan")
    selected = tuple(command for command in plan.verification_commands
                      if set(command.criterion_ids).intersection(criterion_ids))
    if not selected or any(not set(command.criterion_ids).issubset(criteria) for command in selected):
        raise TransitionError("no valid approved verification command for current criteria")
    return selected


def mutation_argument_digest(content: str) -> str:
    if type(content) is not str:
        raise ValueError("WRITE content must be a string")
    payload = json.dumps({"content": content}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_mutation_proposal_digest(proposal: MutationProposal) -> str:
    payload = {"schema": "engineering-gate.mutation-proposal", "version": 1,
               "proposal_id": proposal.proposal_id, "task_id": str(proposal.task_id),
               "revision": int(proposal.revision), "plan_digest": str(proposal.plan_digest),
               "operation": {"kind": proposal.operation.kind.value, "target": proposal.operation.target,
                             "rationale": proposal.operation.rationale},
               "argument_digest": proposal.argument_digest, "rationale": proposal.rationale,
               "diff_digest": proposal.diff_digest}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def _parse_canonical_utc(value: str) -> datetime:
    if type(value) is not str:
        raise ValueError("timestamp must be canonical UTC ISO-8601")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("malformed timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed) or not value.endswith("Z") or parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        raise ValueError("timestamp must be canonical UTC ISO-8601")
    return parsed


def record_mutation_proposal(state: TaskStateRecord, proposal: MutationProposal) -> TaskStateRecord:
    if type(proposal) is not MutationProposal or state.state is not TaskState.IMPLEMENTING:
        raise TransitionError("mutation proposal requires IMPLEMENTING state and typed proposal")
    plan_digest = canonical_plan_digest(state.plan) if state.plan is not None else None
    receipt, request, permit = state.approval, state.approval_request, state.permit
    if (state.plan is None or state.plan_digest != plan_digest or state.plan.workspace_identity is None
            or state.plan_review is None or state.plan_review.verdict is not ReviewVerdict.APPROVED
            or request is None or receipt is None or not receipt.approved
            or (receipt.request_id, receipt.task_id, receipt.revision, receipt.digest, receipt.requester) !=
               (request.request_id, request.task_id, request.revision, request.digest, state.task.requester)
            or (request.task_id, request.revision, request.digest) != (state.task_id, state.revision, plan_digest)
            or permit is None or permit.task_id != state.task_id or permit.revision != state.revision
            or permit.digest != plan_digest or proposal.operation not in permit.scope.operations):
        raise TransitionError("mutation proposal requires current plan review, approval, and scoped permit")
    if (proposal.task_id != state.task_id or proposal.revision != state.revision
            or proposal.plan_digest != plan_digest or proposal.operation not in state.plan.operations
            or proposal.operation.kind is not OperationKind.WRITE):
        raise TransitionError("mutation proposal does not match current approved plan")
    previous = state.mutation_proposal
    same = previous is not None and canonical_mutation_proposal_digest(previous) == canonical_mutation_proposal_digest(proposal)
    return replace(state, mutation_proposal=proposal,
                   mutation_authorization=state.mutation_authorization if same else None)


def record_mutation_authorization(state: TaskStateRecord, authorization: MutationAuthorization, *, now=None) -> TaskStateRecord:
    """Compatibility shim that cannot grant authority from caller-built data."""
    raise TransitionError("caller-constructed MutationAuthorization is not write authority")


def capture_workspace_identity(path: str) -> WorkspaceIdentity:
    if os.name != "posix":
        raise TransitionError("stable workspace identity is unavailable on this platform")
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.resolve(strict=True) != candidate:
        raise TransitionError("workspace root must be canonical and absolute")
    info = candidate.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or type(info.st_dev) is not int or type(info.st_ino) is not int):
        raise TransitionError("workspace root has no stable directory identity")
    return WorkspaceIdentity(str(candidate), info.st_dev, info.st_ino)


def _bind_workspace(plan: Plan) -> Plan:
    if plan.workspace_root:
        return replace(plan, workspace_identity=capture_workspace_identity(plan.workspace_root))
    return replace(plan, workspace_identity=None)


class Event(str, Enum):
    INSPECTION_RECORDED = "inspection_recorded"
    ANALYSIS_RECORDED = "analysis_recorded"
    PLAN_RECORDED = "plan_recorded"
    BLAST_RADIUS_RECORDED = "blast_radius_recorded"
    PLAN_REVIEW_PASSED = "plan_review_passed"
    PLAN_REVIEW_FAILED = "plan_review_failed"
    APPROVAL_REQUESTED = "approval_requested"
    IMPLEMENTATION_STARTED = "implementation_started"
    VERIFICATION_RECORDED = "verification_recorded"
    RESULT_REVIEW_PASSED = "result_review_passed"
    IMPLEMENTATION_FIX_REQUIRED = "implementation_fix_required"
    REPLAN_REQUIRED = "replan_required"
    HANDOFF_RECORDED = "handoff_recorded"
    CANCEL = "cancel"
    REJECT = "reject"
    FAIL = "fail"


class TransitionError(ValueError):
    """Raised when a transition is illegal or lacks its required artifact."""


def new_task(task_id: str | TaskID, objective: str, requester: RequesterIdentity) -> TaskStateRecord:
    if not str(task_id).strip() or not objective.strip() or not requester.subject.strip():
        raise ValueError("task ID, objective, and requester are required")
    task = Task(TaskID(str(task_id)), objective, requester)
    return TaskStateRecord(task, TaskState.INSPECT, PlanRevision(0),
                           (TaskState.INTAKE, TaskState.INSPECT))


def revise_plan(task: TaskStateRecord, plan: Plan) -> TaskStateRecord:
    if task.state is not TaskState.PLAN or not isinstance(plan, Plan) or task.plan is None:
        raise TransitionError("plan edit is only legal in PLAN when an existing plan is present")
    plan = _bind_workspace(plan)
    return replace(task, plan=plan, plan_digest=canonical_plan_digest(plan), revision=PlanRevision(int(task.revision) + 1),
                   plan_review=None, approval_request=None, approval=None, permit=None,
                   mutation_proposal=None, mutation_authorization=None,
                   blast_radius=None, result_review=None, handoff=None,
                   history=task.history + (TaskState.PLAN,))


def transition(task: TaskStateRecord, event: Event, artifact: object | None = None) -> TaskStateRecord:
    state = task.state
    if event in (Event.CANCEL, Event.REJECT, Event.FAIL):
        if state in (TaskState.COMPLETED, TaskState.CANCELLED, TaskState.REJECTED, TaskState.FAILED):
            raise TransitionError("task is already terminal")
        target = {Event.CANCEL: TaskState.CANCELLED, Event.REJECT: TaskState.REJECTED,
                  Event.FAIL: TaskState.FAILED}[event]
        return _move(task, target)
    rules = {
        (TaskState.INSPECT, Event.INSPECTION_RECORDED): (TaskState.ANALYZE, InspectionEvidenceRef, "inspection"),
        (TaskState.ANALYZE, Event.ANALYSIS_RECORDED): (TaskState.PLAN, Evidence, "analysis"),
        (TaskState.PLAN, Event.PLAN_RECORDED): (TaskState.BLAST_RADIUS, Plan, "plan"),
        (TaskState.BLAST_RADIUS, Event.BLAST_RADIUS_RECORDED): (TaskState.PLAN_REVIEW, Evidence, "blast_radius"),
        (TaskState.PLAN_REVIEW, Event.PLAN_REVIEW_PASSED): (TaskState.AWAITING_APPROVAL, PlanReview, "plan_review"),
        (TaskState.PLAN_REVIEW, Event.PLAN_REVIEW_FAILED): (TaskState.PLAN, PlanReview, "plan_review"),
        (TaskState.AWAITING_APPROVAL, Event.APPROVAL_REQUESTED): (TaskState.AWAITING_APPROVAL, ApprovalRequest, "approval_request"),
        (TaskState.APPROVED, Event.IMPLEMENTATION_STARTED): (TaskState.IMPLEMENTING, ExecutionPermit, "permit"),
        (TaskState.IMPLEMENTING, Event.VERIFICATION_RECORDED): (TaskState.VERIFYING, tuple, "verification"),
        (TaskState.VERIFYING, Event.RESULT_REVIEW_PASSED): (TaskState.HANDOFF, ResultReview, "result_review"),
        (TaskState.VERIFYING, Event.IMPLEMENTATION_FIX_REQUIRED): (TaskState.IMPLEMENTING, ResultReview, "result_review"),
        (TaskState.VERIFYING, Event.REPLAN_REQUIRED): (TaskState.PLAN, ResultReview, "result_review"),
        (TaskState.HANDOFF, Event.HANDOFF_RECORDED): (TaskState.COMPLETED, Handoff, "handoff"),
    }
    if (state, event) not in rules:
        raise TransitionError(f"event {event.value} is not legal from {state.value}")
    next_state, artifact_type, field_name = rules[state, event]
    if not isinstance(artifact, artifact_type):
        raise TransitionError(f"{event.value} requires {artifact_type.__name__} evidence")
    if field_name == "inspection" and not artifact.evidence_id.strip():
        raise TransitionError("inspection reference must have an evidence ID")
    if field_name == "plan" and (
        task.inspection is None
        or not task.inspection.evidence_id.strip()
        or not task.inspection.description.strip()
    ):
        raise TransitionError("plan requires a nonempty inspection evidence reference")
    if field_name == "plan" and not (artifact.operations and artifact.acceptance_criteria and artifact.verification):
        raise TransitionError("plan requires operations, acceptance criteria, and verification")
    if field_name == "plan":
        artifact = _bind_workspace(artifact)
        if task.plan is not None:
            raise TransitionError("an existing plan must be edited with revise_plan")
        updated_revision = PlanRevision(int(task.revision) + 1)
    else:
        updated_revision = task.revision
    if field_name == "plan_review" and event is Event.PLAN_REVIEW_PASSED and artifact.verdict is not ReviewVerdict.APPROVED:
        raise TransitionError("passing plan review requires APPROVED verdict")
    if field_name == "plan_review" and event is Event.PLAN_REVIEW_FAILED and artifact.verdict is ReviewVerdict.APPROVED:
        raise TransitionError("failed plan review cannot carry APPROVED verdict")
    if field_name == "approval_request" and (artifact.task_id != task.task_id or artifact.revision != task.revision or artifact.digest != task.plan_digest):
        raise TransitionError("approval request is stale or belongs to another task")
    if field_name == "permit":
        approved_ops = set(task.plan.operations if task.plan else ())
        if artifact.task_id != task.task_id or artifact.revision != task.revision or artifact.digest != task.plan_digest or task.approval is None or artifact.digest != task.approval.digest or not set(artifact.scope.operations).issubset(approved_ops):
            raise TransitionError("implementation permit must match the currently approved task revision")
    if field_name == "verification":
        raise TransitionError("verification can only be recorded by GateVerificationRunner")
    if field_name == "plan_review" and event is Event.PLAN_REVIEW_PASSED and artifact.verdict is not ReviewVerdict.APPROVED:
        raise TransitionError("passing plan review requires APPROVED verdict")
    if field_name == "plan_review" and event is Event.PLAN_REVIEW_FAILED and artifact.verdict in (ReviewVerdict.APPROVED, ReviewVerdict.PASS):
        raise TransitionError("failed plan review cannot carry an approving verdict")
    expected = {Event.IMPLEMENTATION_FIX_REQUIRED: ReviewVerdict.IMPLEMENT_FIX, Event.REPLAN_REQUIRED: ReviewVerdict.REPLAN, Event.RESULT_REVIEW_PASSED: ReviewVerdict.PASS}
    if event in expected and artifact.verdict is not expected[event]:
        raise TransitionError("review verdict does not match event")
    if event is Event.RESULT_REVIEW_PASSED:
        if not _valid_observed_verification(task) or any(not r.passed for r in task.verification):
            raise TransitionError("passing result review requires passed evidence for every current criterion")
    if field_name == "result_review" and event is Event.RESULT_REVIEW_PASSED and artifact.verdict is not ReviewVerdict.PASS:
        raise TransitionError("passing result review requires PASS verdict")
    if field_name == "handoff" and (not artifact.summary.strip() or not artifact.evidence or any(not e.evidence_id.strip() or not e.description.strip() for e in artifact.evidence)):
        raise TransitionError("handoff requires a summary and evidence")
    updated = replace(task, **({field_name: artifact, "revision": updated_revision, "plan_digest": canonical_plan_digest(artifact)} if field_name == "plan" else {field_name: artifact}))
    if event is Event.REPLAN_REQUIRED:
        # Keep the review that triggered replanning (including its findings), but
        # revoke all authorization and downstream artifacts tied to the old plan.
        updated = replace(updated, blast_radius=None, plan_review=None,
                          approval_request=None, approval=None, permit=None,
                          mutation_proposal=None, mutation_authorization=None,
                          verification=(), handoff=None)
    if event is Event.PLAN_REVIEW_FAILED:
        updated = replace(updated, blast_radius=None, approval_request=None, approval=None, permit=None,
                          mutation_proposal=None, mutation_authorization=None)
    if event is Event.IMPLEMENTATION_FIX_REQUIRED:
        updated = replace(updated, verification=(), mutation_proposal=None, mutation_authorization=None)
    return _move(updated, next_state)


def _valid_observed_verification(task):
    if task.plan is None or task.plan_digest != canonical_plan_digest(task.plan) or task.plan.workspace_identity is None:
        return False
    criteria = {c.criterion_id for c in task.plan.acceptance_criteria}
    results = {r.criterion_id: r for r in task.verification if type(r) is VerificationResult}
    if not criteria or set(results) != criteria:
        return False
    approved = {cmd.argv: set(cmd.criterion_ids) for cmd in task.plan.verification_commands}
    seen = set()
    for criterion, result in results.items():
        if not result.evidence:
            return False
        for evidence in result.evidence:
            key = (criterion, evidence.argv)
            if (type(evidence) is not ObservedCommandEvidence or evidence.provenance is not EvidenceProvenance.GATE_OBSERVED
                    or key in seen or criterion not in approved.get(evidence.argv, set())
                    or (evidence.task_id, evidence.plan_revision, evidence.plan_digest, evidence.workspace_identity)
                    != (task.task_id, task.revision, task.plan_digest, task.plan.workspace_identity)):
                return False
            seen.add(key)
    return True


def _record_gate_observed_verification(current_task: TaskStateRecord, observations) -> TaskStateRecord:
    if current_task.state is not TaskState.IMPLEMENTING or current_task.plan is None:
        raise TransitionError("observed verification requires IMPLEMENTING state and a plan")
    if type(observations) is not tuple or not observations or not _bindings_valid(current_task, observations):
        raise TransitionError("observations do not match current approved verification plan")
    by_criterion = {c.criterion_id: [] for c in current_task.plan.acceptance_criteria}
    for obs in observations:
        if type(obs) is not ObservedCommandEvidence:
            raise TransitionError("verification requires gate-observed evidence")
        by_criterion[obs.criterion_id].append(obs)
    if not by_criterion or any(not values for values in by_criterion.values()):
        raise TransitionError("observations must cover every acceptance criterion")
    results = tuple(VerificationResult(cid, tuple(items)) for cid, items in by_criterion.items())
    return _move(replace(current_task, verification=results), TaskState.VERIFYING)


def _bindings_valid(task, observations):
    if task.plan is None or task.plan_digest != canonical_plan_digest(task.plan) or task.plan.workspace_identity is None:
        return False
    approved = {cmd.argv: set(cmd.criterion_ids) for cmd in task.plan.verification_commands}
    seen = set()
    for obs in observations:
        if type(obs) is not ObservedCommandEvidence or obs.provenance is not EvidenceProvenance.GATE_OBSERVED:
            return False
        key = (obs.criterion_id, obs.argv)
        if (key in seen or obs.criterion_id not in approved.get(obs.argv, set())
                or (obs.task_id, obs.plan_revision, obs.plan_digest, obs.workspace_identity)
                != (task.task_id, task.revision, task.plan_digest, task.plan.workspace_identity)):
            return False
        seen.add(key)
    return True


def record_approval(task: TaskStateRecord, receipt: ApprovalReceipt) -> TaskStateRecord:
    request = task.approval_request
    if task.state is not TaskState.AWAITING_APPROVAL or request is None:
        raise TransitionError("no current approval request")
    if (receipt.request_id, receipt.task_id, receipt.revision, receipt.digest) != (
        request.request_id, request.task_id, request.revision, request.digest
    ) or receipt.requester != task.task.requester:
        raise TransitionError("approval receipt does not match requester-bound request")
    if not receipt.approved:
        return _move(replace(task, approval=receipt, approval_request=None), TaskState.REJECTED)
    return _move(replace(task, approval=receipt), TaskState.APPROVED)


def _move(task: TaskStateRecord, state: TaskState) -> TaskStateRecord:
    return replace(task, state=state, history=task.history + (state,))


__all__ = ["Event", "Stage", "TransitionError", "canonical_mutation_proposal_digest", "canonical_plan_digest",
           "mutation_argument_digest", "new_task", "record_approval", "record_mutation_authorization",
           "record_mutation_proposal", "resolve_approved_verification_commands", "revise_plan", "transition"]
