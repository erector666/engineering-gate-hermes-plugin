"""Host-neutral, immutable lifecycle value objects."""
from dataclasses import dataclass
from enum import Enum
import re
from pathlib import PureWindowsPath
from typing import NewType

TaskID = NewType("TaskID", str)
PlanRevision = NewType("PlanRevision", int)
PlanDigest = NewType("PlanDigest", str)


def _require_digest(value: str, label: str) -> None:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _validate_relative_target(target: object) -> None:
    if type(target) is not str or not target or "\\" in target or "\x00" in target:
        raise ValueError("target must be a canonical relative POSIX path")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in target):
        raise ValueError("target must be a canonical relative POSIX path")
    if target.startswith("/") or PureWindowsPath(target).drive:
        raise ValueError("target must be a canonical relative POSIX path")
    if any(part in ("", ".", "..") for part in target.split("/")):
        raise ValueError("target must be a canonical relative POSIX path")


@dataclass(frozen=True)
class RequesterIdentity:
    subject: str


class TaskState(str, Enum):
    INTAKE = "intake"
    INSPECT = "inspect"
    ANALYZE = "analyze"
    PLAN = "plan"
    BLAST_RADIUS = "blast_radius"
    PLAN_REVIEW = "plan_review"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    IMPLEMENTING = "implementing"
    VERIFYING = "verifying"
    RESULT_REVIEW = "result_review"
    HANDOFF = "handoff"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass(frozen=True)
class Task:
    task_id: TaskID
    objective: str
    requester: RequesterIdentity


@dataclass(frozen=True)
class WorkspaceIdentity:
    canonical_path: str
    device: int
    inode: int


@dataclass(frozen=True)
class Plan:
    objective: str
    operations: tuple["NormalizedOperation", ...]
    acceptance_criteria: tuple["AcceptanceCriterion", ...]
    verification: tuple[str, ...]
    exclusions: tuple[str, ...] = ()
    workspace_root: str = ""
    workspace_identity: WorkspaceIdentity | None = None
    verification_commands: tuple["VerificationCommand", ...] = ()

    def __post_init__(self):
        criteria = [c.criterion_id for c in self.acceptance_criteria]
        if any(type(value) is not str or not value.strip() for value in criteria) or len(criteria) != len(set(criteria)):
            raise ValueError("acceptance criteria must have unique nonempty IDs")
        if type(self.verification_commands) is not tuple or any(type(c) is not VerificationCommand for c in self.verification_commands):
            raise ValueError("verification_commands must be a tuple of VerificationCommand")
        for command in self.verification_commands:
            if not set(command.criterion_ids).issubset(criteria):
                raise ValueError("verification command maps to an unknown criterion")


@dataclass(frozen=True)
class InspectionEvidenceRef:
    evidence_id: str
    description: str


class ReviewVerdict(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_CHANGES = "needs_changes"
    PASS = "pass"
    IMPLEMENT_FIX = "implement_fix"
    REPLAN = "replan"


@dataclass(frozen=True)
class PlanReview:
    verdict: ReviewVerdict
    findings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ApprovalRequest:
    task_id: TaskID
    revision: PlanRevision
    digest: PlanDigest
    request_id: str


@dataclass(frozen=True)
class ApprovalReceipt:
    request_id: str
    task_id: TaskID
    revision: PlanRevision
    digest: PlanDigest
    requester: RequesterIdentity
    approved: bool


class OperationKind(str, Enum):
    READ = "read"
    WRITE = "write"
    PATCH = "patch"
    DELETE = "delete"
    RENAME = "rename"
    EXECUTE = "execute"
    DELEGATE = "delegate"
    UNKNOWN = "unknown"


class ExecutionOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    OUTCOME_UNKNOWN = "outcome_unknown"


@dataclass(frozen=True)
class ExecutionAuditRecord:
    audit_id: str
    task_id: TaskID
    revision: PlanRevision
    plan_digest: PlanDigest
    proposal_digest: str
    authorization_id: str
    permit_hash: str
    operation_kind: OperationKind
    target: str
    argument_digest: str
    workspace_identity: WorkspaceIdentity
    started_at: str
    completed_at: str
    outcome: ExecutionOutcome
    resulting_artifact_digest: str | None = None
    path_detached: bool = False
    error_class: str | None = None

    def __post_init__(self):
        from datetime import datetime
        import re
        for name in ("audit_id", "authorization_id"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise ValueError(f"{name} is required")
        for name in ("plan_digest", "proposal_digest", "permit_hash", "argument_digest"):
            _require_digest(getattr(self, name), name)
        if self.resulting_artifact_digest is not None:
            _require_digest(self.resulting_artifact_digest, "resulting artifact digest")
        if type(self.task_id) is not str or not self.task_id.strip() or type(self.revision) is not int or self.revision < 0:
            raise ValueError("invalid task or revision")
        if type(self.operation_kind) is not OperationKind or self.operation_kind is not OperationKind.WRITE:
            raise ValueError("audit operation must be WRITE")
        _validate_relative_target(self.target)
        if type(self.workspace_identity) is not WorkspaceIdentity:
            raise ValueError("workspace identity is required")
        if type(self.path_detached) is not bool:
            raise ValueError("path_detached must be boolean")
        timestamps = []
        for stamp in (self.started_at, self.completed_at):
            if type(stamp) is not str or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp) is None:
                raise ValueError("timestamps must be canonical UTC ISO strings")
            try:
                parsed = datetime.fromisoformat(stamp[:-1] + "+00:00")
            except ValueError as exc:
                raise ValueError("invalid timestamp") from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("timestamps must include a timezone")
            timestamps.append(parsed)
        if timestamps[1] < timestamps[0]:
            raise ValueError("completion timestamp precedes start")
        if type(self.outcome) is not ExecutionOutcome:
            raise ValueError("outcome must be an ExecutionOutcome")
        if self.outcome is ExecutionOutcome.SUCCEEDED and self.resulting_artifact_digest is None:
            raise ValueError("successful outcome requires artifact digest")
        if self.outcome is ExecutionOutcome.OUTCOME_UNKNOWN and self.resulting_artifact_digest is not None:
            raise ValueError("unknown outcome cannot claim artifact digest")
        if self.error_class is not None and (type(self.error_class) is not str or len(self.error_class) > 120):
            raise ValueError("error_class must be bounded text")


@dataclass(frozen=True)
class ExecutionTransactionResult:
    audit_record: ExecutionAuditRecord
    path_detached: bool

    def __post_init__(self):
        if type(self.audit_record) is not ExecutionAuditRecord:
            raise ValueError("audit_record must be an ExecutionAuditRecord")
        if type(self.path_detached) is not bool:
            raise ValueError("path_detached must be boolean")


@dataclass(frozen=True)
class NormalizedOperation:
    kind: OperationKind
    target: str
    rationale: str = ""


@dataclass(frozen=True)
class MutationProposal:
    proposal_id: str
    task_id: TaskID
    revision: PlanRevision
    plan_digest: PlanDigest
    operation: NormalizedOperation
    argument_digest: str
    rationale: str
    diff_digest: str | None = None

    def __post_init__(self):
        if type(self.proposal_id) is not str or not self.proposal_id.strip():
            raise ValueError("proposal ID is required")
        if type(self.task_id) is not str or not self.task_id.strip() or type(self.revision) is not int or self.revision < 0:
            raise ValueError("proposal task and revision are invalid")
        _require_digest(self.plan_digest, "plan digest")
        _require_digest(self.argument_digest, "argument digest")
        if self.diff_digest is not None:
            _require_digest(self.diff_digest, "diff digest")
        if type(self.operation) is not NormalizedOperation or type(self.operation.kind) is not OperationKind or self.operation.kind is not OperationKind.WRITE:
            raise ValueError("only a typed WRITE operation is supported")
        _validate_relative_target(self.operation.target)
        if type(self.rationale) is not str or not self.rationale.strip():
            raise ValueError("proposal rationale is required")


@dataclass(frozen=True)
class MutationAuthorization:
    """Recorded authority/provider claim; not proof of human authentication."""
    authorization_id: str
    task_id: TaskID
    revision: PlanRevision
    plan_digest: PlanDigest
    proposal_digest: str
    authority_id: str
    authorized_at: str
    expires_at: str

    def __post_init__(self):
        from datetime import datetime
        import re
        if any(type(value) is not str or not value.strip() for value in
               (self.authorization_id, self.task_id, self.authority_id)):
            raise ValueError("authorization ID, task ID, and authority ID are required")
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("authorization revision is invalid")
        _require_digest(self.plan_digest, "plan digest")
        _require_digest(self.proposal_digest, "proposal digest")
        parsed = []
        for value in (self.authorized_at, self.expires_at):
            if type(value) is not str or re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value) is None:
                raise ValueError("authorization timestamps must be canonical UTC ISO strings")
            try:
                dt = datetime.fromisoformat(value[:-1] + "+00:00")
            except ValueError as exc:
                raise ValueError("malformed authorization timestamp") from exc
            parsed.append(dt)
        if parsed[1] <= parsed[0]:
            raise ValueError("authorization expiry must follow authorization time")


@dataclass(frozen=True)
class MutationScope:
    operations: tuple[NormalizedOperation, ...]


@dataclass(frozen=True)
class ExecutionPermit:
    task_id: TaskID
    revision: PlanRevision
    digest: PlanDigest
    scope: MutationScope


class EvidenceProvenance(str, Enum):
    AGENT_CLAIM = "agent_claim"
    GATE_OBSERVED = "gate_observed"


_ISSUER = object()


def _issue_observed_evidence(issuer, **values):
    if issuer is not _ISSUER:
        raise ValueError("ObservedCommandEvidence must be issued by the gate or internally restored")
    values["provenance"] = EvidenceProvenance.GATE_OBSERVED
    return ObservedCommandEvidence(**values, _issuer=_ISSUER)


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    description: str
    passed: bool | None = None
    provenance: EvidenceProvenance = EvidenceProvenance.AGENT_CLAIM


@dataclass(frozen=True, init=False)
class ObservedCommandEvidence:
    task_id: TaskID
    plan_revision: int
    plan_digest: str
    criterion_id: str
    provenance: EvidenceProvenance
    argv: tuple[str, ...]
    workspace_identity: WorkspaceIdentity
    started_at: str
    completed_at: str
    exit_code: int
    stdout_digest: str
    stderr_digest: str
    output_summary: str
    timed_out: bool

    def __init__(self, task_id, plan_revision, plan_digest, criterion_id, provenance, argv,
                 workspace_identity, started_at, completed_at, exit_code, stdout_digest,
                 stderr_digest, output_summary, timed_out, *, _issuer=None):
        if _issuer is not _ISSUER:
            raise ValueError("ObservedCommandEvidence must be issued by the gate or internally restored")
        for name, value in locals().copy().items():
            if name in {"self", "_issuer"}:
                continue
            object.__setattr__(self, name, value)
        self.__post_init__()

    def __post_init__(self):
        from datetime import datetime
        if self.provenance is not EvidenceProvenance.GATE_OBSERVED:
            raise ValueError("observations require GATE_OBSERVED provenance")
        if (not isinstance(self.task_id, str) or not self.task_id or type(self.plan_revision) is not int
                or self.plan_revision < 0 or not isinstance(self.criterion_id, str) or not self.criterion_id):
            raise ValueError("invalid observation binding")
        _require_digest(self.plan_digest, "plan digest")
        _require_digest(self.stdout_digest, "stdout digest")
        _require_digest(self.stderr_digest, "stderr digest")
        if (not isinstance(self.argv, tuple) or not self.argv or any(type(x) is not str or not x for x in self.argv)
                or type(self.workspace_identity) is not WorkspaceIdentity):
            raise ValueError("invalid command or workspace")
        try:
            start = datetime.fromisoformat(self.started_at.replace("Z", "+00:00"))
            end = datetime.fromisoformat(self.completed_at.replace("Z", "+00:00"))
        except (ValueError, AttributeError) as exc:
            raise ValueError("invalid observation timestamps") from exc
        if start.tzinfo is None or end.tzinfo is None or end < start:
            raise ValueError("invalid observation timestamp order")
        if type(self.exit_code) is not int or type(self.timed_out) is not bool:
            raise ValueError("invalid observation result")
        if type(self.output_summary) is not str or len(self.output_summary) > 512:
            raise ValueError("output_summary must be text of at most 512 characters")

    @property
    def passed(self):
        return self.exit_code == 0 and not self.timed_out

    @classmethod
    def _issue(cls, *, _issuer=None, **values):
        if _issuer is not _ISSUER:
            raise ValueError("ObservedCommandEvidence must be issued by the gate or internally restored")
        values["provenance"] = EvidenceProvenance.GATE_OBSERVED
        return cls(**values, _issuer=_ISSUER)

    @classmethod
    def _restore(cls, **values):
        values.setdefault("provenance", EvidenceProvenance.GATE_OBSERVED)
        return cls(**values, _issuer=_ISSUER)


@dataclass(frozen=True)
class AcceptanceCriterion:
    criterion_id: str
    description: str
    verification_procedure: str


@dataclass(frozen=True)
class VerificationCommand:
    argv: tuple[str, ...]
    criterion_ids: tuple[str, ...]
    timeout_seconds: int
    output_cap_bytes: int

    def __post_init__(self):
        if (type(self.argv) is not tuple or not self.argv or
                any(type(arg) is not str or not arg or "\x00" in arg for arg in self.argv)):
            raise ValueError("argv must be a nonempty tuple of nonempty strings")
        if (type(self.criterion_ids) is not tuple or not self.criterion_ids or
                any(type(cid) is not str or not cid.strip() for cid in self.criterion_ids) or
                len(self.criterion_ids) != len(set(self.criterion_ids))):
            raise ValueError("criterion_ids must be unique nonempty IDs")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be between 1 and 3600")
        if type(self.output_cap_bytes) is not int or not 1 <= self.output_cap_bytes <= 10_000_000:
            raise ValueError("output_cap_bytes must be between 1 and 10000000")


@dataclass(frozen=True)
class VerificationResult:
    criterion_id: str
    evidence: tuple[ObservedCommandEvidence, ...]

    def __post_init__(self):
        if type(self.criterion_id) is not str or not self.criterion_id or type(self.evidence) is not tuple or not self.evidence or any(type(e) is not ObservedCommandEvidence for e in self.evidence):
            raise ValueError("verification results require observed command evidence")

    @property
    def passed(self):
        return bool(self.evidence) and all(item.passed for item in self.evidence)


@dataclass(frozen=True)
class ResultReview:
    verdict: ReviewVerdict
    findings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ChildTaskLease:
    child_task_id: TaskID
    allowed_scope: MutationScope


@dataclass(frozen=True)
class Handoff:
    summary: str
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True)
class TaskStateRecord:
    task: Task
    state: TaskState
    revision: PlanRevision
    history: tuple[TaskState, ...]
    inspection: InspectionEvidenceRef | None = None
    analysis: Evidence | None = None
    plan: Plan | None = None
    plan_digest: PlanDigest | None = None
    blast_radius: Evidence | None = None
    plan_review: PlanReview | None = None
    approval_request: ApprovalRequest | None = None
    approval: ApprovalReceipt | None = None
    permit: ExecutionPermit | None = None
    verification: tuple[VerificationResult, ...] = ()
    result_review: ResultReview | None = None
    handoff: Handoff | None = None
    child_leases: tuple[ChildTaskLease, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    mutation_proposal: MutationProposal | None = None
    mutation_authorization: MutationAuthorization | None = None

    @property
    def task_id(self) -> TaskID:
        return self.task.task_id


__all__ = [
    "AcceptanceCriterion", "ApprovalReceipt", "ApprovalRequest", "ChildTaskLease", "ExecutionAuditRecord", "ExecutionOutcome", "ExecutionTransactionResult",
    "Evidence", "EvidenceProvenance", "ObservedCommandEvidence", "ExecutionPermit", "Handoff", "InspectionEvidenceRef",
    "MutationAuthorization", "MutationProposal", "MutationScope", "NormalizedOperation", "OperationKind", "Plan", "PlanDigest",
    "PlanReview", "PlanRevision", "RequesterIdentity", "ResultReview",
    "ReviewVerdict", "Task", "TaskID", "TaskState", "TaskStateRecord",
    "VerificationCommand", "VerificationResult", "WorkspaceIdentity",
]
