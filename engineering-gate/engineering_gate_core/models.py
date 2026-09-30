"""Host-neutral, immutable lifecycle value objects."""
from dataclasses import dataclass
from enum import Enum
from typing import NewType

TaskID = NewType("TaskID", str)
PlanRevision = NewType("PlanRevision", int)
PlanDigest = NewType("PlanDigest", str)


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
class Plan:
    objective: str
    operations: tuple["NormalizedOperation", ...]
    acceptance_criteria: tuple["AcceptanceCriterion", ...]
    verification: tuple[str, ...]
    exclusions: tuple[str, ...] = ()


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


@dataclass(frozen=True)
class NormalizedOperation:
    kind: OperationKind
    target: str
    rationale: str = ""


@dataclass(frozen=True)
class MutationScope:
    operations: tuple[NormalizedOperation, ...]


@dataclass(frozen=True)
class ExecutionPermit:
    task_id: TaskID
    revision: PlanRevision
    digest: PlanDigest
    scope: MutationScope


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    description: str
    passed: bool | None = None


@dataclass(frozen=True)
class AcceptanceCriterion:
    criterion_id: str
    description: str
    verification_procedure: str


@dataclass(frozen=True)
class VerificationResult:
    criterion_id: str
    evidence: tuple[Evidence, ...]
    passed: bool


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

    @property
    def task_id(self) -> TaskID:
        return self.task.task_id


__all__ = [
    "AcceptanceCriterion", "ApprovalReceipt", "ApprovalRequest", "ChildTaskLease",
    "Evidence", "ExecutionPermit", "Handoff", "InspectionEvidenceRef",
    "MutationScope", "NormalizedOperation", "OperationKind", "Plan", "PlanDigest",
    "PlanReview", "PlanRevision", "RequesterIdentity", "ResultReview",
    "ReviewVerdict", "Task", "TaskID", "TaskState", "TaskStateRecord",
    "VerificationResult",
]
