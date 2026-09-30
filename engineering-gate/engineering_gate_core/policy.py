"""Pure policy decision for normalized operations.

An ALLOW result is a preflight decision, not authority to call a host mutation
surface directly. Filesystem checks can race when used alone; mutations must
execute through GateWriteService, which revalidates current state inside the
store transaction and uses descriptor-relative no-follow operations. This is
not an OS sandbox.
"""
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PureWindowsPath

from .models import NormalizedOperation, OperationKind, TaskState, TaskStateRecord
from .workflow import canonical_plan_digest


class MutationClass(str, Enum):
    READ_ONLY = "read_only"
    FILESYSTEM_MUTATION = "filesystem_mutation"
    UNSUPPORTED = "unsupported"


class PolicyAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    SCOPE_DRIFT = "scope_drift"


@dataclass(frozen=True)
class PolicyDecision:
    action: PolicyAction
    reason: str


def classify_operation(op: NormalizedOperation) -> MutationClass:
    if not isinstance(op, NormalizedOperation) or not isinstance(op.kind, OperationKind):
        return MutationClass.UNSUPPORTED
    if op.kind is OperationKind.READ:
        return MutationClass.READ_ONLY
    if op.kind in (OperationKind.WRITE, OperationKind.PATCH, OperationKind.DELETE, OperationKind.RENAME):
        return MutationClass.FILESYSTEM_MUTATION
    return MutationClass.UNSUPPORTED


def _valid_target(target: object, workspace_root: object) -> bool:
    if not isinstance(target, str) or not target or "\x00" in target:
        return False
    # Normalized targets have exactly one host-neutral representation: `/`.
    # Windows adapters must convert native paths before invoking this policy.
    if "\\" in target:
        return False
    # Treat Windows absolute/drive syntax as hostile even on POSIX.
    win = PureWindowsPath(target)
    if Path(target).is_absolute() or win.is_absolute() or win.drive:
        return False
    if any(part in ("", ".", "..") for part in target.split("/")):
        return False
    if not isinstance(workspace_root, (str, Path)) or not str(workspace_root):
        return False
    try:
        root = Path(workspace_root).resolve(strict=True)
        if not root.is_dir():
            return False
        # Reject every existing symlink component, even when it resolves
        # inside the workspace: aliases can bypass the approved exact path.
        current = root
        for part in target.split("/"):
            current = current / part
            try:
                current.lstat()
            except FileNotFoundError:
                # A missing suffix is allowed, but no later component can
                # exist beneath it without an intervening filesystem change.
                break
            if current.is_symlink():
                return False
        candidate = (root / target).resolve(strict=False)
        candidate.relative_to(root)
        return True
    except (OSError, RuntimeError, ValueError, TypeError):
        return False


def authorize_invocation(state: TaskStateRecord, operation: NormalizedOperation,
                         workspace_root: str | Path) -> PolicyDecision:
    def block(reason: str) -> PolicyDecision:
        return PolicyDecision(PolicyAction.BLOCK, reason)

    if not isinstance(state, TaskStateRecord) or not isinstance(operation, NormalizedOperation):
        return block("malformed state or operation")
    if not hasattr(state, "task") or state.task is None:
        return block("malformed task state")
    if classify_operation(operation) is MutationClass.UNSUPPORTED:
        return block("operation kind is unsupported")
    if state.state is not TaskState.IMPLEMENTING or state.plan is None:
        return block("task is not implementing a planned operation")
    try:
        digest = canonical_plan_digest(state.plan)
    except (AttributeError, TypeError, ValueError):
        return block("plan is malformed")
    if state.plan_digest != digest:
        return block("current plan digest is invalid")
    if not isinstance(state.plan.workspace_root, str) or not state.plan.workspace_root:
        return block("approved plan has no workspace root")
    try:
        approved_root = Path(state.plan.workspace_root)
        supplied_root = Path(workspace_root)
        if not approved_root.is_absolute() or approved_root.resolve(strict=True) != approved_root:
            return block("approved workspace root is invalid or non-canonical")
        if supplied_root.resolve(strict=True) != approved_root or not approved_root.is_dir():
            return block("caller workspace does not match the approved plan")
    except (OSError, RuntimeError, ValueError, TypeError):
        return block("approved or caller workspace root is invalid")
    approval, permit = state.approval, state.permit
    if approval is None or not approval.approved or (
        approval.task_id != state.task_id or approval.revision != state.revision
        or approval.digest != digest or approval.requester != state.task.requester
    ):
        return block("approval does not bind the current task revision and requester")
    if permit is None or (
        permit.task_id != state.task_id or permit.revision != state.revision or permit.digest != digest
    ):
        return block("execution permit does not bind the current task revision")
    if operation not in state.plan.operations:
        return block("operation is not in the approved plan")
    if operation not in permit.scope.operations:
        return PolicyDecision(PolicyAction.SCOPE_DRIFT, "operation is outside the active permit scope")
    if classify_operation(operation) is MutationClass.FILESYSTEM_MUTATION or operation.kind is OperationKind.READ:
        if not _valid_target(operation.target, workspace_root):
            return block("target is invalid or escapes the workspace")
    return PolicyDecision(PolicyAction.ALLOW, "operation is authorized")


__all__ = ["MutationClass", "PolicyAction", "PolicyDecision", "authorize_invocation", "classify_operation"]
