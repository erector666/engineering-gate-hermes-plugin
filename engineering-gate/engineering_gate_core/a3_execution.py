"""Gate-owned, one-shot execution for authorized single-file writes.

This constrains mutations routed through this service; it is not an OS sandbox.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Callable

from datetime import datetime, timezone
from uuid import uuid4
from .models import (ExecutionAuditRecord, ExecutionOutcome, ExecutionTransactionResult,
                    MutationAuthorization, MutationProposal, NormalizedOperation, OperationKind,
                    TaskState, TaskStateRecord)
from .models import WorkspaceIdentity
from .policy import PolicyAction, authorize_invocation
from .workflow import (TransitionError, canonical_mutation_proposal_digest,
                       mutation_argument_digest, record_mutation_authorization)


class MutationOutcomeUnknown(RuntimeError):
    """The file replacement completed, but its enclosing state transaction failed.

    SQLite and the filesystem are not a single atomic resource. This exception
    does not roll back or reconcile the filesystem mutation; inspect the target
    before retrying.
    """


class WorkspacePathDetached(RuntimeError):
    """The pinned workspace received the write, but its canonical path changed."""


@dataclass(frozen=True)
class WritePermit:
    """Opaque capability issued for one exact authorized write request."""
    _nonce: str


@dataclass(frozen=True)
class _Binding:
    task_id: str
    revision: int
    plan_digest: str
    operation: NormalizedOperation
    target: str
    argument_digest: str
    proposal_digest: str
    authorization_digest: str


@dataclass(frozen=True)
class _DetachedOutcome:
    cause: BaseException


def _digest(arguments: Any) -> str:
    encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class GateWriteService:
    """Issue one-use permits and execute writes beneath a pinned root.

    Parent directories are opened component-by-component beneath the pinned root;
    all mutation and readback use the pinned leaf-parent descriptor. A concurrent
    rename after the last edge check can therefore leave the write in a detached
    directory, which is audited and reported rather than redirected. This is not
    protection against a hostile same-UID process or OS-level compromise.

    The injected verifier is a trusted host/provider boundary; None fails closed.
    This library does not authenticate humans. Do not expose service construction
    or its verifier to the autonomous executor. The lease provider must atomically
    reserve the authorization against revocation and return a context manager;
    its lease remains held until context exit, including across the final workspace
    identity check and os.replace. Acquisition rejects by raising; exit always
    releases the reservation. This is a trusted provider contract.
    """

    def __init__(self, root: str | os.PathLike[str], *, state_store: Any,
                 mutation_authority: Any, clock: Callable[[], datetime] | None = None) -> None:
        from .mutation_authority import GateMutationAuthority
        from .state_store import StateStore
        if type(state_store) is not StateStore or type(mutation_authority) is not GateMutationAuthority:
            raise TypeError("StateStore and GateMutationAuthority are required")
        if mutation_authority.store is not state_store:
            raise ValueError("mutation authority must use the identical StateStore")
        self._state_store = state_store
        self._mutation_authority = mutation_authority
        self._state_loader = state_store.load
        self._state_transaction = state_store.with_current_state_transaction
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._root = Path(root).resolve(strict=True)
        if not self._root.is_dir():
            raise ValueError("write root must be an existing directory")
        if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
            raise PermissionError("platform lacks safe directory descriptor operations")
        self._root_fd = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._permits: dict[str, _Binding] = {}
        self._reserved_permits: set[str] = set()
        self._lock = Lock()
        self._closed = False

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                os.close(self._root_fd)
                self._closed = True
                self._permits.clear()

    def __enter__(self) -> "GateWriteService":
        if self._closed:
            raise ValueError("write service is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _authorize(self, state: TaskStateRecord, operation: NormalizedOperation) -> str:
        if not isinstance(operation, NormalizedOperation) or operation.kind is not OperationKind.WRITE:
            raise PermissionError("unsupported operation")
        target = operation.target
        from .models import _validate_relative_target
        try:
            _validate_relative_target(target)
        except ValueError as exc:
            raise PermissionError("write target must be a canonical relative POSIX path") from exc
        decision = authorize_invocation(state, operation, self._root)
        if decision.action is not PolicyAction.ALLOW:
            raise PermissionError(f"invocation is not authorized: {decision.reason}")
        return str(state.plan_digest)

    def _load_current_state(self, task_id: str) -> TaskStateRecord:
        if not isinstance(task_id, str) or not task_id:
            raise PermissionError("invalid task ID")
        try:
            state = self._state_loader(task_id)
        except Exception as exc:
            raise PermissionError("current task state is unavailable") from exc
        if not isinstance(state, TaskStateRecord) or state.task_id != task_id:
            raise PermissionError("current task state is invalid or belongs to another task")
        return state

    def _verified_context(self, state: TaskStateRecord, operation: NormalizedOperation,
                          arguments: Any, *, authorization_id: str | None = None) -> tuple[str, str, str, str]:
        if not isinstance(arguments, dict) or set(arguments) != {"content"} or type(arguments["content"]) is not str:
            raise PermissionError("write arguments must contain only string content")
        proposal = state.mutation_proposal
        if type(proposal) is not MutationProposal:
            raise PermissionError("current mutation proposal is required")
        try:
            proposal_digest = canonical_mutation_proposal_digest(proposal)
            if authorization_id is None:
                authorization_id = self._mutation_authority.get_active_authorization(state.task_id, proposal).authorization_id
            expected_argument = mutation_argument_digest(arguments["content"])
        except Exception as exc:
            raise PermissionError("mutation authorization context is invalid") from exc
        if (state.state is not TaskState.IMPLEMENTING or proposal.operation != operation
                or proposal.argument_digest != expected_argument or proposal.task_id != state.task_id
                or proposal.revision != state.revision or proposal.plan_digest != state.plan_digest):
            raise PermissionError("request does not match reviewed mutation proposal")
        return str(state.plan_digest), expected_argument, proposal_digest, authorization_id

    def issue_permit(self, *, task_id: str, operation: NormalizedOperation, arguments: Any) -> WritePermit:
        with self._lock:
            if self._closed:
                raise ValueError("write service is closed")
        state = self._load_current_state(task_id)
        plan_digest = self._authorize(state, operation)
        _, arg_digest, proposal_digest, auth_digest = self._verified_context(state, operation, arguments)
        binding = _Binding(str(state.task_id), int(state.revision), plan_digest, operation,
                           operation.target, arg_digest, proposal_digest, auth_digest)
        nonce = secrets.token_urlsafe(32)
        with self._lock:
            if self._closed:
                raise ValueError("write service is closed")
            self._permits[nonce] = binding
        return WritePermit(nonce)

    def execute(self, permit: WritePermit, *, task_id: str,
                operation: NormalizedOperation, arguments: Any) -> Path:
        if not isinstance(permit, WritePermit):
            raise PermissionError("invalid permit")
        with self._lock:
            if self._closed:
                raise PermissionError("write service is closed")
            binding = self._permits.get(permit._nonce)
            if binding is None:
                raise PermissionError("permit is invalid or already used")
            if permit._nonce in self._reserved_permits:
                raise PermissionError("permit is already reserved")
            if task_id != binding.task_id:
                raise PermissionError("request does not match permit")
        # Prepare fallible audit metadata before reserving the one-shot permit;
        # rejected pre-write attempts must not strand the permit as in-flight.
        started_at = self._clock().astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self._lock:
            if self._closed:
                raise PermissionError("write service is closed")
            if self._permits.get(permit._nonce) != binding or permit._nonce in self._reserved_permits:
                raise PermissionError("permit is invalid or already reserved")
            self._reserved_permits.add(permit._nonce)
        replacement_completed = False
        approved_identity: WorkspaceIdentity | None = None
        detached = False

        staged: dict[str, Any] = {}

        def stage_current(state: TaskStateRecord) -> None:
            self._authorize(state, operation)
            _, arg_digest, proposal_digest, _ = self._verified_context(
                state, operation, arguments, authorization_id=binding.authorization_digest)
            if _Binding(task_id, int(state.revision), str(state.plan_digest), operation,
                        operation.target, arg_digest, proposal_digest, binding.authorization_digest) != binding:
                raise PermissionError("request does not match permit")
            components = operation.target.split("/")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            fds = [os.dup(self._root_fd)]
            temp_name = None
            try:
                for component in components[:-1]:
                    child = os.open(component, flags, dir_fd=fds[-1])
                    if not stat.S_ISDIR(os.fstat(child).st_mode):
                        os.close(child)
                        raise PermissionError("target parent is not a directory")
                    fds.append(child)
                parent, name = fds[-1], components[-1]
                try: existing = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError: existing = None
                except OSError as exc: raise PermissionError("target cannot be inspected safely") from exc
                if existing is not None and not stat.S_ISREG(existing.st_mode):
                    raise PermissionError("target must be a regular file, not a symlink or special file")
                for _ in range(10):
                    candidate = f".gate-write-{secrets.token_hex(16)}.tmp"
                    if candidate == name:
                        continue
                    try:
                        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666, dir_fd=parent)
                    except FileExistsError:
                        continue
                    temp_name = candidate
                    break
                else:
                    raise FileExistsError("unable to allocate a unique staging file")
                try:
                    if existing is not None: os.fchmod(fd, stat.S_IMODE(existing.st_mode))
                    view = memoryview(arguments["content"].encode("utf-8"))
                    while view:
                        n = os.write(fd, view)
                        if n <= 0: raise OSError("short write")
                        view = view[n:]
                finally: os.close(fd)
                info = os.stat(temp_name, dir_fd=parent, follow_symlinks=False)
                staged.update(fds=fds, name=name, temp_name=temp_name,
                              identity=(info.st_dev, info.st_ino), components=components,
                              edges=[(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in fds])
                temp_name = None
                fds = []
            finally:
                if temp_name:
                    try: os.unlink(temp_name, dir_fd=fds[-1])
                    except FileNotFoundError: pass
                for fd in reversed(fds): os.close(fd)

        def cleanup_staged() -> None:
            fds = staged.pop("fds", [])
            name = staged.pop("temp_name", None)
            if name and fds:
                try: os.unlink(name, dir_fd=fds[-1])
                except FileNotFoundError: pass
                except OSError as exc:
                    if exc.errno != 9: raise
            for fd in reversed(fds):
                try: os.close(fd)
                except OSError as exc:
                    if exc.errno != 9: raise

        def execute_current(state: TaskStateRecord) -> ExecutionTransactionResult:
            nonlocal replacement_completed, approved_identity, detached
            if not isinstance(state, TaskStateRecord) or state.task_id != task_id:
                raise PermissionError("current task state is invalid or belongs to another task")
            current_plan_digest = self._authorize(state, operation)
            plan_digest, arg_digest, proposal_digest, auth_digest = self._verified_context(
                state, operation, arguments, authorization_id=binding.authorization_digest)
            if current_plan_digest != plan_digest:
                raise PermissionError("current plan does not match authorization")
            approved_identity = state.plan.workspace_identity if state.plan else None
            attempted = _Binding(task_id, int(state.revision), plan_digest,
                                 operation, operation.target, arg_digest, proposal_digest, auth_digest)
            if attempted != binding:
                raise PermissionError("request does not match permit")
            if not isinstance(arguments, dict) or set(arguments) != {"content"} or not isinstance(arguments["content"], str):
                raise ValueError("write arguments must contain only string content")

            components = staged["components"]
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            temp_name = staged["temp_name"]
            pinned_fds = staged["fds"]
            parent_fd = pinned_fds[-1]
            name = staged["name"]
            pinned_edges = staged["edges"]
            try:
                def parent_chain_matches() -> bool:
                    check_fd = os.dup(self._root_fd)
                    try:
                        if (os.fstat(check_fd).st_dev, os.fstat(check_fd).st_ino) != pinned_edges[0]:
                            return False
                        for index, component in enumerate(components[:-1], 1):
                            next_fd = os.open(component, directory_flags, dir_fd=check_fd)
                            info = os.fstat(next_fd)
                            os.close(check_fd)
                            check_fd = next_fd
                            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != pinned_edges[index]:
                                return False
                        return True
                    except OSError:
                        return False
                    finally:
                        os.close(check_fd)

                try: existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError: existing = None
                except OSError as exc: raise PermissionError("target cannot be inspected safely") from exc
                if existing is not None and not stat.S_ISREG(existing.st_mode):
                    raise PermissionError("target must be a regular file, not a symlink or special file")
                staged_identity = staged["identity"]
                if state.mutation_proposal is None:
                    raise PermissionError("current mutation proposal is unavailable")
                latest_arg_digest = mutation_argument_digest(arguments["content"])
                latest_proposal_digest = canonical_mutation_proposal_digest(state.mutation_proposal)
                latest = _Binding(task_id, int(state.revision), str(state.plan_digest), operation,
                                  operation.target, latest_arg_digest, latest_proposal_digest,
                                  binding.authorization_digest)
                if latest != binding:
                    raise PermissionError("authorization changed before filesystem mutation")
                self._validate_workspace_identity(state.plan.workspace_identity if state.plan else None)
                if not parent_chain_matches():
                    raise WorkspacePathDetached("workspace parent path detached before replacement")
                active_lease.mark_replacement_attempted()
                try:
                    os.replace(temp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                except Exception:
                    raise
                replacement_completed = True
                temp_name = None
                temp_name = None
                try:
                    self._validate_workspace_identity(state.plan.workspace_identity if state.plan else None)
                    if not parent_chain_matches():
                        detached = True
                except PermissionError:
                    detached = True
                observed_fd = None
                audit_error: str | None = None
                try:
                    observed_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    observed_info = os.fstat(observed_fd)
                    if (not stat.S_ISREG(observed_info.st_mode)
                            or (observed_info.st_dev, observed_info.st_ino) != staged_identity):
                        raise OSError("readback identity mismatch")
                    readback_identity = (observed_info.st_dev, observed_info.st_ino,
                                         observed_info.st_size, observed_info.st_mtime_ns,
                                         observed_info.st_ctime_ns)
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(observed_fd, 65536)
                        if not chunk:
                            break
                        digest.update(chunk)
                    after_read_info = os.fstat(observed_fd)
                    after_read_identity = (after_read_info.st_dev, after_read_info.st_ino,
                                           after_read_info.st_size, after_read_info.st_mtime_ns,
                                           after_read_info.st_ctime_ns)
                    if after_read_identity != readback_identity:
                        raise OSError("readback artifact mutated")
                    resulting_artifact_digest = digest.hexdigest()
                    after_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if (after_info.st_dev, after_info.st_ino) != staged_identity:
                        raise OSError("readback target changed")
                except Exception as exc:
                    resulting_artifact_digest = None
                    audit_error = type(exc).__name__[:40]
                finally:
                    if observed_fd is not None:
                        os.close(observed_fd)
            finally:
                pass
            audit = ExecutionAuditRecord(
                audit_id=str(uuid4()), task_id=state.task_id, revision=state.revision,
                plan_digest=str(state.plan_digest), proposal_digest=proposal_digest,
                authorization_id=binding.authorization_digest,
                permit_hash=hashlib.sha256(permit._nonce.encode("utf-8")).hexdigest(),
                operation_kind=operation.kind, target=operation.target, argument_digest=arg_digest,
                workspace_identity=state.plan.workspace_identity,
                started_at=started_at,
                completed_at=self._clock().astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                outcome=ExecutionOutcome.OUTCOME_UNKNOWN if audit_error else ExecutionOutcome.SUCCEEDED,
            resulting_artifact_digest=resulting_artifact_digest,
            path_detached=detached, error_class=audit_error)
            return ExecutionTransactionResult(audit, detached)

        try:
            current = self._state_loader(task_id)
            if not isinstance(current, TaskStateRecord) or current.task_id != task_id:
                raise PermissionError("current task state is invalid or belongs to another task")
            self._authorize(current, operation)
            _, current_argument_digest, current_proposal_digest, current_authorization_id = self._verified_context(
                current, operation, arguments)
            if (current_authorization_id != binding.authorization_digest
                    or current_argument_digest != binding.argument_digest
                    or current_proposal_digest != binding.proposal_digest
                    or current.revision != binding.revision
                    or current.plan_digest != binding.plan_digest):
                raise PermissionError("execution request does not match permit authorization")
            stage_current(current)
            with self._mutation_authority.acquire_write_lease(
                    task_id, binding.authorization_digest, current.mutation_proposal) as active_lease:
                outcome = self._state_transaction(task_id, execute_current)
                if (isinstance(outcome, ExecutionTransactionResult)
                        and outcome.audit_record.outcome is ExecutionOutcome.SUCCEEDED
                        and not outcome.path_detached):
                    active_lease.complete()
                else:
                    active_lease.finalize("uncertain")
            cleanup_staged()
        except Exception as exc:
            cleanup_staged()
            with self._lock:
                self._reserved_permits.discard(permit._nonce)
                if replacement_completed:
                    self._permits.pop(permit._nonce, None)
            if replacement_completed:
                raise MutationOutcomeUnknown(
                    "the write may have completed; inspect the target before retrying"
                ) from exc
            if isinstance(exc, PermissionError):
                raise
            raise PermissionError("write authorization or execution failed") from exc
        with self._lock:
            self._reserved_permits.discard(permit._nonce)
            self._permits.pop(permit._nonce, None)
        if not isinstance(outcome, ExecutionTransactionResult):
            raise MutationOutcomeUnknown("state transaction returned no execution audit result")
        if outcome.audit_record.outcome is ExecutionOutcome.OUTCOME_UNKNOWN:
            raise MutationOutcomeUnknown(
                "filesystem replacement may have completed, but the resulting artifact could not be verified; inspect the target before retrying"
            )
        if outcome.path_detached:
            raise WorkspacePathDetached(
                "write completed on the pinned approved workspace inode, but the approved workspace path changed; no path result is available"
            )
        try:
            self._validate_workspace_identity(approved_identity)
        except PermissionError as exc:
            raise WorkspacePathDetached(
                "write completed on the pinned approved workspace inode, but the approved workspace path changed; no path result is available"
            ) from exc
        return self._root.joinpath(operation.target)

    def _validate_workspace_identity(self, identity: WorkspaceIdentity | None) -> None:
        try:
            pinned = os.fstat(self._root_fd)
            path_info = self._root.lstat()
            if (identity is None or self._root.is_symlink() or not stat.S_ISDIR(path_info.st_mode)
                    or str(self._root) != identity.canonical_path
                    or (pinned.st_dev, pinned.st_ino) != (identity.device, identity.inode)
                    or (path_info.st_dev, path_info.st_ino) != (identity.device, identity.inode)):
                raise PermissionError("approved workspace identity changed")
        except OSError as exc:
            raise PermissionError("approved workspace identity is unavailable") from exc
