"""Gate-owned, one-shot execution for authorized single-file writes.

This constrains mutations routed through this service; it is not an OS sandbox.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Callable

from .models import NormalizedOperation, OperationKind, TaskStateRecord
from .policy import PolicyAction, authorize_invocation


class MutationOutcomeUnknown(RuntimeError):
    """The file replacement completed, but its enclosing state transaction failed.

    SQLite and the filesystem are not a single atomic resource. This exception
    does not roll back or reconcile the filesystem mutation; inspect the target
    before retrying.
    """


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


def _digest(arguments: Any) -> str:
    encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class GateWriteService:
    """Issue one-use permits and execute authorized writes beneath a pinned root."""

    def __init__(self, root: str | os.PathLike[str], *,
                 state_loader: Callable[[str], TaskStateRecord],
                 state_transaction: Callable[[str, Callable[[TaskStateRecord], Any]], Any] | None = None) -> None:
        if not callable(state_loader):
            raise TypeError("state_loader must be callable")
        if not callable(state_transaction):
            raise TypeError("state_transaction must be callable")
        self._state_loader = state_loader
        self._state_transaction = state_transaction
        self._root = Path(root).resolve(strict=True)
        if not self._root.is_dir():
            raise ValueError("write root must be an existing directory")
        if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
            raise PermissionError("platform lacks safe directory descriptor operations")
        self._root_fd = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._permits: dict[str, _Binding] = {}
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

    def issue_permit(self, *, task_id: str, operation: NormalizedOperation, arguments: Any) -> WritePermit:
        with self._lock:
            if self._closed:
                raise ValueError("write service is closed")
        state = self._load_current_state(task_id)
        plan_digest = self._authorize(state, operation)
        if not isinstance(arguments, dict) or set(arguments) != {"content"} or not isinstance(arguments["content"], str):
            raise ValueError("write arguments must contain only string content")
        try:
            arg_digest = _digest(arguments)
        except (TypeError, ValueError) as exc:
            raise ValueError("write arguments are not canonical JSON") from exc
        binding = _Binding(str(state.task_id), int(state.revision), plan_digest, operation,
                           operation.target, arg_digest)
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
            binding = self._permits.pop(permit._nonce, None)
        if binding is None:
            raise PermissionError("permit is invalid or already used")
        if task_id != binding.task_id:
            raise PermissionError("request does not match permit")
        replacement_completed = False

        def execute_current(state: TaskStateRecord) -> Path:
            nonlocal replacement_completed
            if not isinstance(state, TaskStateRecord) or state.task_id != task_id:
                raise PermissionError("current task state is invalid or belongs to another task")
            plan_digest = self._authorize(state, operation)
            try:
                arg_digest = _digest(arguments)
            except (TypeError, ValueError) as exc:
                raise PermissionError("request arguments are invalid") from exc
            attempted = _Binding(task_id, int(state.revision), plan_digest,
                                 operation, operation.target, arg_digest)
            if attempted != binding:
                raise PermissionError("request does not match permit")
            if not isinstance(arguments, dict) or set(arguments) != {"content"} or not isinstance(arguments["content"], str):
                raise ValueError("write arguments must contain only string content")

            relative = Path(operation.target)
            if relative.is_absolute() or not relative.parts or any(part in (".", "..") for part in relative.parts):
                raise PermissionError("target must be a contained relative path")
            required = ("O_DIRECTORY", "O_NOFOLLOW", "supports_dir_fd")
            if not all(hasattr(os, name) for name in required) or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd or os.rename not in os.supports_dir_fd:
                raise PermissionError("platform lacks safe descriptor-relative filesystem operations")
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            descriptors: list[int] = []
            temp_name: str | None = None
            parent_fd = os.dup(self._root_fd)
            descriptors.append(parent_fd)
            try:
                for part in relative.parts[:-1]:
                    try:
                        parent_fd = os.open(part, directory_flags, dir_fd=parent_fd)
                    except OSError as exc:
                        raise PermissionError("target parent is missing or traverses a symlink") from exc
                    descriptors.append(parent_fd)
                name = relative.parts[-1]
                try:
                    existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    existing = None
                except OSError as exc:
                    raise PermissionError("target cannot be inspected safely") from exc
                if existing is not None and not stat.S_ISREG(existing.st_mode):
                    raise PermissionError("target must be a regular file, not a symlink or special file")
                temp_name = f".gate-write-{secrets.token_hex(16)}.tmp"
                fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666, dir_fd=parent_fd)
                try:
                    if existing is not None:
                        os.fchmod(fd, stat.S_IMODE(existing.st_mode))
                    view = memoryview(arguments["content"].encode("utf-8"))
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            raise OSError("short write")
                        view = view[written:]
                finally:
                    os.close(fd)
                os.replace(temp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                replacement_completed = True
                temp_name = None
            finally:
                if temp_name is not None:
                    try:
                        os.unlink(temp_name, dir_fd=parent_fd)
                    except FileNotFoundError:
                        pass
                for descriptor in reversed(descriptors):
                    os.close(descriptor)
            return self._root.joinpath(relative)

        try:
            return self._state_transaction(task_id, execute_current)
        except Exception as exc:
            if replacement_completed:
                raise MutationOutcomeUnknown(
                    "the write may have completed; inspect the target before retrying"
                ) from exc
            raise
