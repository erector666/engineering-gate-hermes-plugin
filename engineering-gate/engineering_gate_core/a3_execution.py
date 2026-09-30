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
from typing import Any


@dataclass(frozen=True)
class WritePermit:
    """Opaque capability issued for one exact write request."""

    _nonce: str


@dataclass(frozen=True)
class _Binding:
    task: str
    plan_revision: str
    operation: str
    target: str
    argument_digest: str


def _digest(arguments: Any) -> str:
    encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class GateWriteService:
    """Issue one-use permits and execute authorized writes below a fixed root."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self._root = Path(root).resolve(strict=True)
        if not self._root.is_dir():
            raise ValueError("write root must be an existing directory")
        self._permits: dict[str, _Binding] = {}
        self._lock = Lock()

    def issue_permit(
        self, *, task: str, plan_revision: str, operation: str,
        target: str, arguments: Any,
    ) -> WritePermit:
        if operation != "write":
            raise ValueError("unsupported operation")
        if not all(isinstance(v, str) and v for v in (task, plan_revision, target)):
            raise ValueError("task, plan revision, and target must be non-empty strings")
        binding = _Binding(task, plan_revision, operation, target, _digest(arguments))
        nonce = secrets.token_urlsafe(32)
        with self._lock:
            self._permits[nonce] = binding
        return WritePermit(nonce)

    def execute(
        self, permit: WritePermit, *, task: str, plan_revision: str,
        operation: str, target: str, arguments: Any,
    ) -> Path:
        if not isinstance(permit, WritePermit):
            raise PermissionError("invalid permit")
        with self._lock:
            binding = self._permits.pop(permit._nonce, None)
        if binding is None:
            raise PermissionError("permit is invalid or already used")
        if operation != "write":
            raise PermissionError("unsupported operation")
        attempted = _Binding(task, plan_revision, operation, target, _digest(arguments))
        if attempted != binding:
            raise PermissionError("request does not match permit")

        relative = Path(target)
        if relative.is_absolute() or not relative.parts or any(part in (".", "..") for part in relative.parts):
            raise PermissionError("target must be a contained relative path")
        if not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "supports_dir_fd")) or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd or os.rename not in os.supports_dir_fd:
            raise PermissionError("platform lacks safe descriptor-relative filesystem operations")
        if not isinstance(arguments, dict) or set(arguments) != {"content"} or not isinstance(arguments["content"], str):
            raise ValueError("write arguments must contain only string content")

        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptors: list[int] = []
        temp_name: str | None = None
        parent_fd = os.open(self._root, directory_flags)
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

            # Replacement gives the new file the normal creation mode (0666 filtered
            # by umask); for an existing regular file preserve its permission bits,
            # matching the prior truncate-in-place behavior without following links.
            temp_name = f".gate-write-{secrets.token_hex(16)}.tmp"
            fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666, dir_fd=parent_fd)
            try:
                if existing is not None:
                    os.fchmod(fd, stat.S_IMODE(existing.st_mode))
                data = arguments["content"].encode("utf-8")
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("short write")
                    view = view[written:]
            finally:
                os.close(fd)

            os.replace(temp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
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
