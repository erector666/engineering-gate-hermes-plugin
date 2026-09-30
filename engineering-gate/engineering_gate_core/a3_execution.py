"""Gate-owned, one-shot execution for authorized single-file writes.

This constrains mutations routed through this service; it is not an OS sandbox.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
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
        destination = self._root.joinpath(relative)
        resolved = destination.resolve(strict=False)
        if not resolved.is_relative_to(self._root):
            raise PermissionError("target escapes write root")
        if destination.is_symlink():
            raise PermissionError("symlink targets are not writable")
        if not resolved.parent.is_dir():
            raise PermissionError("target parent must already exist")
        if not isinstance(arguments, dict) or set(arguments) != {"content"} or not isinstance(arguments["content"], str):
            raise ValueError("write arguments must contain only string content")

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(resolved, flags, 0o666)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
                stream.write(arguments["content"])
        except BaseException:
            # fdopen owns the descriptor once constructed.
            raise
        return resolved
