"""Observe an approved argv command. shell=False and cwd are not an OS sandbox."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
import re
import selectors
import signal
import subprocess
import sys
import time

from .models import EvidenceProvenance, ObservedCommandEvidence, TaskState, VerificationCommand, WorkspaceIdentity, _ISSUER
from .state_store import StateStoreError
from .workflow import canonical_plan_digest, capture_workspace_identity, resolve_approved_verification_commands


class CommandLaunchError(RuntimeError):
    """Approved command could not be launched; no evidence was produced."""


class WorkspaceIdentityError(RuntimeError):
    """Approved workspace no longer matches its bound identity."""


class OutputIncompleteError(RuntimeError):
    """Captured output did not reach EOF before its bounded drain deadline."""

    def __init__(self, returncode: int | None):
        self.returncode = returncode
        super().__init__(f"command output incomplete (return code {returncode})")


_SUMMARY_MAX = 512
_DRAIN_GRACE_SECONDS = 0.5
_SECRET = re.compile(r"(?i)(api[_-]?key|access[_-]?token|secret|password|token)(\s*[:=]\s*|\s+)[^\s,;]+")


def _check_workspace(identity: WorkspaceIdentity) -> None:
    try:
        canonical = os.path.realpath(identity.canonical_path)
        info = os.stat(canonical)
    except OSError as exc:
        raise WorkspaceIdentityError("approved workspace is unavailable") from exc
    if (canonical != identity.canonical_path or info.st_dev != identity.device or
            info.st_ino != identity.inode or not os.path.isdir(canonical)):
        raise WorkspaceIdentityError("approved workspace identity changed")


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _observe_verification_command(command: VerificationCommand, *, task_id: str,
                                 plan_revision: int, plan_digest: str, criterion_id: str,
                                 workspace_identity: WorkspaceIdentity) -> ObservedCommandEvidence:
    """Run resolved approved argv without a shell; cwd is not an OS sandbox."""
    if type(command) is not VerificationCommand:
        raise TypeError("command must be a resolved VerificationCommand")
    if not sys.platform.startswith("linux") or not os.path.isdir("/proc/self/fd"):
        raise CommandLaunchError("pinned workspace launch is unavailable")
    _check_workspace(workspace_identity)
    started = _utcnow()
    workspace_fd = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        workspace_fd = os.open(workspace_identity.canonical_path, flags)
        info = os.fstat(workspace_fd)
        if (info.st_dev, info.st_ino) != (workspace_identity.device, workspace_identity.inode):
            raise WorkspaceIdentityError("approved workspace identity changed")
        # The child resolves cwd through the inherited descriptor, not the mutable pathname.
        process = subprocess.Popen(command.argv, shell=False,
                                   cwd=f"/proc/self/fd/{workspace_fd}", pass_fds=(workspace_fd,),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
    except WorkspaceIdentityError:
        raise
    except (OSError, ValueError) as exc:
        raise CommandLaunchError("approved command could not be launched") from exc
    finally:
        if workspace_fd is not None:
            os.close(workspace_fd)

    hashes = [hashlib.sha256(), hashlib.sha256()]
    retained = [bytearray(), bytearray()]
    streams = (process.stdout, process.stderr)
    selector = selectors.DefaultSelector()
    eof = set()
    try:
        if any(stream is None for stream in streams):
            raise OSError("captured pipe unavailable")
        for index, stream in enumerate(streams):
            assert stream is not None
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
    except (AttributeError, OSError, ValueError, TypeError) as exc:
        selector.close()
        for stream in streams:
            stream.close()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise CommandLaunchError("nonblocking captured pipes are unavailable") from exc

    timed_out = False
    incomplete = False
    deadline = time.monotonic() + command.timeout_seconds
    drain_deadline = None
    try:
        while process.poll() is None or selector.get_map():
            now = time.monotonic()
            if not timed_out and now >= deadline:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                drain_deadline = now + _DRAIN_GRACE_SECONDS
            if timed_out and drain_deadline is not None and now >= drain_deadline:
                incomplete = bool(selector.get_map())
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                break
            wait_until = deadline if not timed_out else drain_deadline
            events = selector.select(max(0, min(0.1, wait_until - now)))
            for key, _ in events:
                stream = key.fileobj
                index = key.data
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    eof.add(index)
                    stream.close()
                    continue
                hashes[index].update(chunk)
                available = max(0, command.output_cap_bytes - len(retained[index]))
                if available:
                    retained[index].extend(chunk[:available])
        if timed_out:
            process.wait()
        else:
            process.wait()
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()
    if incomplete or len(eof) != 2:
        raise OutputIncompleteError(process.returncode)
    _check_workspace(workspace_identity)
    completed = _utcnow()
    output = (retained[0] + b"\n" + retained[1]).decode("utf-8", errors="replace")
    output = _SECRET.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", output)
    output = output[:_SUMMARY_MAX]
    return ObservedCommandEvidence._issue(_issuer=_ISSUER,
        task_id=task_id, plan_revision=plan_revision, plan_digest=plan_digest,
        criterion_id=criterion_id, argv=command.argv, workspace_identity=workspace_identity,
        started_at=started, completed_at=completed,
        exit_code=process.returncode if process.returncode is not None else -1,
        stdout_digest=hashes[0].hexdigest(), stderr_digest=hashes[1].hexdigest(),
        output_summary=output, timed_out=timed_out,
    )


class GateVerificationRunner:
    """Execute the persisted approved plan and atomically record observations.

    This local execution is NOT an OS sandbox: shell=False and cwd do not
    restrict filesystem/network access or arbitrary behavior of a command.
    """

    def __init__(self, store):
        self.store = store

    def run_all(self, task_id: str):
        """Run only currently approved Plan argv and persist all-or-nothing."""
        task = self.store.load(task_id)
        plan = task.plan
        if (task.state is not TaskState.IMPLEMENTING or plan is None
                or task.plan_digest != canonical_plan_digest(plan)
                or plan.workspace_identity is None):
            raise StateStoreError("task has no current implementing verification plan")
        request, receipt, permit = task.approval_request, task.approval, task.permit
        if (request is None or receipt is None or not receipt.approved or permit is None
                or (request.task_id, request.revision, request.digest) !=
                   (task.task_id, task.revision, task.plan_digest)
                or (receipt.task_id, receipt.revision, receipt.digest, receipt.request_id,
                    receipt.requester) != (task.task_id, task.revision, task.plan_digest,
                                           request.request_id, task.task.requester)
                or permit.task_id != task.task_id or permit.revision != task.revision
                or permit.digest != task.plan_digest):
            raise StateStoreError("task does not have current approval and permit bindings")
        try:
            current_workspace = capture_workspace_identity(plan.workspace_root)
        except (OSError, ValueError) as exc:
            raise WorkspaceIdentityError("approved workspace is unavailable") from exc
        if current_workspace != plan.workspace_identity:
            raise WorkspaceIdentityError("approved workspace identity changed")
        criteria = tuple(c.criterion_id for c in plan.acceptance_criteria)
        covered = {cid for command in plan.verification_commands for cid in command.criterion_ids}
        if not criteria or covered != set(criteria):
            raise ValueError("approved commands must cover every acceptance criterion")
        commands = resolve_approved_verification_commands(plan, criteria)
        observations = []
        for command in commands:
            for criterion_id in command.criterion_ids:
                observations.append(_observe_verification_command(
                    command, task_id=str(task.task_id), plan_revision=int(task.revision),
                    plan_digest=task.plan_digest, criterion_id=criterion_id,
                    workspace_identity=plan.workspace_identity))
        return self.store._record_gate_verification(
            task_id, expected_revision=task.revision,
            expected_plan_digest=task.plan_digest, observations=tuple(observations))
