"""
Engineering Gate v3.2 — Per-Task Workflow Enforcement Plugin.

Enforces per-task gating at tool dispatch time:

  THINK → READ → PLAN → ADVERSARIAL JUDGE → BUILD → VERIFY (judge, up to 5x) → HANDOFF

Each NEW CONVERSATION TURN starts with the gate CLOSED.
The adversarial judge must pass BEFORE any write/build tool is allowed
in that turn.  Once the judge passes for a turn, all writes/builds within
that turn are permitted.  The NEXT user turn auto-closes the turn.

Turn detection: uses the ``turn_id`` from the pre_tool_call kwargs.
Session boundary: uses ``on_session_start`` to reset on /new or first boot.

State is tracked in ~/.hermes/engineering-gate-state.json.

v3.2 enhancements:
  - Pre-build adversarial judge (gate approval before writes)
  - Post-build verification judge (up to 5 correction loops)
  - Permanent block after 5 failed verification attempts
  - Stuck agent detection (tool call history buffer, repeat/stall patterns)
  - Concurrent file-write prevention (per-session file locks, 1h auto-expiry)
  - Evidence classification (post_tool_call evidence tracking + pre-mutation check)
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import textwrap
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── State file ──────────────────────────────────────────────────────────────
STATE_FILE = os.path.expanduser("~/.hermes/engineering-gate-state.json")

# ── Tools we gate ───────────────────────────────────────────────────────────
GATED_WRITE_TOOLS = frozenset({"write_file", "patch", "skill_manage"})
GATED_TERMINAL_TOOLS = frozenset({"terminal"})

# Terminal commands that are READ-ONLY and always allowed
READONLY_COMMAND_PATTERNS = (
    re.compile(r"^\s*(ls|cat|head|tail|less|more|echo|pwd|which|file|stat|du|df|wc)\b"),
    re.compile(r"^\s*(grep|rg|ag|find|locate|tree)\b"),
    re.compile(r"^\s*(git\s+(status|diff|log|show|branch|remote|ls-files|stash\s+list))\b"),
    re.compile(r"^\s*(npm\s+(list|view|search|why))\b"),
    re.compile(r"^\s*(pip\s+(list|show|search))\b"),
    re.compile(r"^\s*(npx\s+(tsc|prettier|eslint)\s+--(noEmit|check))\b"),
    re.compile(r"^\s*(docker\s+(ps|images|logs|inspect))\b"),
    re.compile(r"^\s*(ps|top|htop|free|uptime|uname|env|printenv|date)\b"),
    re.compile(r"^\s*(python3?\s+(-[cm]|--version|setup\.py))\b"),
    re.compile(r"^\s*(cat\s+.*/engineering-gate-state\.json)\b"),
    re.compile(r"^\s*(rtk\b)"),
)

# Build/write commands that ARE gated
BUILD_COMMAND_PATTERNS = (
    re.compile(r"\bnpm\s+(run|install|ci|add|update|audit|rebuild)\b", re.I),
    re.compile(r"\byarn\s+\b", re.I),
    re.compile(r"\bpnpm\s+\b", re.I),
    re.compile(r"\bgit\s+(commit|push|add|merge|rebase|checkout\s+-b|tag)\b"),
    re.compile(r"\bvercel\b", re.I),
    re.compile(r"\bfirebase\s+deploy\b", re.I),
    re.compile(r"\bdocker\s+(build|compose\s+up|push|tag|run)\b", re.I),
    re.compile(r"\bprisma\s+(generate|push|migrate|deploy)\b", re.I),
    re.compile(r"\bsupabase\s+(start|stop|deploy|functions\s+deploy)\b", re.I),
    re.compile(r"\bdeploy\b", re.I),
    re.compile(r"\bprettier\b.*--write\b", re.I),
)

# ── Infrastructure / docs paths — always allowed ───────────────────────────
HERMES_HOME = os.path.expanduser("~/.hermes")
SAFE_PATH_PREFIXES = (HERMES_HOME,)
SAFE_FILE_EXTENSIONS = frozenset({".md", ".txt", ".log", ".json", ".yaml", ".yml"})

# ── Stuck Detection constants ───────────────────────────────────────────────
STUCK_SAME_CALL_THRESHOLD = 3
STUCK_PHASE_STALL_THRESHOLD = 8

# ── File lock constants ─────────────────────────────────────────────────────
FILE_LOCK_MAX_AGE_HOURS = 1

# ── Judge integration ──────────────────────────────────────────────────────
JUDGE_CRITERIA = [
    "correctness",
    "empty states",
    "permissions",
    "error handling",
    "write-path integrity",
    "type safety",
]
JUDGE_TIMEOUT = 120  # seconds


def _build_judge_query(task_label: str, tool_name: str, target: str, command: str = "") -> str:
    """Build an adversarial judge query from the blocked tool context."""
    lines = [f"Task: {task_label or 'Unknown task'}"]
    lines.append(f"Tool: {tool_name}")
    if target:
        lines.append(f"Files: {target}")
    if command:
        lines.append(f"Command: {command[:200]}")
    lines.append("")
    lines.append("Criteria:")
    for c in JUDGE_CRITERIA:
        lines.append(f"- {c}")
    lines.append("")
    lines.append("Review the files listed above. Do NOT trust any summary — read every file yourself.")
    lines.append("Return a structured JSON verdict with keys: verdict (APPROVED|REJECTED|NEEDS_CLARIFICATION), reason, evidence, missingAuthority, forbiddenActions.")
    return "\n".join(lines)


def _parse_judge_verdict(output: str) -> dict:
    """Extract structured verdict from judge output, trying JSON first, then text fallback."""
    json_match = re.search(r'\{[\s\S]*?"verdict"\s*:\s*"(APPROVED|REJECTED|NEEDS_CLARIFICATION)"[\s\S]*?\}', output)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    if "APPROVED" in output:
        return {"verdict": "APPROVED", "reason": "Approved (text fallback — no structured JSON)", "evidence": []}
    if "REJECTED" in output:
        return {"verdict": "REJECTED", "reason": "Rejected (text fallback — no structured JSON)", "evidence": []}
    return {"verdict": "NEEDS_CLARIFICATION", "reason": "Could not parse judge verdict from output", "evidence": []}


def _invoke_judge(query: str) -> dict:
    """Run the judge profile and return the parsed verdict."""
    try:
        result = subprocess.run(
            ["hermes", "-p", "judge", "chat", "-q", query, "-Q"],
            capture_output=True, text=True, timeout=JUDGE_TIMEOUT,
        )
        logger.info(
            "Engineering Gate: judge exited code=%d stdout=%dchars stderr=%dchars",
            result.returncode, len(result.stdout or ""), len(result.stderr or ""),
        )
        return _parse_judge_verdict(result.stdout or "")
    except subprocess.TimeoutExpired:
        logger.warning("Engineering Gate: judge timed out (%ds)", JUDGE_TIMEOUT)
        return {"verdict": "NEEDS_CLARIFICATION", "reason": f"Judge timed out after {JUDGE_TIMEOUT}s", "evidence": []}
    except FileNotFoundError:
        logger.error("Engineering Gate: judge binary not found — run `hermes profile alias judge`")
        return {"verdict": "REJECTED", "reason": "Judge profile or Hermes CLI not accessible. Ensure Hermes is installed.", "evidence": []}
    except Exception as e:
        logger.error("Engineering Gate: judge invocation error: %s", e)
        return {"verdict": "NEEDS_CLARIFICATION", "reason": f"Judge error: {e}", "evidence": []}


# ── State management ────────────────────────────────────────────────────────

DEFAULT_STATE = {
    "phase": "idle",
    "judge_passed": False,
    "last_gated_turn": "",
    "task": "",
    "timestamp": "",
    "tool_call_history": [],
    "file_locks": {},
    "evidence_log": [],
    # Post-build verification state
    "verify_loop_count": 0,
    "verify_passed": True,
    "verify_findings": "",
    "verify_permanent_fail": False,
    "verify_tool_turn": "",
}


def _evolve_state(state: dict) -> dict:
    """Ensure state dict has all keys from DEFAULT_STATE, adding missing ones."""
    for key, default_val in DEFAULT_STATE.items():
        if key not in state:
            state[key] = default_val
    return state


def _read_state() -> dict:
    """Read the current gate state."""
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
                state = _evolve_state(state)
                return state
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Engineering Gate: failed to read state: %s", e)
    return dict(DEFAULT_STATE)


def _write_state(state: dict) -> None:
    """Write gate state atomically."""
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_FILE)
    except OSError as e:
        logger.warning("Engineering Gate: failed to write state: %s", e)


def _reset_gate(task_label: str = "") -> None:
    """Set judge_passed=False and record a new task scope.

    Preserves file_locks (cross-task), resets tool_call_history and evidence_log.
    """
    state = _read_state()
    state["phase"] = "idle"
    state["judge_passed"] = False
    state["last_gated_turn"] = ""
    state["task"] = task_label
    state["timestamp"] = datetime.now(timezone.utc).isoformat()
    state["tool_call_history"] = []
    state["evidence_log"] = []
    state["verify_loop_count"] = 0
    state["verify_passed"] = True
    state["verify_findings"] = ""
    state["verify_permanent_fail"] = False
    state["verify_tool_turn"] = ""
    # Preserve file_locks across resets
    _auto_release_expired_locks(state)
    _write_state(state)
    logger.info("Engineering Gate: reset (closed) — task=%s", task_label or "(unnamed)")


def _open_gate(turn_id: str, task_label: str = "") -> None:
    """Set judge_passed=True for the given turn."""
    state = _read_state()
    state["phase"] = "executing"
    state["judge_passed"] = True
    state["last_gated_turn"] = turn_id
    if task_label:
        state["task"] = task_label
    state["timestamp"] = datetime.now(timezone.utc).isoformat()
    # Don't reset verification state here — it persists across the turn
    _write_state(state)
    logger.info("Engineering Gate: opened for turn=%s", turn_id)


def _is_infra_path(path: str) -> bool:
    """Check if path is infrastructure/docs — always allowed."""
    resolved = os.path.abspath(os.path.expanduser(path))
    for prefix in SAFE_PATH_PREFIXES:
        if resolved.startswith(prefix):
            return True
    ext = os.path.splitext(path)[1].lower()
    if ext in SAFE_FILE_EXTENSIONS:
        return True
    return False


def _is_readonly_command(command: str) -> bool:
    """Check if a terminal command is read-only (always allowed)."""
    for pattern in READONLY_COMMAND_PATTERNS:
        if pattern.match(command.strip()):
            return True
    return False


def _is_build_command(command: str) -> bool:
    """Check if a terminal command is a build/write operation."""
    for pattern in BUILD_COMMAND_PATTERNS:
        if pattern.search(command):
            return True
    return False


def _verify_background_workdir(args: dict, turn_id: str) -> Optional[Dict[str, str]]:
    """Special handling for background terminal commands — always check workdir for project files."""
    workdir = args.get("workdir", "")
    if workdir:
        state = _read_state()
        gated_turn = state.get("last_gated_turn", "")
        if turn_id != gated_turn:
            _reset_gate("background-task")
        if not state.get("judge_passed", False):
            # Invoke judge automatically
            command = args.get("command", "")
            judge_query = _build_judge_query(
                state.get("task", "background-task"), "terminal", workdir, command
            )
            judge_verdict = _invoke_judge(judge_query)

            if judge_verdict.get("verdict") == "APPROVED":
                _open_gate(turn_id, state.get("task", "background-task"))
                logger.info(
                    "Engineering Gate: judge APPROVED — bg gate opened for turn=%s", turn_id
                )
                return None  # Gate now open — allow
            else:
                evidence_lines = []
                for e in judge_verdict.get("evidence", []):
                    file_str = e.get("file", "?")
                    line_str = e.get("line", "?")
                    finding = e.get("finding", "")
                    evidence_lines.append(f"- `{file_str}:{line_str}` — {finding}")
                evidence_text = "\n".join(evidence_lines) if evidence_lines else "No specific evidence cited."

                return {
                    "action": "block",
                    "message": (
                        "🚫 **Engineering Gate — Judge Rejected**\n\n"
                        f"**Verdict:** {judge_verdict.get('verdict', 'REJECTED')}\n"
                        f"**Reason:** {judge_verdict.get('reason', 'No reason given')}\n\n"
                        f"**Evidence:**\n{evidence_text}\n\n"
                        f"**Command:** `{command[:200]}`\n\n"
                        "Fix the issues based on the judge's findings and retry."
                    ),
                }
    return None


# ── Stuck Agent Detection ───────────────────────────────────────────────────

def _record_tool_call(state: dict, tool_name: str, args: Any, turn_id: str) -> None:
    """Add an entry to the tool_call_history buffer."""
    target = ""
    if isinstance(args, dict):
        if tool_name in GATED_WRITE_TOOLS:
            target = args.get("path", "") or args.get("file_path", "") or ""
        elif tool_name == "terminal":
            target = (args.get("command", "") or "")[:80]

    entry = {
        "tool": tool_name,
        "target": target,
        "turn_id": turn_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    state["tool_call_history"].append(entry)
    logger.info(
        "Engineering Gate: recorded tool call #%d — %s target=%s turn=%s",
        len(state["tool_call_history"]), tool_name,
        target[:60] if target else "(none)", turn_id[:12] if turn_id else "(none)",
    )


def _check_stuck(state: dict, tool_name: str, args: Any, turn_id: str) -> Optional[str]:
    """Check for stuck agent patterns. Returns 'stuck_repeat', 'stuck_phase_stall', or None."""
    history = state.get("tool_call_history", [])

    target = ""
    if isinstance(args, dict):
        if tool_name in GATED_WRITE_TOOLS:
            target = args.get("path", "") or args.get("file_path", "") or ""
        elif tool_name == "terminal":
            target = (args.get("command", "") or "")[:80]

    # Count repeats of same tool+target in this turn
    if target:
        same_calls = [
            h for h in history
            if h.get("tool") == tool_name
            and h.get("target") == target
            and h.get("turn_id") == turn_id
        ]
        # -1 because we haven't added this call yet
        if len(same_calls) >= STUCK_SAME_CALL_THRESHOLD - 1:
            logger.warning(
                "Engineering Gate: STUCK REPEAT — %s on %s (%d repeats in turn %s)",
                tool_name, target, len(same_calls) + 1, turn_id,
            )
            return "stuck_repeat"

    # Check phase stall — no phase change events for many calls
    phase_starts = [
        h for h in history
        if h.get("event") == "phase_change" and h.get("turn_id") == turn_id
    ]
    if not phase_starts:
        calls_since_phase = len([h for h in history if h.get("turn_id") == turn_id])
        if calls_since_phase >= STUCK_PHASE_STALL_THRESHOLD:
            logger.warning(
                "Engineering Gate: STUCK PHASE STALL — %d calls in turn %s with no phase change",
                calls_since_phase, turn_id,
            )
            return "stuck_phase_stall"

    return None


def _add_phase_change_event(state: dict, phase: str, turn_id: str) -> None:
    """Record a phase change in the tool_call_history for stall detection."""
    state["tool_call_history"].append({
        "event": "phase_change",
        "phase": phase,
        "turn_id": turn_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ── Concurrent File-Write Prevention ────────────────────────────────────────

def _auto_release_expired_locks(state: dict) -> None:
    """Release file locks older than FILE_LOCK_MAX_AGE_HOURS."""
    now = datetime.now(timezone.utc)
    expired = []
    for path, lock_info in state.get("file_locks", {}).items():
        lock_time_str = lock_info.get("locked_at", "")
        try:
            lock_time = datetime.fromisoformat(lock_time_str)
            if now - lock_time > timedelta(hours=FILE_LOCK_MAX_AGE_HOURS):
                expired.append(path)
                logger.info(
                    "Engineering Gate: auto-releasing expired lock on %s (locked %s)",
                    path, lock_time_str,
                )
        except (ValueError, TypeError):
            expired.append(path)
    for path in expired:
        del state["file_locks"][path]


def _check_file_lock(path: str, session_id: str) -> Optional[Dict[str, str]]:
    """Check if a file is locked by a different session. Returns block dict or None."""
    if not path or not session_id:
        return None

    state = _read_state()
    _auto_release_expired_locks(state)
    _write_state(state)

    file_locks = state.get("file_locks", {})
    resolved = os.path.abspath(os.path.expanduser(path))

    if resolved in file_locks:
        lock_info = file_locks[resolved]
        lock_session = lock_info.get("session_id", "")
        if lock_session and lock_session != session_id:
            logger.warning(
                "Engineering Gate: FILE LOCKED — %s locked by session %s, requested by %s",
                resolved, lock_session[:12], session_id[:12],
            )
            return {
                "action": "block",
                "message": (
                    "🔒 **Engineering Gate** — file locked by another session.\n\n"
                    f"File: `{path}`\n"
                    f"Locked by session: `{lock_session[:12]}...`\n"
                    f"Locked at: {lock_info.get('locked_at', 'unknown')}\n\n"
                    "Wait for the other session to finish, or the lock will auto-expire after "
                    f"{FILE_LOCK_MAX_AGE_HOURS} hour."
                ),
            }

    return None


def _lock_file(path: str, session_id: str) -> None:
    """Lock a file after a successful write."""
    if not path or not session_id:
        return

    state = _read_state()
    resolved = os.path.abspath(os.path.expanduser(path))

    # Don't lock infra paths
    if _is_infra_path(path):
        return

    now = datetime.now(timezone.utc)
    state["file_locks"][resolved] = {
        "session_id": session_id,
        "locked_at": now.isoformat(),
        "path": path,
    }
    _write_state(state)
    logger.info(
        "Engineering Gate: locked file %s for session %s",
        resolved, session_id[:12],
    )


def _release_session_locks(session_id: str) -> None:
    """Release all file locks held by a given session."""
    if not session_id:
        return

    state = _read_state()
    released = []
    for path, lock_info in list(state.get("file_locks", {}).items()):
        if lock_info.get("session_id") == session_id:
            del state["file_locks"][path]
            released.append(path)

    if released:
        _write_state(state)
        logger.info(
            "Engineering Gate: released %d file lock(s) for session %s",
            len(released), session_id[:12],
        )


# ── Evidence Classification ─────────────────────────────────────────────────

def _classify_evidence(tool_name: str, args: Any, result: Any) -> str:
    """Classify the evidence type from a tool call's result.

    Returns one of: EXECUTION, INSPECTION, SIMULATION, OPINION
    """
    result_str = str(result or "")

    # EXECUTION: has diffs, test output, file stats, build output
    if any(marker in result_str for marker in [
        "diff --git", "PASS", "FAIL", "total_lines", "exit_code",
    ]):
        return "EXECUTION"

    # INSPECTION: file reads, content searches, browsing
    if tool_name in (
        "read_file", "search_files",
        "browser_navigate", "browser_snapshot",
    ):
        return "INSPECTION"

    # SIMULATION: has mock/stub/test double references
    if any(marker in result_str for marker in ["mock", "stub", "fake", "SIMULATED"]):
        return "SIMULATION"

    # OPINION: everything else (model-generated claims)
    return "OPINION"


def _get_path_from_args(tool_name: str, args: Any) -> str:
    """Extract the target path from tool args."""
    if not isinstance(args, dict):
        return ""
    if tool_name in GATED_WRITE_TOOLS:
        return args.get("path", "") or args.get("file_path", "") or ""
    return ""


def _add_evidence(
    state: dict,
    tool_name: str,
    args: Any,
    result: Any,
    turn_id: str,
) -> None:
    """Classify and record evidence from a tool call."""
    evidence_type = _classify_evidence(tool_name, args, result)
    path = _get_path_from_args(tool_name, args)
    is_build = False
    if tool_name == "terminal" and isinstance(args, dict):
        is_build = _is_build_command(args.get("command", ""))

    entry = {
        "tool": tool_name,
        "path": path,
        "evidence_type": evidence_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "turn_id": turn_id,
        "is_build": is_build,
    }
    state.setdefault("evidence_log", []).append(entry)
    logger.info(
        "Engineering Gate: evidence recorded — %s on %s → %s",
        tool_name, path or "(none)", evidence_type,
    )


def _check_prior_evidence(
    state: dict,
    tool_name: str,
    args: Any,
) -> Optional[Dict[str, str]]:
    """Check if the prior mutation has sufficient evidence before allowing another.

    Looks at the evidence_log: if the most recent entry is from a mutation tool
    and no inspection/execution evidence has been gathered since, block.
    """
    evidence_log = state.get("evidence_log", [])
    if not evidence_log:
        return None  # First mutation — no prior evidence needed

    # Find the last mutation in the log
    last_mutation_idx = None
    for i in range(len(evidence_log) - 1, -1, -1):
        entry = evidence_log[i]
        entry_tool = entry.get("tool", "")
        if entry_tool in GATED_WRITE_TOOLS or (
            entry_tool == "terminal" and entry.get("is_build", False)
        ):
            last_mutation_idx = i
            break

    if last_mutation_idx is None:
        return None  # No prior mutation, allow

    # Check if there's at least INSPECTION-level evidence AFTER the last mutation
    has_subsequent_evidence = False
    for i in range(last_mutation_idx + 1, len(evidence_log)):
        entry = evidence_log[i]
        if entry.get("evidence_type") in ("INSPECTION", "EXECUTION"):
            has_subsequent_evidence = True
            break

    if not has_subsequent_evidence:
        logger.warning(
            "Engineering Gate: EVIDENCE GAP — no inspection/execution evidence after "
            "last mutation (entry #%d)",
            last_mutation_idx,
        )
        return {
            "action": "block",
            "message": (
                "🚫 **Engineering Gate** — provide evidence first.\n\n"
                "The last mutation has no subsequent evidence (inspection or execution). "
                "Read a file, run a test, or verify output before making another change."
            ),
        }

    return None


# ── Hook handlers ───────────────────────────────────────────────────────────


def on_session_start(
    session_id: str = "",
    model: str = "",
    platform: str = "",
    **kwargs: Any,
) -> None:
    """Reset the gate on every new session (/new or first boot)."""
    _reset_gate(f"new-session-{session_id[:12]}")
    logger.info(
        "Engineering Gate: session start — gate closed (session=%s, model=%s, platform=%s)",
        session_id[:12], model, platform,
    )


def on_session_end(
    session_id: str = "",
    **kwargs: Any,
) -> None:
    """Release all file locks held by this session when it ends."""
    if session_id:
        _release_session_locks(session_id)
        logger.info(
            "Engineering Gate: session end — locks released (session=%s)",
            session_id[:12],
        )


def pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    **kwargs: Any,
) -> Optional[Dict[str, str]]:
    """
    Engineering Gate v3.1 pre-tool-call handler.

    Returns None (allow) or {"action": "block", "message": "..."} (block).

    Per-turn enforcement: if turn_id has changed since judge approved,
    the gate auto-closes for the new turn.

    v3.1 additions:
      - Stuck agent detection (repeat calls, phase stall)
      - File lock checks (concurrent write prevention)
      - Prior evidence check (must inspect after mutation)
    """

    # ── Always allow inspection tools ───────────────────────────────────
    ALWAYS_ALLOWED_TOOLS = frozenset({
        "read_file", "search_files", "browser_navigate", "browser_snapshot",
        "browser_click", "browser_type", "browser_scroll", "browser_vision",
        "browser_console", "browser_get_images", "browser_back", "browser_press",
        "web_search", "web_extract", "vision_analyze",
        "delegate_task", "session_search", "execute_code",
    })
    if tool_name in ALWAYS_ALLOWED_TOOLS:
        return None

    # ── Extract turn_id from kwargs ─────────────────────────────────────
    turn_id = kwargs.get("turn_id", "") or kwargs.get("task_id", "") or ""

    # ── Read current gate state ─────────────────────────────────────────
    state = _read_state()
    judge_passed = state.get("judge_passed", False)
    current_phase = state.get("phase", "idle")
    last_gated_turn = state.get("last_gated_turn", "")

    # ── Auto-close on turn change ──────────────────────────────────────
    if judge_passed and turn_id and last_gated_turn and turn_id != last_gated_turn:
        logger.info(
            "Engineering Gate: turn changed (%s → %s) — auto-closing",
            last_gated_turn, turn_id,
        )
        _reset_gate(state.get("task", ""))
        # Re-read state after reset to get fresh tool_call_history etc.
        state = _read_state()
        judge_passed = False
        current_phase = "idle"

    # ── Record tool call for stuck detection ────────────────────────────
    _record_tool_call(state, tool_name, args, turn_id)

    # ── write_file / patch / skill_manage ───────────────────────────────
    if tool_name in GATED_WRITE_TOOLS:
        if not isinstance(args, dict):
            _write_state(state)
            return None

        path = args.get("path") or args.get("file_path") or ""
        if path and _is_infra_path(path):
            _write_state(state)
            return None  # Infrastructure/docs — always allow

        # ── Stuck agent detection ──────────────────────────────────
        stuck_reason = _check_stuck(state, tool_name, args, turn_id)
        if stuck_reason:
            logger.warning(
                "Engineering Gate: BLOCKING stuck agent — reason=%s tool=%s target=%s",
                stuck_reason, tool_name, path,
            )
            # Reset history after blocking stuck to break the loop
            state["tool_call_history"] = []
            _write_state(state)
            return {
                "action": "block",
                "message": (
                    "🤖 **Engineering Gate — Stuck Agent Detected**\n\n"
                    f"Reason: `{stuck_reason}`\n"
                    f"Tool: `{tool_name}` on target `{path or '(none)'}`\n\n"
                    "The same operation has been attempted repeatedly. "
                    "Stop and reassess your approach. Consider:\n"
                    "1. Reading relevant files to understand the current state\n"
                    "2. Breaking the task into smaller steps\n"
                    "3. Trying a different approach or tool\n"
                    "4. Asking the user for clarification if stuck"
                ),
            }

        # ── File lock check ────────────────────────────────────────
        session_id = kwargs.get("session_id", "") or ""
        lock_block = _check_file_lock(path, session_id)
        if lock_block is not None:
            _write_state(state)
            return lock_block

        # ── Evidence check — was there inspection after last mutation? ─
        evidence_block = _check_prior_evidence(state, tool_name, args)
        if evidence_block is not None:
            _write_state(state)
            return evidence_block

        # ── Post-build verification loop check ─────────────────────────
        if state.get("verify_permanent_fail", False):
            _write_state(state)
            return {
                "action": "block",
                "message": (
                    "🔴 **Engineering Gate — Verification Failed Permanently**\n\n"
                    "The adversarial judge rejected the build output 5 times with no passing verification.\n"
                    f"**Last findings:** {state.get('verify_findings', 'N/A')}\n\n"
                    "**Report this to the Captain.** Do not continue without explicit approval."
                ),
            }

        if not state.get("verify_passed", True) and state.get("verify_tool_turn") == turn_id:
            _write_state(state)
            return {
                "action": "block",
                "message": (
                    "🔄 **Engineering Gate — Build Failed Verification**\n\n"
                    f"**Loop {state.get('verify_loop_count', 1)}/5**\n"
                    f"**Judge's findings:**\n{state.get('verify_findings', 'No details')}\n\n"
                    "Fix the issues above and retry the build."
                ),
            }

        if judge_passed and current_phase in ("executing", "verifying", "complete"):
            _write_state(state)
            return None  # Gate is open for this turn

        # ── Invoke the adversarial judge ──────────────────────────────
        judge_query = _build_judge_query(state.get("task", ""), tool_name, path)
        judge_verdict = _invoke_judge(judge_query)

        if judge_verdict.get("verdict") == "APPROVED":
            _open_gate(turn_id, state.get("task", ""))
            _write_state(state)
            logger.info("Engineering Gate: judge APPROVED — gate opened for turn=%s", turn_id)
            return None  # Gate now open — allow tool to proceed

        # Build block message from judge's reasoning
        evidence_lines = []
        for e in judge_verdict.get("evidence", []):
            file_str = e.get("file", "?")
            line_str = e.get("line", "?")
            finding = e.get("finding", "")
            evidence_lines.append(f"- `{file_str}:{line_str}` — {finding}")
        evidence_text = "\n".join(evidence_lines) if evidence_lines else "No specific evidence cited."

        _write_state(state)
        return {
            "action": "block",
            "message": (
                "🚫 **Engineering Gate — Judge Rejected**\n\n"
                f"**Verdict:** {judge_verdict.get('verdict', 'REJECTED')}\n"
                f"**Reason:** {judge_verdict.get('reason', 'No reason given')}\n\n"
                f"**Evidence:**\n{evidence_text}\n\n"
                f"**Target:** `{tool_name}` on `{path}`\n\n"
                "Fix the issues based on the judge's findings and retry."
            ),
        }

    # ── terminal ────────────────────────────────────────────────────────
    if tool_name in GATED_TERMINAL_TOOLS:
        if not isinstance(args, dict):
            _write_state(state)
            return None

        command = args.get("command", "")

        # Read-only commands are always allowed
        if _is_readonly_command(command):
            _write_state(state)
            return None

        # ── Stuck agent detection for terminal builds ────────────────
        if _is_build_command(command):
            stuck_reason = _check_stuck(state, tool_name, args, turn_id)
            if stuck_reason:
                logger.warning(
                    "Engineering Gate: BLOCKING stuck agent — reason=%s tool=%s",
                    stuck_reason, tool_name,
                )
                state["tool_call_history"] = []
                _write_state(state)
                return {
                    "action": "block",
                    "message": (
                        "🤖 **Engineering Gate — Stuck Agent Detected**\n\n"
                        f"Reason: `{stuck_reason}`\n"
                        f"Command: `{command[:120]}`\n\n"
                        "The same operation has been attempted repeatedly. "
                        "Stop and reassess your approach."
                    ),
                }

            # ── Evidence check for build commands ──────────────────
            evidence_block = _check_prior_evidence(state, tool_name, args)
            if evidence_block is not None:
                _write_state(state)
                return evidence_block

        # Background with workdir — check gate
        bg_result = _verify_background_workdir(args, turn_id)
        if bg_result is not None:
            _write_state(state)
            return bg_result

        # Build commands require the gate
        if _is_build_command(command):
            if judge_passed and current_phase in ("executing", "verifying", "complete"):
                _write_state(state)
                return None  # Gate is open for this turn

            # ── Invoke the adversarial judge ──────────────────────────
            target_path = args.get("workdir", "") or ""
            judge_query = _build_judge_query(state.get("task", ""), "terminal", target_path, command)
            judge_verdict = _invoke_judge(judge_query)

            if judge_verdict.get("verdict") == "APPROVED":
                _open_gate(turn_id, state.get("task", ""))
                _write_state(state)
                logger.info("Engineering Gate: judge APPROVED — gate opened for turn=%s", turn_id)
                return None  # Gate now open — allow tool to proceed

            evidence_lines = []
            for e in judge_verdict.get("evidence", []):
                file_str = e.get("file", "?")
                line_str = e.get("line", "?")
                finding = e.get("finding", "")
                evidence_lines.append(f"- `{file_str}:{line_str}` — {finding}")
            evidence_text = "\n".join(evidence_lines) if evidence_lines else "No specific evidence cited."

            _write_state(state)
            return {
                "action": "block",
                "message": (
                    "🚫 **Engineering Gate — Judge Rejected**\n\n"
                    f"**Verdict:** {judge_verdict.get('verdict', 'REJECTED')}\n"
                    f"**Reason:** {judge_verdict.get('reason', 'No reason given')}\n\n"
                    f"**Evidence:**\n{evidence_text}\n\n"
                    f"**Command:** `{command[:200]}`\n\n"
                    "Fix the issues based on the judge's findings and retry."
                ),
            }

        # Non-build, non-readonly terminal commands — allow
        _write_state(state)
        return None

    # ── Everything else ─────────────────────────────────────────────────
    _write_state(state)
    return None


def post_tool_call(
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    **kwargs: Any,
) -> None:
    """Observer hook — records evidence AND runs verification judge.

    After every write/build tool completes, runs the adversarial judge
    to verify the output against 6 criteria. If verification fails,
    increments a loop counter and blocks subsequent writes with the
    judge's corrections. After 5 loops, permanently blocks.
    """
    should_record = tool_name in GATED_WRITE_TOOLS
    if tool_name == "terminal" and isinstance(args, dict):
        should_record = _is_build_command(args.get("command", ""))

    if not should_record:
        return

    turn_id = kwargs.get("turn_id", "") or kwargs.get("task_id", "") or ""
    state = _read_state()
    _add_evidence(state, tool_name, args, result, turn_id)

    # ── Run verification judge ──────────────────────────────────────
    path = _get_path_from_args(tool_name, args) or args.get("workdir", "")
    command = args.get("command", "") if isinstance(args, dict) else ""
    
    result_str = str(result or "")
    # Build a verification query that includes the build output
    judge_query = _build_judge_query(
        state.get("task", ""), f"{tool_name} (verification)", path, command
    )
    judge_query += "\n\n### BUILD OUTPUT\n"
    judge_query += result_str[:2000]
    judge_query += "\n\n### TASK\n"
    judge_query += state.get("task", "Unknown task")
    judge_query += "\n\nVerify the BUILD OUTPUT against the TASK and all criteria. "
    judge_query += "If rejected, provide specific corrections."

    judge_verdict = _invoke_judge(judge_query)
    verdict = judge_verdict.get("verdict", "NEEDS_CLARIFICATION")
    reason = judge_verdict.get("reason", "")
    findings = reason or judge_verdict.get("evidence", [])

    if verdict == "APPROVED":
        state["verify_passed"] = True
        state["verify_findings"] = ""
        state["verify_loop_count"] = 0
        logger.info(
            "Engineering Gate: VERIFICATION PASSED — tool=%s path=%s",
            tool_name, path,
        )
    else:
        loop = state.get("verify_loop_count", 0) + 1
        state["verify_loop_count"] = loop
        state["verify_passed"] = False
        state["verify_findings"] = str(findings)[:2000]
        state["verify_tool_turn"] = turn_id

        if loop >= 5:
            state["verify_permanent_fail"] = True
            logger.error(
                "Engineering Gate: VERIFICATION FAILED PERMANENTLY — %d loops tool=%s",
                loop, tool_name,
            )
        else:
            logger.warning(
                "Engineering Gate: VERIFICATION FAILED — loop %d/5 tool=%s",
                loop, tool_name,
            )

    state.setdefault("last_verdict", {})
    state["last_verdict"] = {
        "tool": tool_name,
        "path": path,
        "verdict": verdict,
        "reason": reason,
        "findings": str(findings)[:500],
        "loop": state.get("verify_loop_count", 0),
        "turn_id": turn_id,
    }
    _write_state(state)


# ── Plugin registration ─────────────────────────────────────────────────────

def register(ctx) -> None:
    """Register the engineering-gate v3.1 hooks."""
    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("on_session_end", on_session_end)
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    logger.info(
        "Engineering Gate v3.1: hooks registered — "
        "on_session_start + on_session_end + pre_tool_call + post_tool_call"
    )
