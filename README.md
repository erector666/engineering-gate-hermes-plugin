# Engineering Gate Hermes Plugin

Enforces the **THINK → READ → PLAN → ADVERSARIAL JUDGE → EXECUTE → VERIFY → HANDOFF** workflow at the tool dispatch level inside Hermes Agent.

Blocks `write_file`, `patch`, `skill_manage`, and build commands (`npm install`, `git push`, `docker build`, `vercel deploy`, etc.) unless the adversarial judge step has passed for the current turn. Inspection tools (`read_file`, `search_files`, `web_search`, browser, delegation) are always allowed.

## Features

- **Per-turn gating** — gate auto-closes on every new user message. Each turn starts clean.
- **Stuck agent detection** — blocks after 3+ identical tool calls in one turn, or 8+ calls with no phase change. Prevents loops.
- **Evidence enforcement** — blocks a second mutation until verification evidence exists (inspection or execution output). Enforces VERIFY before the next change.
- **Concurrent file-lock prevention** — prevents cross-session file conflicts with 1-hour auto-expiry.
- **Infra path passthrough** — `~/.hermes/`, `.md`/`.txt`/`.log` files always writable without gate.
- **Read-only terminal passthrough** — `ls`, `git status`, `grep`, `find`, `du`, `df`, `pip list`, etc. always allowed.

## How It Works

The plugin registers 4 Hermes lifecycle hooks:

| Hook | Phase | Role |
|------|-------|------|
| `on_session_start` | Session boot | Close gate, reset state |
| `pre_tool_call` | Before every tool | Block or allow based on gate state + stuck/evidence checks |
| `post_tool_call` | After every tool | Classify and record evidence type (EXECUTION / INSPECTION / SIMULATION / OPINION) |
| `on_session_end` | Session shutdown | Release all file locks held by that session |

**The flow:**

```
User sends message
  → Gate CLOSES (new turn)
  → Agent may inspect freely (read_file, search_files, web_search, etc.)
  → Agent must pass adversarial judge to open the gate
  → Judge returns PASS → Gate OPENS for this turn
  → Agent may write files, run builds, mutate code
  → After each mutation, post_tool_call records evidence
  → Next mutation checks: was there verification after the last one?
  → If no → blocked with "provide evidence first"
  → Next user message → Gate CLOSES again
```

### Stuck Detection

| Pattern | Threshold | What triggers it |
|---------|-----------|-----------------|
| Same tool + same target | 3 calls | Same write_file path or command repeated |
| Phase stall | 8 calls | No phase_change event logged between tool calls |

When stuck is detected, the tool call history resets to break the loop.

### File Locks

Files written through the gate are locked per-session. Another session (subagent, cron) trying to write to the same path gets blocked with a clear message. Locks auto-expire after 1 hour.

### Evidence Classification

Every post_tool_call classifies the result:

| Type | Meaning |
|------|---------|
| `EXECUTION` | Has diffs, test output, build output, exit codes |
| `INSPECTION` | File reads, content searches, browser snapshots |
| `SIMULATION` | Mock/stub/fake references |
| `OPINION` | Model-generated claims with no tool output backing |

The evidence check blocks a new mutation unless at least INSPECTION-level evidence exists after the last one.

## Installation

### Quick Install

```bash
git clone https://github.com/erector666/engineering-gate-hermes-plugin.git
cd engineering-gate-hermes-plugin
./setup.sh
```

Then restart Hermes with `/new`.

### Manual Install

```bash
# Copy plugin files
mkdir -p ~/.hermes/plugins/engineering-gate
cp engineering-gate/__init__.py ~/.hermes/plugins/engineering-gate/
cp engineering-gate/plugin.yaml ~/.hermes/plugins/engineering-gate/

# Enable in config.yaml
# Add to ~/.hermes/config.yaml:
# plugins:
#   - engineering-gate
```

## Agent Setup Guide

For the plugin to work properly, the agent needs:

### 1. SOUL.md Integration

The agent's SOUL.md should reference the Engineering Gate workflow. Example snippet:

```
## Engineering Gate

Before controlled work, run:
THINK → READ → PLAN → blast radius → ADVERSARIAL JUDGE → EXECUTE → VERIFY → HANDOFF

Controlled work means:
- editing files, changing config, installing packages
- changing lockfiles, auth, APIs, database behavior
- deploying, touching Vercel, env, DNS, CI/CD, infra

Inspection is not controlled work. Mutation is controlled work.
```

### 2. A Judge Profile (Recommended)

The gate expects an adversarial judge to review plans before write access. Set up a judge Hermes profile at `~/.hermes/profiles/judge/` with:

- A stricter, more critical model
- Access to `read_file`, `search_files`, `web_search`, `terminal` (read-only)
- NO write tool access

The agent runs:
```
hermes chat -q "Review this plan: [objective + criteria — NO code blocks]" -p judge
```

The judge reads the relevant files, evaluates the criteria, and returns PASS or FAIL.

### 3. Understanding Gate States

The gate state is stored at `~/.hermes/engineering-gate-state.json`. Key fields:

| Field | Values | Meaning |
|-------|--------|---------|
| `phase` | `idle`, `executing`, `verifying` | Current workflow phase |
| `judge_passed` | `true`, `false` | Has the judge approved work for this turn? |
| `last_gated_turn` | turn ID | Which turn has gate access |
| `tool_call_history` | array | Recent tool calls (for stuck detection) |
| `file_locks` | dict | Paths locked by session IDs |
| `evidence_log` | array | Evidence types recorded after mutations |

## Verification

After installation:

```bash
# Check plugin is registered
hermes plugin list
# Should show: engineering-gate (v3.1.0) — active

# Check hooks
hermes plugin info engineering-gate
# hooks: on_session_start, on_session_end, pre_tool_call, post_tool_call

# Check gate state
cat ~/.hermes/engineering-gate-state.json
```

## Structure

```
engineering-gate-hermes-plugin/
├── setup.sh                    # One-command installer
├── engineering-gate/
│   ├── __init__.py             # Plugin code (783 lines, v3.1)
│   └── plugin.yaml             # Plugin manifest
└── README.md
```

## Configuration

The plugin uses these constants (modify in `__init__.py` if needed):

| Constant | Default | Purpose |
|----------|---------|---------|
| `STUCK_SAME_CALL_THRESHOLD` | 3 | Same tool+target repeats before stuck |
| `STUCK_PHASE_STALL_THRESHOLD` | 8 | Calls without phase change before stuck |
| `FILE_LOCK_MAX_AGE_HOURS` | 1 | Auto-release file locks after N hours |
| `SAFE_PATH_PREFIXES` | `~/.hermes` | Paths always writable |
| `SAFE_FILE_EXTENSIONS` | `.md .txt .log .json .yaml .yml` | File types always writable |

## Requirements

- Hermes Agent (by Nous Research)
- Python 3.10+

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| All writes blocked with "gate closed" | Judge hasn't passed this turn | Run the adversarial judge step |
| "Stuck Agent Detected" on legit work | Same tool called repeatedly | Break work into phases, or open the gate manually via state file |
| "provide evidence first" after write | Forgot to verify the output | Read the file or run a test before the next mutation |
| `pre_tool_call` hook not firing | Plugin not enabled or hooks not registered | Check `hermes plugin list`, restart with `/new` |

## License

MIT
