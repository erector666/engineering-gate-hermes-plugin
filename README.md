# Engineering Gate Hermes Plugin

Enforces the THINK → READ → PLAN → JUDGE → EXECUTE → VERIFY → HANDOFF workflow at the tool dispatch level inside Hermes Agent.

Blocks `write_file`, `patch`, `skill_manage`, and build commands (`npm install`, `git push`, `docker build`, `vercel deploy`, etc.) unless the adversarial judge step has passed for the current turn. Inspection tools (`read_file`, `search_files`, `web_search`, browser, delegation) are always allowed.

## Features

- **Per-turn gating** — gate auto-closes on every new user message
- **Stuck agent detection** — blocks after 3+ identical tool calls in one turn
- **Evidence enforcement** — blocks a second mutation until verification evidence exists
- **Concurrent file-lock prevention** — prevents cross-session file conflicts
- **Infra path passthrough** — `~/.hermes/`, `.md`/`.txt`/`.log` files always writable

## Installation

```bash
git clone https://github.com/erector666/engineering-gate-hermes-plugin.git
cd engineering-gate-hermes-plugin
./setup.sh
```

Then `/new` to restart Hermes with the gate active.

## Verification

```bash
hermes plugin list
# Should show: engineering-gate (v3.1.0) — active

hermes plugin info engineering-gate
# hooks: on_session_start, on_session_end, pre_tool_call, post_tool_call
```

## Structure

```
engineering-gate-hermes-plugin/
├── setup.sh                    # One-command installer
├── engineering-gate/
│   ├── __init__.py             # Plugin code (783 lines)
│   └── plugin.yaml             # Plugin manifest
└── README.md
```

## How It Works

The plugin registers 4 Hermes lifecycle hooks:

| Hook | Phase | Role |
|------|-------|------|
| `on_session_start` | Session boot | Close gate, reset state |
| `pre_tool_call` | Before every tool | Block or allow based on gate state |
| `post_tool_call` | After every tool | Classify and record evidence |
| `on_session_end` | Session shutdown | Release file locks |

The gate starts closed. The agent must pass the adversarial judge before any write/build tool will be allowed. Once the judge passes, all writes in that turn proceed. The next user message auto-closes the gate.

## Requirements

- Hermes Agent (by Nous Research)
- Python 3.10+

## License

MIT
