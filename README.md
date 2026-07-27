# Engineering Gate — Hermes Plugin

**Version 4.0** — Per-Task Workflow Enforcement with Adversarial Judge Verification.

## Flow

THINK → READ → PLAN → ADVERSARIAL JUDGE → BUILD → VERIFY (judge, up to 5x) → HANDOFF

## Features

- **Pre-build gate**: Blocks write/build tools unless the adversarial judge approves
- **Post-build verification**: Judge verifies output against 6 criteria after each write
- **5-loop correction cycle**: Failed verification blocks with corrections; after 5 loops permanently blocks
- **Auto-judge invocation**: No agent action required — spawns judge profile automatically
- **Stuck agent detection**, file locks, evidence tracking

## Install

```bash
cp -r engineering-gate ~/.hermes/plugins/
# Add 'engineering-gate' to plugins.enabled in config.yaml
hermes gateway restart
```
