# Engineering Gate Redesign PRD

**Status:** Approved requirements baseline, including the user-directed harness-neutral core/Hermes-first adapter requirement; implementation plan remains under review and adapter capabilities require runtime verification  
**Scope:** Requirements for the harness-neutral Engineering Gate core and its Hermes-first adapter

## 1. Objective

Engineering Gate must keep lifecycle/state/policy logic in a host-neutral core and put runtime-specific identity, tool normalization, hook wiring, storage location, judge execution, and human-approval integration in adapters. Hermes is the initial integration target, not a dependency of the core.

Redesign Engineering Gate so project mutations follow the user-approved lifecycle:

**INTAKE → INSPECT → ANALYZE → PLAN → ASSESS BLAST RADIUS → ADVERSARIAL PLAN REVIEW → USER APPROVAL → IMPLEMENT → VERIFY → ADVERSARIAL RESULT REVIEW → HANDOFF**

The plugin must prevent applicable write/build actions from proceeding without current, explicit authorization for the task and scope. It must make each lifecycle transition auditable through observable artifacts, stop on scope drift, and require actual verification evidence before handoff. It is a tool-level enforcement mechanism: it cannot prove that an agent privately performed an unobservable reasoning stage. It must not present a stage as verified unless the required artifact is available to the plugin or in the handoff record.

## 2. Current state and problem

Repository facts supplied for this PRD:

- The repository contains `README.md`, `LICENSE`, `setup.sh`, `engineering-gate/plugin.yaml`, and `engineering-gate/__init__.py`; no tests or Git metadata were found.
- README and setup material claim version 4.0, while the implementation and manifest identify 3.1 and 3.2.
- The current implementation gates writes/build tools by invoking `hermes -p judge chat`, stores state in the global `~/.hermes/engineering-gate-state.json`, auto-allows documentation/configuration extensions, opens the mutation gate for the remainder of a turn, and judge-verifies write/build output in a post-hook.

These behaviors do not provide task-specific, plan-bound authorization across the full lifecycle. Extension-based exceptions can permit out-of-scope changes; a turn-wide unlock can outlive the action approved; and a global state file risks unrelated tasks sharing gate state. The redesign must replace those semantics with explicit lifecycle evidence, narrowly bound approval, per-action enforcement, and deterministic failure handling.

## 3. Users and primary use cases

- **Requester/approver:** states the objective and scope, reviews the complete plan, and grants or denies approval.
- **Implementing agent:** inspects, plans, requests approval, makes only approved changes, and supplies verification evidence.
- **Supervising/parent agent:** independently inspects actual files/diffs and verification evidence before accepting delegated work. Agent or subagent summaries alone are not sufficient evidence.
- **Plugin maintainer:** configures supported mutation surfaces, investigates blocked actions, and validates the gate’s behavior.

The system must support: a new task requiring repository changes; an attempted mutation before approval; a plan-review failure; an implementation defect within approved scope; scope or acceptance-criteria changes; approval denial or expiration; and successful verification and handoff.

## 4. Lifecycle contract

Every transition must have a task-bound record containing the stage, plan revision (once a plan exists), timestamp, outcome, and links or content for its required evidence. Stage records are attestations of observable work, not proof of hidden cognition.

| Stage | Minimum observable evidence and exit condition |
|---|---|
| **INTAKE** | Objective, requester, constraints, and initial scope are recorded. Unknowns are marked, not silently assumed. |
| **INSPECT** | Relevant baseline is captured, including the files/state inspected and any existing changes that affect the task. |
| **ANALYZE** | Findings, constraints, and implications for the requested outcome are recorded. |
| **PLAN** | A revisioned plan lists intended paths/operations, acceptance criteria, verification commands or procedures, and expected outputs. |
| **ASSESS BLAST RADIUS** | Affected files/systems, side effects, dependencies, risks, and rollback or recovery approach are recorded. |
| **ADVERSARIAL PLAN REVIEW** | Review outcome is explicit (pass/fail), with objections and their disposition. Any unresolved blocking issue means fail. |
| **USER APPROVAL** | The requester sees the complete plan and grants or denies that exact revision through a verified human-response receipt from the active adapter. Silence, agent assertion, judge output, cached host permission, auto-approval, or approval of an earlier revision is not approval. |
| **IMPLEMENT** | Each applicable mutation is authorized against the active task, approved plan revision, and approved scope. Actual changes are recorded. |
| **VERIFY** | Each acceptance criterion is mapped to an executed check and its actual result/output. Unrun or inconclusive checks are disclosed and cannot be reported as passing. |
| **ADVERSARIAL RESULT REVIEW** | Review examines the actual changed files/diff and verification evidence; outcome and findings are recorded. |
| **HANDOFF** | Summary identifies changed files, actual verification results, unresolved risks, and review findings. The supervising/parent agent must inspect the files/diffs; a delegated report alone does not satisfy this requirement. |

The user-approval packet must be detailed enough to make scope and risk review possible: objective and constraints; inspected baseline; exact planned paths and operations; explicit in-scope and out-of-scope boundaries; acceptance criteria; verification steps; blast-radius assessment; material risks and unknowns; rollback/recovery; and any delegated work. Approval is bound to the packet revision. Any material edit to it invalidates the prior approval.

## 5. Transition, loopback, and failure rules

1. No stage may be skipped. A missing, malformed, stale, or contradictory stage record blocks the next transition.
2. A failed adversarial plan review returns to **PLAN** and **ASSESS BLAST RADIUS**, then requires another adversarial review and new user approval if the approved plan changes.
3. An implementation defect that remains within the approved scope returns to **IMPLEMENT → VERIFY → ADVERSARIAL RESULT REVIEW**. The new verification must cover the affected acceptance criteria.
4. A plan flaw, acceptance-criteria flaw, or material scope change stops further mutation and returns through **PLAN → ASSESS BLAST RADIUS → ADVERSARIAL PLAN REVIEW → USER APPROVAL**. No prior approval carries forward to the revised plan.
5. Any detected scope drift during implementation blocks that mutation and all subsequent mutations until the revised plan is reviewed and approved. Read-only inspection needed to assess the drift may continue only if separately permitted by policy.
6. Approval denial, judge failure, timeout, unavailable hook, state corruption, or inability to determine whether a tool action is in scope must fail closed for mutations. The user receives a specific blocked reason and a safe recovery path; the plugin must not silently downgrade to allow.
7. A task may end without handoff only as an explicitly recorded cancellation/abandonment or rejection. Partial work and remaining risks must still be disclosed.

## 6. Functional and measurable acceptance criteria

The redesign is acceptable only when all criteria below pass in automated or documented integration tests:

- **AC-1 — Stage enforcement:** Tests cover every listed forward transition and prove that skipped, out-of-order, or evidence-free transitions are rejected.
- **AC-2 — Plan-bound human approval:** A mutation is denied before an explicit human-response receipt for the exact task, plan revision, digest, and scope; approval of revision N does not authorize revision N+1; denial leaves mutations blocked. A host handler being invoked, a manual-mode setting, cached/session permission, or auto-approval is not sufficient evidence of requester approval.
- **AC-3 — Per-action scope check:** Every supported mutation-capable tool invocation is checked against the active task and approved scope immediately before execution. Approval of one action never opens a turn-wide mutation window.
- **AC-4 — No extension bypass:** Documentation and configuration writes receive the same plan/scope/approval checks as other writes; file suffix alone never grants an allow decision.
- **AC-5 — Scope drift:** Tests attempt an unapproved path/operation and a material plan change; no such mutation executes before reapproval.
- **AC-6 — Loopbacks:** Tests demonstrate both required loops: plan-review failure returns to planning/impact assessment/review, and an in-scope implementation defect returns to implementation/verification/result review. A material scope change invalidates approval.
- **AC-7 — Verification evidence:** Handoff cannot claim an acceptance criterion passed without a recorded executed check and actual result. Skipped, failed, and inconclusive checks remain distinguishable.
- **AC-8 — Result review and handoff:** Result review is tied to the actual changed files/diff and verification evidence. Handoff contains the changed-file list, check results, unresolved risks, and review outcome; the supervising agent’s inspection is identified separately from the implementer’s report.
- **AC-9 — Isolation:** Concurrent or sequential tasks cannot inherit another task’s approval or stage state. Tests cover distinct task/workspace contexts and stale state. If a reliable task/workspace identity is unavailable, the plugin blocks mutations rather than sharing a global approval.
- **AC-10 — Fail-closed behavior:** Tests inject unavailable judge, callback timeout, malformed/stale state, unknown mutation surface, and missing evidence; each produces a block, an actionable reason, and no mutation.
- **AC-11 — Release consistency:** Before release, version claims in README/setup and the implementation/manifest agree, and the supported-hook behavior is documented without asserting unverified API semantics.
- **AC-12 — Host-neutral core and adapter conformance:** Automated tests import the core in a clean environment without Hermes runtime installed and confirm that core imports no Hermes, Claude, OpenAI, or MCP runtime libraries. For each adapter declared supported, contract tests verify host identity, tool/action normalization, hook registration and pre-mutation enforcement, approval receipt, task/workspace-scoped storage, judge execution, and delegation-event mapping; tests also verify that absence of any capability required for a mutation blocks that mutation. V1 passes these tests for the Hermes adapter only, and release claims no other harness support until its adapter passes the same suite.

The supported mutation-surface inventory must be produced during implementation. At minimum it must cover the write/build surfaces currently gated. Any tool or command whose effects cannot be safely classified must be denied or routed to an explicit approval decision, not implicitly allowed.

## 7. Security and scope controls

- Bind lifecycle state and approval to one task, one workspace/repository context, and one plan revision; do not use a single unqualified global approval state.
- Replace extension-based allow rules and turn-wide unlocking with action-level decisions. Scope evaluation must consider the target and operation, not only a filename suffix.
- Resolve and validate paths/operations before a mutation executes. Ambiguous targets, paths outside approved scope, or commands with uninspectable effects must stop for review rather than pass through.
- Only the requester’s explicit decision may satisfy **USER APPROVAL**. The adapter must issue a receipt only from a verified human-response event for the exact task/revision/digest; a judge or implementing agent cannot approve, and host configuration, handler invocation, stale/cache grants, and unattended auto-approval do not prove requester consent.
- Keep enough audit evidence to reconstruct transitions, approval requests and receipts, blocked attempts, mutations, and checks. Do not put secrets into lifecycle records or handoff output.
- Treat plugin enforcement as bounded: users and maintainers must be told that the gate observes tool calls and recorded artifacts, not private reasoning or changes made through unobserved channels.

## 8. Non-goals

- Proving that hidden cognitive stages occurred without observable artifacts.
- Guaranteeing that a judge model’s review is correct or that a test suite proves absence of defects.
- Treating a parent/subagent summary as a substitute for inspecting actual files/diffs.
- Adding automatic approval based on extensions, past turns, or a judge’s confidence.
- Expanding into a general repository policy engine beyond the lifecycle and mutation controls described here.

## 9. Assumptions and open risks

- Official Hermes documentation confirms that `pre_tool_call` may return an `approve` action/message to invoke the built-in human-approval gate, and denial/timeout fails closed.[7] Whether that gate can present and persist approval for the complete plan revision—especially for `write_file`/`patch`, rather than only approving one tool call—is **unverified**; prove the exact UX and callback outcome before selecting it. Do not treat a session-wide or persistent tool approval as plan-scoped authorization.
- Official Hermes documentation sets `plugins.hook_callback_timeout` to a default of 30 seconds (0 disables it; maximum 600 seconds).[7] The current implementation sets `JUDGE_TIMEOUT = 120` seconds. Under default host configuration, a synchronous judge call can outlast the hook budget and be abandoned/blocked. The redesign must make this compatible by design or explicitly configure and test a compatible host timeout; a timeout must never allow mutation.
- Availability and stability of task, workspace, and tool identity inside hooks are unverified. Confirm before committing to a storage key or claiming cross-task isolation.
- Hook ordering, coverage of all relevant write/build tools, and the ability to block before side effects require integration verification.
- The current global state file may contain legacy state. Migration, invalidation, and user-facing recovery need a decision; never treat an unmapped legacy approval as valid authorization.
- Decide whether “adversarial review” requires a distinct reviewer identity or can be satisfied by a structured critic step. Until decided, do not label an implementer’s unsupported self-check as independent review.
- Define the structured evidence format and how a supervising/parent inspection is recorded without implying that the plugin can observe an inspection it cannot see.

## 10. Testing and rollout requirements

Because no tests were found in the supplied repository inventory, implementation must introduce a test suite before enabling the redesign by default. It must include state-machine unit tests; scope/path and operation-policy tests; hook integration tests proving blocks occur before side effects; approval-flow tests against the actual supported Hermes interface; and end-to-end tests for every loopback, denial, timeout, and successful handoff. Include regression cases for documentation/configuration extensions, turn boundaries, concurrent tasks, stale/global state, unknown tools, and material scope drift.

Roll out first against a disposable fixture repository. Promote only after all acceptance tests pass, every supported mutation surface has an explicit policy, and the suite records zero unapproved mutations. Run a migration dry run before consuming legacy state; stale or unmapped state must not unlock tools. Keep a documented rollback procedure that restores the prior plugin safely without preserving stale approvals. Synchronize version claims and update user-facing setup/documentation as part of the release, not as a later cleanup.

## 11. Harness portability and v1 boundary (user-directed amendment)

Engineering Gate is intended to use a host-neutral lifecycle/policy core with host adapters. The core must not import Hermes, Claude, OpenAI, or MCP runtime libraries. Adapters own host-specific identity, tool/action normalization, hook registration, approval receipt, storage home, judge runner, and delegation-event mapping. If a host lacks a capability required for a mutation, block that affected mutation; portability must not weaken the lifecycle, scope, approval, audit, or fail-closed requirements.

**Research note:** Claude Code documents host-specific pre/post tool and permission hooks [1]; the OpenAI Agents SDK models human approval as interruption and resumption via `RunState` [2]; MCP tool annotations are hints, not authorization [3]. **Architectural inference:** these distinct host control contracts support an explicit adapter boundary around a host-neutral core; annotations or metadata alone cannot provide authorization or enforcement.

**V1 boundary:** Initial implementation, testing, and conformance integration cover only the host-neutral core plus the Hermes adapter. This does not establish support for another harness. Do not claim a harness is supported until its adapter passes the same capability and contract tests, including fail-closed behavior when a required capability is unavailable.

## Sources

[1] https://code.claude.com/docs/en/hooks — Claude Code Hooks reference
[2] https://openai.github.io/openai-agents-python/human_in_the_loop — OpenAI Agents SDK Human-in-the-loop
[3] https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations — MCP Tool Annotations as Risk Vocabulary
[7] https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks — Hermes Event Hooks reference
