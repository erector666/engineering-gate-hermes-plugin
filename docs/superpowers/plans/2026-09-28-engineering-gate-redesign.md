# Engineering Gate — Hermes v0.21.4 Adapter-Only Phase (Current Scope)

> **Authority and scope (2026-10-02):** This section is the sole current execution plan. The narrow timing-policy fix passed the full core suite (`253 tests`), was committed and pushed, and the remote branch SHA was verified as `27e8b4bdf2695c82322066af592f555223e7b059`. **CORE FREEZE is declared at that exact SHA.** Proceed with the approved adapter-only implementation, then prove exact Telegram correlation, prove native mutators cannot bypass Gate, and run adapter integration tests. Do not make further core edits or conduct another broad core review. The adapter design is approved in principle; no further architectural approval prompt is required. If a required Hermes v0.21.4 capability cannot be proven, stop with mutation disabled and report the blocker. The remainder of this file is historical/reference material only and does not authorize core changes.

## Goal and hard boundaries

Integrate the frozen Engineering Gate core with Hermes v0.21.4 through a plugin that fails closed unless trusted requester identity, exact plan approval, independent review, signed authorization, and Gate-owned writes are all demonstrated end to end in disposable integration tests.

- Once CORE FREEZE is declared at the verified pushed SHA, edit/create only the paths under `engineering-gate/adapters/hermes/`, Hermes plugin entrypoint/manifest, adapter-specific tests, and adapter/profile/rollback documentation listed below. Do not edit `engineering_gate_core/`, `PRD.md`, any other plan, or the Hermes checkout/config/profile/user data. Preserve the Hermes checkout's pre-existing dirty `agent/memory_manager.py` and `tests/agent/test_memory_provider.py` untouched. No live install/config change, public-key enrollment, commit, push, or merge during the adapter phase.
- All protected file mutation remains exclusively through the existing Gate-owned `GateWriteService` and exact signed verdict/lease path. Native Hermes mutators must always remain blocked, including after plan approval; no post-approval native tool execution. Plan-level approval may gate only the Gate control/approval operation, never authorize a native mutator. No shell or direct filesystem mutation bypass. Map Hermes `delegate_task` to normalized `DELEGATE` and block before spawn: v1 delegation is unsupported because core exposes `ChildTaskLease` but the inspected `workflow.py`/`state_store.py` have no usable child-lease lifecycle APIs. Block all other native/unknown mutation-like tools and unsupported capabilities; never allow fallback paths.
- Public-key enrollment/revocation is operator-only and must not be an LLM-exposed tool. Never provision keys or alter user data in this phase.
- If exact Telegram requester/approver correlation, complete plan display, or any other required capability cannot be demonstrated, report the blocker and keep the adapter mutation-disabled. Do not relax requirements to make tests pass.
- Core is frozen at pushed commit `27e8b4bdf2695c82322066af592f555223e7b059`, whose remote SHA was read back and matched. It includes workflow/state store, signed Ed25519 verdicts, `GateMutationAuthority`, Gate-owned `GateWriteService`, reserve-before-staging durable leases, and the single effective `AuthorizationTimingPolicy` (300-second v1 ceilings with stricter configured limits enforced end to end). Make no further core edits; its tests are regression checks only during adapter work.

## Pinned Hermes v0.21.4 contract and staged adapter activation

**Approved activation sequence — two stages, disposable profile only:**

- **Stage 1 (approval only):** Wire the real Gate Telegram DM callback path through the pinned Hermes plugin entrypoint and actual dispatcher. Mutation stays disabled for every tool before and after approval. Prove the complete path: exact current task/plan/revision/digest → durable pending sidecar → complete canonical plan and digest delivered in Telegram DM → button shown only after confirmed delivery → host-authenticated callback actor and private chat → exact pending request lookup → transactional one-time consume → existing core `ApprovalReceipt` persisted → task reaches `APPROVED`. Persist at least `profile_id`, `session_id`, `telegram_user_id`, `telegram_chat_id`, `task_id`, `plan_revision`, `plan_digest`, `workspace_identity`, `approval_request_id`, and `prompt_message_id`, plus a cryptographically random callback nonce and lifecycle status. Bind callback to the same user, DM chat, profile/session, approval request ID, current task/revision/digest/workspace and exact complete prompt. Reject cross-user/chat/profile/session, stale or duplicate callbacks, post-denial/restart-inconsistent state, missing/corrupt sidecars, ambiguous pending approvals, prompt truncation/mismatch, and any model-text approval. Consume durably before constructing/persisting the receipt. Verify restart/replay in a disposable profile. Stage 1 acceptance leaves all native and Gate mutation paths blocked.
- **Stage 2 (one WRITE tracer, only after Stage 1 passes):** Enable one exact protected WRITE path: Hermes request → strict target/content normalization → current Gate task/plan binding → `MutationProposal` → disposable signed-reviewer provider → Gate authorization → one-shot lease → `GateWriteService` → readback/audit → `GateVerificationRunner`. Native Hermes write implementation must never execute; add a spy/failing native mutator and assert its call count is zero. Unknown mutators, PATCH, DELETE, RENAME, EXECUTE, and `delegate_task` remain blocked. The disposable reviewer fixture is test-only and is not a production reviewer service. If the pinned dispatcher cannot return a Gate-owned result while suppressing the original native mutation, stop with mutation disabled and report the exact API limitation; do not fall back to native execution.

These stages are authorized only in disposable Hermes v0.21.4 profiles. Do not modify the frozen core, live Hermes profile, credentials, or unrelated Hermes working-tree changes. Do not commit, push, merge, or deploy.

The built-in Hermes Gateway approval path is not used for Gate plan consent. Gate uses its own nonce-specific callback through `ctx.register_telegram_handler(factory)`, with only application/bot handles supplied by the pinned host API. If message delivery, complete plan rendering, callback identity, profile/session/task/revision/digest/workspace binding, or durable one-use consumption cannot be proven, no core receipt or write is possible. Stage 1 approval never enables mutation.

Accept a Gate plan decision only when the Gate-owned Telegram callback carries the exact pending Gate nonce; its actual `query.from_user.id` is the positive exact-integer trusted requester; the callback is in that requester’s exact private chat; the durable record and current core task match profile/session/requester/chat/task/revision/digest/workspace/approval-request/prompt-message bindings; the complete canonical plan was delivered before controls; the action is exactly `approve_once`; and an atomic consume succeeds once. Reject duplicate/replayed, stale, cancelled/expired, concurrent, cross-scope, wrong-actor/chat, malformed, persistence-failed, ambiguous, or restart-inconsistent callbacks. Conversational `yes`/`approved`, host auto-approval, and model interpretation are never fallbacks. Never invoke or resolve Hermes `ea:` approvals. Any mismatch or inability to prove exact correlation leaves mutation disabled.

## Adapter file map (only permitted changes)

**Gate-owned Telegram prompt boundary:** Send the complete canonical plan as plain text through the pinned PTB application handle supplied to the plugin's Telegram handler factory. If the plan exceeds a Telegram message limit, split only at deterministic text boundaries and prove concatenating the delivered chunks reproduces the exact canonical plan byte-for-byte; attach Approve once / Deny buttons only after every chunk is delivered. Include and display the plan digest. Any send failure, truncation, digest mismatch, or unsupported callback capability leaves the request unapproved. Never invoke Hermes native mutators or resolve Hermes `ea:` approvals.

- `engineering-gate/__init__.py`, `engineering-gate/plugin.yaml`: v0.21.4 entrypoint and manifest; register only Gate controls/hooks and fail closed on unsupported host versions/capabilities.
- `engineering-gate/adapters/__init__.py`, `engineering-gate/adapters/hermes/__init__.py`: plugin factory, dependency construction, capability probe, lifecycle wiring.
- `engineering-gate/adapters/hermes/identity.py`: trusted sender/turn/session and direct-DM identity binding.
- `engineering-gate/adapters/hermes/approval.py`: Gate-owned pending-request lifecycle and core receipt handoff only after exact Telegram callback evidence is durably consumed.
- `engineering-gate/adapters/hermes/telegram_approval.py`: complete-plan plain-text rendering, deterministic lossless splitting/verified delivery, and a nonce-specific Gate callback handler using actual numeric actor/private-chat evidence; no `ea:` observer.
- `engineering-gate/adapters/hermes/approval_sidecar.py`: adapter-owned durable, bounded audit/correlation records; profile-scoped storage, atomic one-use/replay prevention, binding profile + session + trusted requester + task + canonical workspace identity; no core schema changes.
- `engineering-gate/adapters/hermes/hooks.py`: Hermes hooks and normalized event/tool mapping; blocking for all unrecognized or unsupported operations.
- `engineering-gate/adapters/hermes/tool_map.py`, `tool_definitions.py`: pinned tool inventory and Gate-only model-facing controls; no native mutation tools or operator key-management tools.
- `engineering-gate/adapters/hermes/judge_runner.py`: dedicated plugin-owned `ctx.llm` auxiliary judge task; independently configured from implementer and must fail closed if absent, same model/provider identity, or invalid response.
- `tests/hermes_v0214/`: disposable-profile plugin-loader, hook, Telegram approval, identity-correlation, sidecar, judge, write-path, and unsupported-capability integration tests; never run against live profile. Isolation cases are specified in test task 2.
- `docs/engineering-gate-hermes-profile.md`, `docs/ROLLBACK.md`: profile-safe bootstrap, operator-only public-key enrollment instructions, explicit capability limits, safe disable/uninstall/rollback, no live install in this plan.

## Bite-sized test-first tasks

For each task: add the narrow failing test, run it and inspect the expected failure, implement only adapter code, rerun to green, and then run the integration suite. The prerequisite core timing fix is complete; the full core suite passed (`253 tests`), and CORE FREEZE is declared at pushed/verified SHA `27e8b4bdf2695c82322066af592f555223e7b059`. Do not edit core during adapter work. Pin the disposable Hermes checkout and tests to exact commit `d3b25b52ad1318c526bdb259b600eeca3d5f38e6` (not merely version string `v0.21.4`); tests must assert both the checked-out commit and required API. Never edit `/home/uss/.hermes/hermes-agent`, its pre-existing dirty `agent/memory_manager.py` or `tests/agent/test_memory_provider.py`, or the active profile.

1. **Plugin shell and manifest:** test actual plugin loading/API at exact Hermes commit `d3b25b52ad1318c526bdb259b600eeca3d5f38e6`; assert checkout SHA and required API, and prove unsupported version/commit, missing hooks, or failed capability probe yields disabled mutation. Implement entrypoint/manifest and adapter package only.
2. **Task/workspace/profile/session isolation and trusted intake identity:** test `StateStore.load(task_id)` limitations and require sidecar binding/validation for `(profile, Hermes session, trusted requester, task ID, canonical workspace identity)` before every Gate tool call, transition, receipt, or write. Suggested adapter test file `tests/hermes_v0214/test_isolation.py`; focused cases: `test_same_task_other_session_blocks`, `test_same_task_other_requester_blocks`, `test_same_task_other_profile_blocks`, `test_same_task_other_workspace_identity_blocks`, `test_stale_or_revised_plan_blocks`, `test_missing_or_corrupt_sidecar_blocks_without_receipt_or_write`. Root path from intake is untrusted: core canonicalizes/captures `WorkspaceIdentity` (canonical path/device/inode), complete plan displays that canonical path, and the user's receipt binds its digest; never label it trusted/current Hermes CWD absent a host API fact. Capture/binding failure blocks. Also test StateStore and sidecar paths resolve under active profile at operation time and never fall back globally. Test `pre_llm_call.sender_id` sourced from Telegram `from_user.id`; direct DM accepted; group/channel, missing/changed identity, model-supplied identity and unmatched session/turn rejected. Implement identity and sidecar adapter.
3. **Plan packet and presentation:** test complete packet validation, digest binding, full approval-relevant field rendering (including constraints, inspected evidence, analysis/findings, risks/unknowns, every operation/target, blast radius, exclusions, criteria/procedures, verification, rollback, delegated work), and deterministic message splitting whose concatenated successfully delivered text equals the complete canonical plan and digest exactly. Buttons appear only after successful full delivery; any failure or mismatch leaves the request disabled. Test any edit/revision changes digest and invalidates prior approval. Implement presenter/preflight and control-tool wrappers using frozen core.
4. **Approval identity correlation (mandatory exact matrix):** exercise a disposable pinned-Hermes plugin, Gate-owned Telegram callback handler, durable Gate nonce sidecar, and actual numeric `query.from_user.id`/private-chat evidence. Positive case proves one `approve_once` callback by the same authenticated DM requester consumes the exact request once and produces exactly one core receipt for matching profile/session/task/revision/digest/requester/workspace/tool-call/turn, permitting only Gate control progression. Negative tests independently vary: boolean/string/zero/negative ID; username/display-name/model-supplied identity; another Telegram user; requester changes between intake and click; wrong profile/session/task/workspace; stale revision; changed digest; wrong/missing/duplicate nonce; callback data with a native `ea:` prefix; wrong chat/non-DM; action other than exact `approve_once`; concurrent or replayed nonce; expired/cancelled request; malformed fields; failed sidecar read/write; timeout; conversational `yes`/`approved`; host auto-approval; and plan/digest display truncation or failed message delivery. For every negative case assert no receipt and no write authorization. Verify exact Hermes callback routing and that the built-in handler is not triggered by the Gate-specific callback prefix. **If the Gate-owned nonce-bound Telegram callback cannot be proven using the pinned public plugin APIs, stop and report the blocker with mutation disabled; never substitute username/text/model inference.**
5. **Independent auxiliary judge:** test `ctx.llm` invocation through a plugin-owned task configured separately from implementer; missing auxiliary configuration, equal model/provider identity, timeout, malformed verdict, or exception blocks progression. No judge work in `pre_tool_call`. Implement dedicated runner.
6. **Frozen signed verdict and Gate write path:** test valid configured signed reviewer verdict binds exact task/revision/plan digest/proposal digest and independent reviewer; operator-only enrollment is not a tool. Verify durable reserve-before-staging, one-shot lease, and the existing `GateWriteService` are the only mutation path. Test direct shell/file writes, `execute_code`, `delegate_task` mapped to `DELEGATE` and blocked before spawn, every native Hermes mutator both before and after approval, unknown/mutation-like tools, malformed arguments and unsupported tool registry entries all block; assert no post-approval native tool execution and no mutation outside `GateWriteService`.
7. **Verification, result review, handoff, failure/rollback:** run only exact verification commands recorded in the approved plan through existing Gate execution; preserve result evidence, require independent result review and supervisor inspection before handoff. Test missing/failed/inconclusive verification, judge failure, scope drift, persistence errors, cancellation, stale approval, restart/replay, and rollback all deny further writes and accurately report partial results.
8. **Documentation and release gate:** test profile-scoped bootstrap and rollback docs, manifest agreement, no installer/live-profile side effects, no key material, and only permitted paths changed. Document unsupported capabilities and tool-level boundary; no claim of sandboxing or general Hermes support.

## Verification commands and acceptance gate

The integration test harness must create a disposable profile and remove it on every exit path; stub all LLM/network activity and never read live profile config/secrets. Use the Hermes checkout at exact commit `d3b25b52ad1318c526bdb259b600eeca3d5f38e6`, assert that exact checkout SHA and required API before tests, and expose both repositories explicitly. The prerequisite timing fix passed the full suite, was committed/pushed, and remote-verified; the core is frozen at `27e8b4bdf2695c82322066af592f555223e7b059`. Adapter testing must remain disposable and API-pinned:

```sh
set -eu
profile="$(mktemp -d)"
trap 'rm -rf "$profile"' EXIT HUP INT TERM
test "$(git -C /home/uss/.hermes/hermes-agent rev-parse HEAD)" = "d3b25b52ad1318c526bdb259b600eeca3d5f38e6"
HERMES_HOME="$profile" PYTHONPATH="$PWD/engineering-gate:/home/uss/.hermes/hermes-agent" /home/uss/.hermes/hermes-agent/venv/bin/python -m unittest discover -s tests/hermes_v0214 -v
```

Confirm the installed interpreter path against the exact pinned Hermes checkout before running; do not fall back to system Python. The fixture must stub LLM/network and never read live profile config/secrets. Core regression and compile commands should use the same pinned interpreter and `PYTHONPATH` as needed. Before enabling mutation, all exact approval positive/negative tests must pass, exact callback-to-pending-request correlation and full canonical plan presentation must be proven, the independent judge must be verified, native mutators must remain blocked after approval, and all protected writes must traverse Gate-owned services. Any unmet criterion leaves mutation disabled. Core suite is a regression gate only after freeze; a failure is reported, not repaired by changing core in this phase. Review the final diff and assert every changed path is in the allowed adapter/test/docs map; do not commit, push, or merge during adapter work.

## Historical/reference material

The former broad core-redesign plan begins below and is preserved for historical context only. Its architecture, file map, contracts, and tasks are superseded where they conflict with the adapter-only scope above. Do not execute its instructions in this phase.

---

## Historical: Engineering Gate Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a harness-neutral Engineering Gate core that enforces the approved lifecycle through explicit, fail-closed adapters; Hermes is the first adapter and initial integration-test target.

**Architecture:** Put lifecycle/state, normalized-operation policy, evidence, review orchestration, approval-receipt validation, and handoff logic in a standalone `engineering_gate_core` Python package with no harness imports. Put Hermes hook/tool registration, host approval integration, Hermes CLI judge runner, profile-home lookup, and Hermes tool-name mapping under `engineering-gate/adapters/hermes/`; the plugin `__init__.py` is a thin adapter entry point. The v1 deliverable supports the Hermes adapter only; other harnesses are not claimed supported until they implement the same adapter contract and pass its conformance suite.

**Tech Stack:** Python 3.12 and standard-library core (`sqlite3`, `unittest`, `hashlib`, `difflib`, `shlex`, `subprocess`). Hermes plugin API v0.21.4 is an adapter-specific integration target only. No new runtime dependency.

**Spec:** `/home/uss/Desktop/engineering-gate-hermes-plugin-master/PRD.md`

## Global Constraints

- Use strict tracer-bullet TDD: for each behavior, write one failing test, run and inspect the expected failure, implement the smallest change, rerun to green, then move to the next behavior. Do not batch multiple new tests before implementation.
- Keep `engineering_gate_core` free of imports/references to Hermes, Claude, OpenAI Agents, MCP runtime SDKs, host hook names, host config, or raw harness tool names. Inject ports for state-home resolution, judge execution, approval receipts, and normalized tool observations.
- Resolve the state path through an adapter-supplied `home_provider()` at call time. Only the Hermes adapter may call `hermes_constants.get_hermes_home()`; core state code never imports Hermes.
- Every adapter declares `AdapterCapabilities`. For each use case, the core checks its exact required capability set: a missing mutation/identity/approval-correlation/preimage/redaction capability blocks mutation; missing result-observation or judge capability blocks result review; missing supervisor-inspection evidence blocks handoff; missing delegation lifecycle blocks delegation only. A missing capability is never an implicit allow.
- Record plan approval only after the adapter supplies a trusted, correlated receipt for the exact task/revision/digest and a verified binding between the responder and that task’s requester. Host mode `manual`, tool-handler invocation, cached `always`/`session` rules, auto-approval, or absence of a deny result alone are not proof of requester approval.
- Core policy consumes normalized `ToolInvocation` objects; raw harness tool names/argument schemas belong to adapters. Each adapter must publish a supported-surface inventory and map every known mutation surface or fail closed as unknown.
- `pre_action` adapter callbacks must remain fast and perform no LLM/subprocess work; judge calls use an injected runner in a dedicated control handler with an explicit timeout.
- Never persist or send raw secrets or raw file contents to the judge. Only bounded redacted preimages/diffs may be retained; if capture/redaction fails before a mutation, block that mutation. If safe evidence is unavailable, block result review/handoff.
- This remains a tool-level gate, not an OS sandbox. It cannot prevent direct filesystem writes by arbitrary Python code, non-cooperative plugins, plugin-internal `ctx.dispatch_tool()` calls, or out-of-process agents; document this boundary for every adapter and do not claim those paths are gated.
- Do not trust delegated summaries as proof. The parent directly inspects every changed file/diff and runs the final tests on the final tree.
- No project implementation/tests may be created until the revised plan is explicitly approved.

## Review Focus

1. Manual approval disabled, smart approval, YOLO, persistent `always` approvals, no interactive approver, timeout, or denial must never authorize an unapproved plan.
2. Missing or changing `session_id`, `task_id`, `turn_id`, plan revision, or delegated-child identity must not inherit another task’s authorization.
3. `execute_code`, `delegate_task`, unknown tools, malformed arguments, command chaining/redirection, `python -c`/`-m`, and shell-prefix tricks must not bypass policy.
4. Relative paths, `..`, symlinks, paths outside the approved workspace, and `.md`/`.json`/`.yaml`/`.txt`/`.log` files must receive the same scope check as source code.
5. Judge timeout, malformed/plain-text verdict, corrupt state, failed state writes, missing test output, redaction failure, and out-of-scope post-change evidence must fail closed without a false pass.

---

## File Structure and Contracts

| File | Responsibility |
|---|---|
| `engineering-gate/engineering_gate_core/models.py` | Host-neutral immutable lifecycle, normalized invocation, approval-receipt, criterion-evidence, handoff, and adapter-capability types. Standard library only. |
| `engineering-gate/engineering_gate_core/ports.py` | Host-neutral `JudgeRunner`, `Redactor`, `WorkspaceReader`, `HarnessAdapter`, and `EngineeringGate` protocols plus fail-closed capability checks; no registration/hook SDK imports. |
| `engineering-gate/engineering_gate_core/workflow.py` | Pure stage/event definitions, packet validation, plan digest, and legal lifecycle/loopback transitions. |
| `engineering-gate/engineering_gate_core/state_store.py` | SQLite persistence for task history, active-task index, evidence, and child leases; uses injected `home_provider`, no harness import. |
| `engineering-gate/engineering_gate_core/policy.py` | Policy over normalized operations and canonical paths; no raw harness tool-name assumptions. |
| `engineering-gate/engineering_gate_core/judge.py` | Prompt construction, strict verdict parsing, and review orchestration through injected `JudgeRunner`. |
| `engineering-gate/engineering_gate_core/evidence.py` | Redacted preimages/diffs, normalized tool outcomes, per-criterion evidence, cleanup, and supervisor-inspection records. |
| `engineering-gate/engineering_gate_core/control_tools.py` | Host-neutral start/submit/approval/result/handoff/cancel service methods returning mappings; no tool-schema registration. |
| `engineering-gate/adapters/__init__.py` | Python package marker for adapter implementations. |
| `engineering-gate/adapters/hermes/__init__.py` | Hermes-only factory/registration glue; verifies adapter capabilities and constructs core dependencies. |
| `engineering-gate/adapters/hermes/hooks.py` | Maps Hermes callbacks to normalized core events and emits Hermes-specific block/approve directives. |
| `engineering-gate/adapters/hermes/identity.py` | Binds trusted current-turn actor identity to Hermes session/turn context; never reads model-supplied identity. |
| `engineering-gate/adapters/hermes/approval.py` | Correlates Hermes transport request IDs/digests and verified Telegram responder identity into a core receipt. |
| `engineering-gate/adapters/hermes/telegram_approval.py` | Presents the full plan in Telegram DMs and validates one-time requester-bound callback actions. |
| `engineering-gate/adapters/hermes/judge_runner.py` | Hermes CLI judge-profile subprocess implementation of the core `JudgeRunner` port. |
| `engineering-gate/adapters/hermes/tool_map.py` | Versioned inventory mapping Hermes tools to normalized operations; unknown/unmapped mutations fail closed. |
| `engineering-gate/adapters/hermes/tool_definitions.py` | Hermes JSON schemas and wrappers for the core control service; serializes returned mappings to JSON strings. |
| `engineering-gate/__init__.py` | Thin Hermes plugin-loader entry point delegating to `adapters.hermes`; no lifecycle/policy logic. |
| `engineering-gate/plugin.yaml` | Hermes adapter manifest only. |
| `tests/support.py` | Shared temporary workspaces, fake adapter, complete typed lifecycle fixture factories, and fake ports. |
| `tests/test_workflow.py` | Every forward FSM transition, illegal skips, stale evidence, and loopbacks. |
| `tests/test_state_store.py` | Harness/session/task/workspace isolation, transaction, schema, retained history, and child-lease cases. |
| `tests/test_policy.py` | Normalized operation/path/command decisions independent of host tool names. |
| `tests/test_judge.py` | Core-only strict verdict parsing, injected runner timeouts, and host-neutral review metadata. |
| `tests/test_hermes_judge_runner.py` | Hermes CLI/profile argument construction, exit/timeout handling, and secret-safe output limits for the adapter runner. |
| `tests/test_evidence.py` | Redaction, safe preimage/diff, per-criterion evidence, and cleanup. |
| `tests/test_control_tools.py` | Start/plan/review/approval/result/handoff/cancel service behavior. |
| `tests/test_adapter_contract.py` | Fake-adapter capability and normalized-event conformance; unsupported capabilities fail closed. |
| `tests/test_architecture_boundary.py` | Import core with no Hermes runtime path; reject harness imports outside adapters. |
| `tests/test_supported_surfaces.py` | Compare pinned Hermes mutation-surface inventory to discovered tool registry; unmapped calls deny. |
| `tests/test_hooks.py` | Hermes pre/post, approval-observer receipt, session/subagent mapping, and failure behavior. |
| `tests/test_telegram_approval.py` | Telegram DM routing, complete plan rendering/chunking, and requester-bound callback behavior. |
| `tests/test_plugin_integration.py` | Real Hermes plugin loader in disposable `HERMES_HOME`; actual model dispatch/approval path, no live profile. |
| `tests/test_docs_contract.py` | Manifest/schema/documentation/rollback consistency and install-side-effect guard. |
| `docs/ROLLBACK.md` | Tested manual rollback/uninstall and stale-approval invalidation procedure.

### Test fixture contract

`EngineeringGateTestCase` in `tests/support.py` creates a `TemporaryDirectory` under `$TMPDIR`, `workspace/`, `outside/`, and an inspected `workspace/README.md`. Core fixtures use only the host-neutral types:

```python
self.context = RunContext(
    harness_id="fake",
    platform="test",
    session_id="session-1",
    task_session_id="session-1",
    host_task_id=None,
    workspace_root=str(self.workspace.resolve()),
    actor_id="principal-1",
    actor_role=ActorRole.REQUESTER,
)
self.intake = IntakeRecord(
    objective="Add a sample feature",
    requester_id="principal-1",
    workspace_root=str(self.workspace.resolve()),
    constraints=("Write only to the approved workspace.",),
    created_at="2026-09-28T00:00:00+00:00",
)
self.valid_packet = PlanPacket(
    objective=self.intake.objective,
    requester_id=self.intake.requester_id,
    workspace_root=self.intake.workspace_root,
    constraints=self.intake.constraints,
    inspected_paths=(str((self.workspace / "README.md").resolve()),),
    inspection_evidence_ids=("read-1",),
    analysis_findings=("One implementation file is required.",),
    risks=("An out-of-scope write could damage unrelated files.",),
    unknowns=("No deployment is requested.",),
    operations=(PlannedOperation(OperationKind.WRITE, "src/main.py", "Implement the feature."),),
    blast_radius=("src/main.py",),
    exclusions=("outside/", ".env"),
    acceptance_criteria=(AcceptanceCriterion("AC-1", "Feature works.", "Run its focused unit test."),),
    verification=("python3 -m unittest discover -s tests -v",),
    rollback="Restore the captured pre-mutation snapshot.",
    delegated_work=(DelegatedWork("work-1", "Implement the feature.", ("src/main.py",), (OperationKind.WRITE,)),),
)
```

`support.py` also provides a successful `READ` `EvidenceRecord` for `README.md`, fixture factories for `GateState` at each stage, a stable test clock, a `FakeJudgeRunner` that returns strict verdict JSON and exposes `reviewer_id="fake:judge"`, a `FakeRedactor`, and a `FakeHarnessAdapter`. State-machine unit tests may construct a valid state directly for the stage under test; they must not call a not-yet-implemented transition to build their RED fixture. Separate state-store/control/hook tests create their own temporary stores and contexts. Hermes adapter tests never use a fake approval bridge to prove real host approval; they exercise the actual observer/dispatch seam with a deterministic test callback. No fixture contains credentials, raw file contents, or claims of live-human approval.

**Scope decision:** The modules are separable implementation units, but none is independently releasable: the PRD’s lifecycle, approval, mutation enforcement, evidence, and handoff criteria depend on each other. Keep one implementation plan with non-overlapping module ownership rather than splitting the approved PRD into partial plans.

### Shared interfaces

`workflow.py` owns these immutable types and signatures; later tasks must use these names rather than invent parallel schemas:

```python
class Stage(str, Enum):
    INTAKE = "intake"
    INSPECT = "inspect"
    ANALYZE = "analyze"
    PLAN = "plan"
    ASSESS_BLAST_RADIUS = "assess_blast_radius"
    ADVERSARIAL_PLAN_REVIEW = "adversarial_plan_review"
    USER_APPROVAL = "user_approval"
    IMPLEMENT = "implement"
    VERIFY = "verify"
    ADVERSARIAL_RESULT_REVIEW = "adversarial_result_review"
    HANDOFF = "handoff"
    CANCELLED = "cancelled"

class TaskStatus(str, Enum):
    ACTIVE = "active"
    COMPLETE = "complete"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"

class ActorRole(str, Enum):
    REQUESTER = "requester"
    PARENT = "parent"
    IMPLEMENTER = "implementer"
    CHILD = "child"
    ADAPTER = "adapter"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class RunContext:
    harness_id: str
    platform: str | None  # adapter-normalized origin; opaque to the core
    session_id: str  # current caller session (parent or child)
    task_session_id: str | None  # owner; parent binds its own session, child derives it only from an active lease
    host_task_id: str | None
    workspace_root: str | None
    actor_id: str | None  # trusted identity of the current turn; task requester lives in IntakeRecord
    actor_role: ActorRole

@dataclass(frozen=True)
class AdapterCapabilities:
    can_block_before_mutation: bool
    stable_session_identity: bool
    stable_workspace_identity: bool
    normalize_operations: bool
    explicit_human_approval_receipt: bool
    approval_event_correlation: bool
    requester_identity_binding: bool
    post_action_observations: bool
    preimage_capture: bool
    safe_redaction: bool
    supervisor_inspection_evidence: bool
    delegation_lifecycle: bool

class CapabilityUseCase(str, Enum):
    MUTATION = "mutation"
    PLAN_APPROVAL = "plan_approval"
    RESULT_REVIEW = "result_review"
    HANDOFF = "handoff"
    DELEGATION = "delegation"

class OperationKind(str, Enum):
    READ = "read"
    WRITE = "write"
    PATCH = "patch"
    DELETE = "delete"
    RENAME = "rename"
    EXECUTE = "execute"
    DELEGATE = "delegate"
    CONTROL = "control"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class ToolInvocation:
    invocation_id: str
    context: RunContext
    operation: OperationKind
    targets: tuple[str, ...]
    command: str | None  # normalized, ephemeral execution descriptor; never persisted raw
    child_goal: str | None

class ToolStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    MISSING = "missing"
    INCONCLUSIVE = "inconclusive"

@dataclass(frozen=True)
class ToolObservation:
    invocation_id: str
    context: RunContext
    status: ToolStatus
    observed_at: str
    safe_excerpt: str
    path_hashes: tuple[tuple[str, str], ...]

class Event(str, Enum):
    INTAKE_CAPTURED = "intake_captured"
    INSPECTION_COMPLETED = "inspection_completed"
    ANALYSIS_RECORDED = "analysis_recorded"
    PLAN_SUBMITTED = "plan_submitted"
    BLAST_RADIUS_ASSESSED = "blast_radius_assessed"
    PLAN_REVIEW_PASSED = "plan_review_passed"
    PLAN_REVIEW_FAILED = "plan_review_failed"
    PLAN_REVISED = "plan_revised"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_REQUEST_BOUND = "approval_request_bound"
    APPROVAL_RECEIPT_RECORDED = "approval_receipt_recorded"
    USER_APPROVED = "user_approved"
    USER_APPROVAL_NOT_GRANTED = "user_approval_not_granted"
    SCOPE_DRIFT = "scope_drift"
    VERIFICATION_STARTED = "verification_started"
    VERIFICATION_RECORDED = "verification_recorded"
    VERIFICATION_PASSED = "verification_passed"
    VERIFICATION_FAILED = "verification_failed"
    RESULT_REVIEW_PASSED = "result_review_passed"
    RESULT_REVIEW_IN_SCOPE_FAILURE = "result_review_in_scope_failure"
    RESULT_REVIEW_REPLAN = "result_review_replan"
    HANDOFF_RECORDED = "handoff_recorded"
    CANCEL = "cancel"

@dataclass(frozen=True)
class PlannedOperation:
    operation: OperationKind
    target: str
    rationale: str
    command: str | None = None

@dataclass(frozen=True)
class DelegatedWork:
    work_id: str
    goal: str
    allowed_paths: tuple[str, ...]
    allowed_operations: tuple[OperationKind, ...]

@dataclass(frozen=True)
class AcceptanceCriterion:
    criterion_id: str
    description: str
    verification_procedure: str  # exact stable normalized check descriptor, not a narrative claim

@dataclass(frozen=True)
class PlanPacket:
    objective: str
    requester_id: str
    workspace_root: str
    constraints: tuple[str, ...]
    inspected_paths: tuple[str, ...]
    inspection_evidence_ids: tuple[str, ...]
    analysis_findings: tuple[str, ...]
    risks: tuple[str, ...]
    unknowns: tuple[str, ...]
    operations: tuple[PlannedOperation, ...]
    blast_radius: tuple[str, ...]
    exclusions: tuple[str, ...]
    acceptance_criteria: tuple[AcceptanceCriterion, ...]
    verification: tuple[str, ...]
    rollback: str
    delegated_work: tuple[DelegatedWork, ...]

class ReviewKind(str, Enum):
    PLAN = "plan"
    RESULT = "result"

class ReviewVerdict(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    NEEDS_CLARIFICATION = "NEEDS_CLARIFICATION"
    PASS = "PASS"
    IMPLEMENT_FIX = "IMPLEMENT_FIX"
    REPLAN = "REPLAN"

@dataclass(frozen=True)
class JudgeVerdict:
    verdict: ReviewVerdict
    rationale: str
    findings: tuple[str, ...]
    required_changes: tuple[str, ...]

@dataclass(frozen=True)
class ReviewResult:
    review_id: str
    kind: ReviewKind
    task_id: str
    revision: int
    reviewer_id: str
    plan_digest: str
    reviewed_at: str
    verdict: ReviewVerdict
    rationale: str
    findings: tuple[str, ...]
    required_changes: tuple[str, ...]
    evidence_ids: tuple[str, ...]

@dataclass(frozen=True)
class IntakeRecord:
    objective: str
    requester_id: str
    workspace_root: str
    constraints: tuple[str, ...]
    created_at: str

class ApprovalDecision(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNAVAILABLE = "unavailable"

@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    harness_id: str
    session_id: str
    requester_id: str
    approver_id: str | None
    requester_binding_verified: bool
    task_id: str
    revision: int
    rule_key: str
    plan_digest: str
    host_request_id: str
    host_request_digest: str
    decision: ApprovalDecision
    human_confirmed: bool
    surface: str
    host_choice: str | None
    tool_call_id: str
    turn_id: str
    observed_at: str

@dataclass(frozen=True)
class PendingApproval:
    harness_id: str
    session_id: str
    requester_id: str
    task_id: str
    revision: int
    rule_key: str
    plan_digest: str
    host_request_id: str | None
    host_request_digest: str | None
    requested_at: str
    tool_call_id: str
    turn_id: str

class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    INCONCLUSIVE = "inconclusive"

@dataclass(frozen=True)
class CriterionClaim:
    criterion_id: str
    procedure: str
    evidence_ids: tuple[str, ...]

@dataclass(frozen=True)
class CriterionEvidence:
    criterion_id: str
    check_id: str
    procedure: str
    status: CheckStatus
    evidence_ids: tuple[str, ...]
    observed_at: str

@dataclass(frozen=True)
class HandoffRecord:
    task_id: str
    revision: int
    changed_files: tuple[str, ...]
    criterion_evidence: tuple[CriterionEvidence, ...]
    result_review_id: str
    unresolved_risks: tuple[str, ...]
    supervisor_session_id: str
    inspection_evidence_ids: tuple[str, ...]
    recorded_at: str

@dataclass(frozen=True)
class TerminationRecord:
    task_id: str
    outcome: str
    reason: str
    partial_changed_files: tuple[str, ...]
    remaining_risks: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    recorded_at: str

@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    receipt_id: str | None
    harness_id: str
    session_id: str
    requester_id: str
    approver_id: str | None
    requester_binding_verified: bool
    task_id: str
    revision: int
    rule_key: str
    plan_digest: str
    host_request_id: str | None
    host_request_digest: str | None
    outcome: ApprovalDecision
    human_confirmed: bool
    surface: str
    host_choice: str | None
    recorded_at: str
    tool_call_id: str
    turn_id: str

@dataclass(frozen=True)
class TransitionRecord:
    event: Event
    stage: Stage
    plan_revision: int
    timestamp: str
    outcome: str
    evidence_ids: tuple[str, ...]

class EvidencePhase(str, Enum):
    PRE_ACTION = "pre_action"
    POST_ACTION = "post_action"
    VERIFICATION = "verification"
    SUPERVISOR_REVIEW = "supervisor_review"

@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    harness_id: str
    session_id: str
    task_id: str
    plan_revision: int
    plan_digest: str | None
    actor_role: ActorRole
    phase: EvidencePhase
    observed_at: str
    operation: OperationKind
    targets: tuple[str, ...]
    invocation_id: str
    turn_id: str | None
    tool_call_id: str | None
    status: ToolStatus
    command_hash: str | None
    artifact_ref: str | None
    safe_excerpt: str
    path_hashes: tuple[tuple[str, str], ...]

@dataclass(frozen=True)
class GateState:
    harness_id: str
    session_id: str
    task_id: str
    workspace_root: str
    stage: Stage
    status: TaskStatus
    revision: int
    intake: IntakeRecord
    inspection_evidence_ids: tuple[str, ...]
    analysis_findings: tuple[str, ...]
    plan_digest: str | None
    approval_rule_key: str | None
    packet: PlanPacket | None
    plan_review: ReviewResult | None
    approval_receipt: ApprovalReceipt | None
    approval: ApprovalRecord | None
    approval_attempt: ApprovalRecord | None
    approval_history: tuple[ApprovalRecord, ...]
    pending_approval: PendingApproval | None
    criterion_evidence: tuple[CriterionEvidence, ...]
    evidence_records: tuple[EvidenceRecord, ...]
    result_review: ReviewResult | None
    review_history: tuple[ReviewResult, ...]
    handoff: HandoffRecord | None
    termination: TerminationRecord | None
    stage_history: tuple[TransitionRecord, ...]

class LeaseStatus(str, Enum):
    RESERVED = "reserved"
    ACTIVE = "active"
    COMPLETED = "completed"
    REVOKED = "revoked"
    EXPIRED = "expired"

@dataclass(frozen=True)
class ChildLease:
    harness_id: str
    parent_session_id: str
    child_session_id: str
    task_id: str
    workspace_root: str
    plan_revision: int
    plan_digest: str
    work_id: str
    goal: str
    allowed_paths: tuple[str, ...]
    allowed_operations: tuple[OperationKind, ...]
    status: LeaseStatus

class MutationClass(str, Enum):
    READ_ONLY = "read_only"
    MUTATION = "mutation"
    CONTROL = "control"
    UNKNOWN = "unknown"

class PolicyAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    SCOPE_DRIFT = "scope_drift"

@dataclass(frozen=True)
class PolicyDecision:
    action: PolicyAction
    reason: str
```

`workflow.py` exposes `validate_plan_packet(raw: Mapping[str, object], intake: IntakeRecord, observed_evidence: tuple[EvidenceRecord, ...]) -> PlanPacket`, `plan_digest(packet: PlanPacket) -> str` (canonical JSON over every approval-relevant field), `new_task_state(context: RunContext, intake: IntakeRecord, task_id: str) -> GateState` (records `INTAKE_CAPTURED`, then enters `INSPECT`), and `transition(state: GateState, event: Event, payload: Mapping[str, object] | None = None) -> GateState`. It defines `TransitionError` for illegal transitions. Every transition validates required artifacts and appends an event-bound `TransitionRecord`; the ordered sequence is INTAKE → INSPECT → ANALYZE → PLAN → ASSESS_BLAST_RADIUS → ADVERSARIAL_PLAN_REVIEW → USER_APPROVAL → IMPLEMENT → VERIFY → ADVERSARIAL_RESULT_REVIEW → HANDOFF. A plan cannot be submitted until normalized successful inspection observations exist and are linked by evidence IDs; analysis/impact artifacts are recorded distinctly, not used as proof of private reasoning.

`PlanPacket` requires a trusted requester ID copied from `IntakeRecord` (never accepted from raw model JSON), objective, canonical workspace root, constraints, inspected paths and evidence IDs, analysis findings, material risks/unknowns, normalized planned operations/targets, blast-radius assessment, explicit exclusions, stable acceptance-criterion IDs with per-criterion verification procedures, rollback/recovery, and bounded delegated work. The renderer shows every approval-relevant field and refers to the recipient as the current authenticated requester; it omits opaque requester identifiers while the digest binds them. The approval renderer must show the complete plan, not just the objective and file list. Any change to a field or evidence reference invalidates review and approval.

`state_store.py` exposes `load_active(harness_id, task_session_id, workspace_root) -> GateState | None`, `load_task(harness_id, task_session_id, task_id) -> GateState | None`, `create_task(context, intake, task_id) -> GateState`, parent-only `update_task(context, task_id, updater) -> GateState`, child-safe `append_evidence(context, task_id, evidence_record) -> GateState`, narrowly scoped `mark_scope_drift(context, task_id, invocation, reason) -> GateState`, `reserve_work(parent_context, task_id, work_id) -> None`, `bind_child(parent_context, child_context, task_id, work_id, child_goal) -> ChildLease`, `load_child(harness_id, child_session_id) -> ChildLease | None`, `load_child_history(harness_id, parent_session_id, task_id) -> tuple[ChildLease, ...]`, `release_work(harness_id, parent_session_id, task_id, work_id) -> None`, `revoke_child(harness_id, child_session_id) -> None`, and `revoke_task_children(harness_id, parent_session_id, task_id) -> None`. `StateStore(home_provider, connection_factory=sqlite3.connect)` resolves `home_provider()` on every operation and stores under `<provided-home>/engineering-gate/state.db`; only the Hermes adapter supplies `get_hermes_home`. Schema version 1 has `task_state` keyed by `(harness_id, task_session_id, task_id)`, an `active_tasks` index unique by `(harness_id, task_session_id, canonical_workspace_root)`, and `child_leases` keyed by parent/task/work item with a unique active child binding. Every read-modify-write uses `BEGIN IMMEDIATE`, a bounded busy timeout, explicit commit/rollback, and short-lived connections. Typed JSON serialization validates all enum/dataclass fields. Corrupt rows, unsupported schema, identity mismatch, path/permission errors, and lock timeout raise `StateStoreError`; the legacy global approval JSON is never read, migrated, or deleted. `create_task` rejects a child context; generic `update_task` accepts only the parent. `append_evidence` accepts the parent or a matching active child lease but cannot change workflow state. `mark_scope_drift` is the only workflow-changing method that accepts a child context: it validates the actor's active lease, records the blocked attempt, returns the task to `PLAN`, clears review/approval, increments revision, and revokes child leases. New database directories are owner-only and database files mode `0600`; completed/cancelled rows remain for audit while their active index entry is removed.

`policy.py` exposes `classify_invocation(call: ToolInvocation) -> MutationClass`, `classify_command(command: str) -> MutationClass`, `authorize_path(target, workspace_root, allowed_targets, operation: OperationKind) -> PolicyDecision`, and `authorize_invocation(state, child_lease, call: ToolInvocation) -> PolicyDecision`. Core policy sees only canonical `OperationKind` values and normalized targets, never raw host tool names. Adapter inventories map each supported host tool to these operations; unmapped/opaque operations are `UNKNOWN` and block. Traversal/symlink escape, sensitive path, malformed arguments, invalid workspace, or unknown mutation blocks. A mutation inside the workspace but outside approved operations is `SCOPE_DRIFT` and stops the run for replanning/reapproval.

`ports.py` defines these injected boundaries:

```python
class JudgeRunner(Protocol):
    reviewer_id: str
    def run(self, prompt: str, timeout_seconds: float) -> str: ...

class Redactor(Protocol):
    def redact(self, text: str) -> str | None: ...

class WorkspaceReader(Protocol):
    def read_bytes(self, canonical_path: str, max_bytes: int) -> bytes | None: ...

class HarnessAdapter(Protocol):
    def capabilities(self, context: RunContext) -> AdapterCapabilities: ...
    def normalize_invocation(self, raw_event: object, context: RunContext) -> ToolInvocation | None: ...
    def normalize_observation(self, raw_event: object, invocation: ToolInvocation) -> ToolObservation | None: ...
    def approval_receipt_from_event(self, raw_event: object) -> ApprovalReceipt | None: ...
    def state_home_provider(self) -> Path: ...

class EngineeringGate(Protocol):
    def before_action(self, context: RunContext, invocation: ToolInvocation) -> PolicyDecision: ...
    def after_action(self, context: RunContext, observation: ToolObservation) -> None: ...
    def record_approval_receipt(self, receipt: ApprovalReceipt) -> GateState: ...

def capability_decision(capabilities: AdapterCapabilities, use_case: CapabilityUseCase) -> PolicyDecision: ...
```

`capability_decision` uses this exact mapping: `MUTATION` requires `can_block_before_mutation`, `stable_session_identity`, `stable_workspace_identity`, `normalize_operations`, `explicit_human_approval_receipt`, `approval_event_correlation`, `requester_identity_binding`, `post_action_observations`, `preimage_capture`, and `safe_redaction`; `PLAN_APPROVAL` requires the first three identity/blocking fields plus `explicit_human_approval_receipt`, `approval_event_correlation`, and `requester_identity_binding`; `RESULT_REVIEW` requires stable session/workspace identity, post-action observations, and safe redaction; `HANDOFF` additionally requires `supervisor_inspection_evidence`; `DELEGATION` requires all `MUTATION` capabilities plus `delegation_lifecycle`. A missing judge runner blocks review even when adapter capabilities pass. Missing delegation lifecycle disables delegation only. The core receives normalized types and opaque adapter events; it imports no harness SDK, hook name, host configuration, or host tool schema. A clean-subprocess architecture test imports core with Hermes paths absent.

The Hermes adapter implements the neutral ports in `adapters/hermes/`; Hermes v0.21.4 is the only implemented harness. `identity.py` maps the trusted current-turn `sender_id` from `pre_llm_call` to `RunContext.actor_id` and joins it to `pre_tool_call` only by exact session+turn; missing identity blocks requester-only actions. For approval, `approval.py` begins a pending request before the host prompt and listens for `pre_approval_request` / `post_approval_response`. Only the explicitly selected `engineering-gate-telegram` custom transport can bind the host request ID+digest and `session_key`; built-in CLI/Gateway/manual prompts without this transport, smart approval, cached rules, off/YOLO, and unattended auto-approval never create a receipt. The operator configuration requires `security.approval.transport_fallback: deny`; if `builtin` fallback is deliberately configured, a built-in response is recorded only as `ApprovalDecision.UNAVAILABLE` with no responder binding, keeps the task at `USER_APPROVAL`, and can never produce `ApprovalReceipt` or authorize mutation. The transport only presents/returns a correlated decision—Hermes retains final host authorization and the Engineering Gate independently enforces lifecycle policy in `pre_tool_call`; no claim is made that the transport itself blocks other tools. `telegram_approval.py` uses the registered public Telegram platform-handler API to resolve only a v0.21.4 direct-message route, displays the entire persisted/redacted plan, and accepts a one-time `once` or `deny` callback only when Telegram’s authenticated `query.from_user.id` equals the recorded requester and chat/thread/request ID/digest match. The presenter returns only `request.respond(choice)`; the actor ID is retained in a bounded sidecar keyed by host request ID+digest, then joined by the observer to create `ApprovalReceipt(human_confirmed=True, requester_binding_verified=True)` for `record_approval_receipt`. Timeout, send/loop failure, wrong user, denial, missing correlation, observer error, or replay produces no approval and records only a nonhuman attempt/denial. `complete_plan_approval` consumes the exact receipt; direct handler dispatch or a cached host grant cannot authorize. The installer does not register or enable the transport or change Hermes config. If the selected transport, session route, actor identity, or request correlation cannot be positively verified, its capability is false and mutation stays blocked. The observer itself never approves or vetoes the host call.

`judge.py` exposes strict `parse_plan_verdict`, `parse_result_verdict`, `build_plan_prompt(packet, evidence)`, `build_result_prompt(packet, redacted_diff, verification_evidence)`, `review_plan(state, evidence, runner)`, and `review_result(state, redacted_diff, verification_evidence, runner)`. Review functions require the corresponding review stage and derive task/revision/digest from the current `GateState` (whose packet digest must recompute exactly). They invoke only the injected `JudgeRunner`; core contains no subprocess, CLI, profile, or harness code. Plan verdicts are `APPROVED`, `REJECTED`, or `NEEDS_CLARIFICATION`; result verdicts are `PASS`, `IMPLEMENT_FIX`, `REPLAN`, or `NEEDS_CLARIFICATION`. Core creates trusted `ReviewResult` metadata from current state, `runner.reviewer_id`, evidence IDs, and UTC timestamp; the model cannot supply or override these values. The Hermes-only CLI implementation lives in `adapters/hermes/judge_runner.py` and is tested separately.

`control_tools.py` exposes a host-neutral `ControlToolService(store, adapter, judge_runner, evidence_service, task_id_factory=uuid.uuid4)` with `start_task(objective, workspace_root, constraints, context)`, `submit_plan(task_id, raw_plan, context)`, adapter-only `begin_plan_approval(task_id, revision, plan_digest, context) -> PendingApproval`, model-tool-backed `complete_plan_approval(task_id, context)`, internal `record_approval_receipt(receipt, context)`, internal `record_approval_attempt(task_id, outcome, context)`, internal `record_scope_drift(task_id, invocation, reason, context)`, `review_result(task_id, criterion_claims: tuple[CriterionClaim, ...], context)`, `handoff(task_id, unresolved_risks, supervisor_evidence_ids, context)`, and `cancel_task(task_id, reason, context)`, each returning its declared typed result or `dict[str, object]`. It uses only typed state transitions and does not expose tool schemas or a host approval bridge. `submit_plan` records the ordered inspect/analyze/plan/impact events from stored observations and packet fields before invoking the judge; long judge work occurs outside SQLite transactions. `record_scope_drift` atomically invalidates the current digest/approval, returns the task to `PLAN`, and revokes child leases before the hook returns its block. `review_result` validates criterion evidence from stored observations before calling the result judge. Hermes `tool_definitions.py` defines six model-facing tools in toolset `engineering_gate`; each JSON object has `additionalProperties: false`:

| Tool | Required arguments | Trust rule |
|---|---|---|
| `engineering_gate_start_task` | `objective: str`, `workspace_root: str`, `constraints: list[str]` | Handler takes requester ID only from trusted `RunContext.actor_id`; it generates task ID and canonicalizes/binds workspace. |
| `engineering_gate_submit_plan` | `task_id: str`, `raw_plan: object` | Raw plan has no `requester_id`, `workspace_root`, or approval field; core copies identity/root from trusted intake and validates every evidence reference. |
| `engineering_gate_request_plan_approval` | `task_id: str`, `revision: int`, `plan_digest: str` | Has no choice, approver ID, host request ID, or receipt argument; `begin_plan_approval`/`complete_plan_approval` enforce adapter receipt. |
| `engineering_gate_review_result` | `task_id: str`, `criterion_claims: list[object]` | Claims are cross-checked against stored tool observations and criterion procedures. |
| `engineering_gate_handoff` | `task_id: str`, `unresolved_risks: list[str]`, `supervisor_evidence_ids: list[str]` | IDs and risk list are validated against stored state; model cannot assert supervisor inspection. |
| `engineering_gate_cancel_task` | `task_id: str`, `reason: str` | Requester identity and current task scope are checked before terminal cancellation. |

The exact nested JSON schema for `raw_plan` mirrors the untrusted fields in `PlanPacket` except `requester_id`, `workspace_root`, and `constraints`, which are supplied from `IntakeRecord`. `criterion_claims` is a required array of objects with exactly `criterion_id: str`, `procedure: str`, and `evidence_ids: list[str]`; each object sets `additionalProperties: false`. It rejects model-supplied `status`, `observed_at`, or `check_id`. `tool_definitions.py` converts service mappings to JSON strings and never registers adapter-only receipt/attempt methods as tools.

`evidence.py` records actual normalized before/after observations and derives criterion-specific verification only from stored records; raw file content and raw commands are never persisted or sent to the judge, only bounded redacted preimages/diffs and nonreversible hashes. Redaction/capture failure blocks mutation before execution. Handoff requires a `HandoffRecord` mapping every acceptance criterion to its final derived `PASSED` evidence, includes unresolved risks, and references actual post-review parent/supervisor inspection evidence for every changed path/diff; `FAILED`, `SKIPPED`, or `INCONCLUSIVE` attempts remain in audit history but cannot satisfy handoff. Cancellation stores and returns a `TerminationRecord` naming partial changes and remaining risks; cancellation never silently discards state.

`adapters/hermes/hooks.py` maps Hermes lifecycle/tool/approval events into normalized core records. Its methods implement `pre_tool_call(...)`, `post_tool_call(**kwargs)`, `post_approval_response(**kwargs)`, `on_session_start(**kwargs)`, `on_session_end(**kwargs)`, `subagent_start(**kwargs)`, and `subagent_stop(**kwargs)`. Hook observers only create receipts after explicit host responses; direct model-tool dispatch is still checked by the core control handler. Each adapter has a separate supported-surface inventory and must pass the same fake-adapter conformance suite; the Hermes adapter is the only adapter implemented in v1.

- Plugin tools can be registered through `ctx.register_tool()` and model-dispatched calls pass through `pre_tool_call`; the hook can request the host approval gate with a message and rule key. The prompt receives the tool name/message rather than a structured plan object, so the adapter must render the complete plan itself. [H1][H2]
- The host approval gate is per tool call, not a native plan-approval API. Its UI receives the tool name/message rather than a structured plan, so the adapter must render the entire plan itself. The host exposes choices such as `once`, `session`, `always`, and `deny`; the adapter must bind the rule key to the exact task/revision/digest and accept only a correlated post-response receipt. [H1][H2][H3]
- Correction to an earlier audit note: Hermes v0.21.4 invokes `pre_approval_request` and `post_approval_response` observers on the Gateway approval wait path as well as the selected-transport path; the observers carry the active tool-call/turn/session context and the returned choice. They are observational only and their failures never veto the host gate. Use a successful, correlated `post_approval_response` only as a receipt event; if it is absent, errors, has a non-accepted choice, or does not identify a reviewed human surface, the control handler must refuse to record approval. Never rely on `post_tool_call` as authorization. [H4][H9][H11][H12]
- Manual approval mode alone does not prove a human acted: the host may bypass prompting for YOLO, mode `off`, a cached session/persistent rule, `single_query_mode: approve`, or cron/unattended auto-approve. The adapter must reject known unattended/auto modes and, independently, require an explicit receipt from a verified human surface. A host grant without that receipt leaves the plan unapproved. [H3][H13]
- Hook callback timeout defaults to 30 seconds, and callback timeouts/errors block the tool; keep judge subprocess work out of hooks. [H6]
- `ctx.dispatch_tool()` calls registry dispatch directly and bypasses the model pre-tool path; never treat handler invocation as proof the normal model gate ran. The plan-bound human receipt is required even if the handler is reached by direct dispatch. [H7]
- `delegate_task` creates a child with a distinct session ID; the installed source emits `subagent_start` with parent/child IDs before the child is returned to the runner. Verify actual callback ordering in integration tests before granting a child lease. [H8]

**Local Hermes Source Evidence (installed v0.21.4):**

H1. `/home/uss/.hermes/hermes-agent/hermes_cli/plugins.py:455-498, 1870-1874, 1952`
H2. `/home/uss/.hermes/hermes-agent/tools/approval.py:1095-1120`
H3. `/home/uss/.hermes/hermes-agent/tools/approval.py:380-392, 1106-1114`
H4. `/home/uss/.hermes/hermes-agent/tools/approval_context.py:53-72`
H5. `/home/uss/.hermes/hermes-agent/tools/approval.py:322-325, 1178-1180`; `/home/uss/.hermes/hermes-agent/tools/approval_context.py:228-236`
H6. `/home/uss/.hermes/hermes-agent/hermes_cli/plugins_dispatch.py:150-178, 209-243`
H7. `/home/uss/.hermes/hermes-agent/hermes_cli/plugins.py:686-695`; `/home/uss/.hermes/hermes-agent/tools/registry.py:880-908`
H8. `/home/uss/.hermes/hermes-agent/tools/delegate_tool.py:244-247, 290-297`
H9. `/home/uss/.hermes/hermes-agent/tools/approval.py:835-892, 907-931`
H10. `/home/uss/.hermes/hermes-agent/model_tools.py:940-959`; `/home/uss/.hermes/hermes-agent/hermes_cli/plugins.py:1949-1952`
H11. `/home/uss/.hermes/hermes-agent/tools/approval_gateway_wait.py:89-98, 197-224`; `/home/uss/.hermes/hermes-agent/tools/approval_context.py:53-72, 88-99`
H12. `/home/uss/.hermes/hermes-agent/tools/approval_prompt.py:236-250`
H13. `/home/uss/.hermes/hermes-agent/tools/approval.py:961-1015, 1095-1120`

Cross-harness rationale: the official Claude Code docs describe hook callbacks around tool use, the OpenAI Agents SDK docs describe human approval as a paused run that resumes with persisted state, and the MCP tool-annotation docs describe annotations as advisory metadata rather than enforcement. These distinct host contracts imply a neutral lifecycle/policy core with explicit, capability-checked adapters; this is an architectural inference, not a claim that all harnesses are already supported. [1][2][3]

## Sources

[1] https://code.claude.com/docs/en/hooks — Claude Code Hooks reference
[2] https://openai.github.io/openai-agents-python/human_in_the_loop — OpenAI Agents SDK Human-in-the-loop
[3] https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations — MCP Tool Annotations as Risk Vocabulary
