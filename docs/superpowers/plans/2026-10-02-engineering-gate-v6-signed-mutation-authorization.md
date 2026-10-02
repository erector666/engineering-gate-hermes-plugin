# Engineering Gate v6 Signed Mutation Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the injected mutation-authorization trust boundary with a Gate-owned verifier for signed, independently reviewed, exact-proposal verdicts and durable, revocable, short-lived, one-shot authorization leases.

**Architecture:** Keep signature verification, key trust, lease state transitions, and enforcement in the host-neutral Gate core. A configured reviewer public key verifies an Ed25519-signed verdict; the reviewer’s private key remains outside Gate, and a signature proves possession of that key, not human approval. The accepted signature is stored with a Gate-generated authorization ID and Gate-clock issue/expiry timestamps in a durable SQLite record; no second Gate signing key is added. Reservation commits in its own StateStore transaction before the final filesystem/state transaction, so an audit/state rollback after `os.replace` cannot reactivate the authorization. `GateWriteService` re-verifies the stored reviewer signature and current lease/key state before reservation. Bind each verdict and lease to one task, current plan revision and digest, exact WRITE proposal digest, distinct reviewer identity/provider, and bounded timestamps. Persist reservation/consumption so a crash never restores an uncertain one-shot opportunity.

**Tech Stack:** Python 3.12, existing SQLite `StateStore`, `unittest`, `hashlib`/canonical JSON, and Ed25519 from the approved dependency range `cryptography>=46,<51`; do not implement cryptography locally.

**Spec:** `PRD.md` (especially lifecycle/approval requirements §§4–7, adversarial review and evidence open question §9, host-neutrality §11); the v5 core contract is documented in `docs/superpowers/plans/2026-10-01-engineering-gate-v5-core-verification-nested-write.md`.

## Global Constraints

- Core must not import Hermes, Claude, OpenAI, or MCP runtime libraries.
- Human approval remains a plan-level, exact-revision decision; a reviewer signature is not requester approval and cannot skip the existing approval receipt.
- Mutations fail closed on missing, malformed, stale, expired, revoked, replayed, or unverifiable evidence or unavailable persistence/clock/key configuration.
- V1 in this plan authorizes only the existing typed, single-file `WRITE` path; do not expand mutation surfaces.
- Reviewer identity must be distinct from the implementing agent identity and must match an explicitly configured trusted key identity/provider.
- Persist public reviewer keys, trust configuration, and signed evidence needed for audit; never persist reviewer private keys.
- Do not implement a Hermes adapter, `PATCH`/`DELETE`/`RENAME`, deployment, UI, or cleanup/release work.
- The execute-once/shared-identity regression is complete and must remain unchanged during authorization Tasks 1–4.
- A caller-created `MutationAuthorization` value or injected test verifier is not authorization. Production `GateWriteService` must require a valid signed reviewer verdict and a current store-backed lease issued by `GateMutationAuthority`; direct same-UID/database-file tampering remains outside this slice's threat model.
- The current repository has no Python dependency manifest, and `setup.sh` only copies the plugin. This slice adds a requirements manifest but does not change or run the installer; any production caller must provision the declared dependency separately, and Gate denies writes if it is absent.
- The host-neutral core verifies a verdict produced by an external reviewer signer; implementing the reviewer/model service, its private-key custody, review UI, and host adapter is outside this slice. Production use requires an independently operated signer that signs only after reviewing the exact bound proposal.
- V1 assumes one active Gate authority process per SQLite StateStore. Any `reserved` lease found during recovery is consumed as uncertain; if another process is still completing that write, recovery may make its outcome report uncertain, but cannot make the lease reusable. Multi-process active-authority coordination is deferred.
- The SQLite authorization row is authoritative only inside the trusted Gate process/application boundary; this core does not defend against hostile same-UID code or direct database-file tampering. A separate Gate signature or OS-backed integrity boundary is not part of this slice.

## Review Focus

- Reviewer identity/provider equal to the configured implementer identity or duplicate key-to-reviewer mapping: reject; test both cases.
- Caller-created or stale `MutationAuthorization` object without a matching signed-verdict record and available one-shot lease: deny before any filesystem change.
- Reordered JSON, duplicate keys, Unicode, or noncanonical timestamps: reject noncanonical signed bytes rather than reinterpret; test canonical encode/verify and duplicate-key rejection.
- Valid signature with changed task/revision/plan/proposal/authorization/provider binding: reject; test each field independently.
- Revocation/expiry racing an in-flight write: serialize lease acquisition and revocation; test that revocation either precedes and blocks the reservation or follows a committed reservation without retroactively splitting its critical section.
- Process restart during reserved execution: do not reissue; test durable consumed/uncertain state after reopening the database.

---

## File Map

- Create `engineering-gate/engineering_gate_core/signed_authorization.py`: canonical verdict wire format, Ed25519 verification against a supplied trusted public-key record, and typed verification errors/results.
- Create `engineering-gate/engineering_gate_core/mutation_authority.py`: Gate-owned signed-verdict recording, key administration, active-authorization lookup, durable lease context, reservation/finalization, and trusted-clock policy.
- Modify `engineering-gate/engineering_gate_core/models.py`: immutable `MutationLeaseRecord`/`AuthorizationLeaseStatus` and execution linkage; preserve legacy record decoding while never treating a plain `MutationAuthorization` as a capability.
- Modify `engineering-gate/engineering_gate_core/workflow.py`: make the legacy plain-object `record_mutation_authorization` path unable to grant write authority; preserve proposal invalidation/approved-plan checks, and treat any legacy `TaskStateRecord.mutation_authorization` field as untrusted evidence only.
- Modify `engineering-gate/engineering_gate_core/state_store.py`: schema migration and transactional durable reviewer-key/verdict/lease state, revocation, one-shot reservation/consumption, restart recovery, Gate-only verified-verdict recording, and execution-audit validation against a RESERVED lease using the already-open transaction connection.
- Modify `engineering-gate/engineering_gate_core/a3_execution.py`: remove production reliance on injected verifier/lease provider and caller-supplied `MutationAuthorization`; use GateMutationAuthority to retrieve a current ACTIVE authorization for permit binding, durably reserve that exact authorization before the final state transaction, and finalize/mark uncertain around the existing WRITE replacement critical section.
- Modify `engineering-gate/engineering_gate_core/__init__.py`: export the supported Gate-owned public API only.
- Create `engineering-gate/requirements.txt`: declare the supported `cryptography` Ed25519 dependency range; missing runtime dependency must fail closed.
- Create `docs/development/signed-authorization.md`: document the dependency/runtime requirement, explicit missing-backend failure, that `setup.sh` remains the copy-only v4 installer and is not a v6 installer, and that this core slice is not yet a Hermes integration.
- Create `tests/test_signed_authorization.py`: canonical bytes, signatures, identity/key trust, binding, timestamps, and negative cases.
- Create `tests/test_authorization_leases.py`: durable lease state, atomic reserve/revoke, one-shot behavior, expiry, and restart recovery.
- Modify `tests/test_a3_gate_owned_write.py`: exercise the real configured-key verifier and state-backed lease instead of synthetic injected authority for production API; retain any explicitly test-only fake tests only where testing a narrow failure seam.
- Modify `tests/test_state_store.py`: schema migration, corrupt/legacy authorization handling, transaction and restart cases.
- Modify `tests/test_workflow.py`: lifecycle and stale-plan/proposal invalidation behavior.
- Do not modify `PRD.md`, the v5 plan, adapters, `setup.sh`, UI, or unrelated files. Task 0 is complete and verified; preserve its shared execution-ID and legacy-unknown behavior while serializing any later edits to overlapping evidence files.

## Task 0: Shared Verification Execution Identity (Prerequisite)

Complete this previously approved regression slice before Tasks 1–4. One approved verification command covering multiple criteria must execute once, and all criterion-bound records from that execution must carry one shared `execution_id`. Different actual command executions must have different IDs. Do not retroactively invent execution identity when restoring legacy evidence that predates this field; restore that identity as unknown (`None`).

**Files:**
- Modify: `engineering-gate/engineering_gate_core/models.py`
- Modify: `engineering-gate/engineering_gate_core/verification_execution.py`
- Modify: `engineering-gate/engineering_gate_core/state_store.py` only as required to preserve current IDs and restore missing legacy IDs as unknown
- Test: `tests/test_verification_runner.py`
- Test: `tests/test_verification_store.py`

- [x] **Step 1: Write the failing runner identity tests**

Assert the observer is called exactly once for a command covering two criteria, both resulting records share the same nonempty `execution_id`, and separate approved commands have different IDs.

- [x] **Step 2: Run the focused runner test and verify failure**

Run: `python3 -m unittest tests.test_verification_runner -v`
Expected: FAIL because one execution identity is not yet shared by criterion records.

- [x] **Step 3: Implement Gate-issued identity propagation**

Generate the ID once when the Gate observes a process and copy it into each criterion-bound observation derived from that result. Preserve the ID through SQLite encoding and decoding.

- [x] **Step 4: Add legacy restoration tests**

Remove `execution_id` from a serialized pre-change observation and assert decoding marks the identity unknown consistently; assert current observations preserve their exact ID over repeated state-store round trips.

- [x] **Step 5: Run focused tests**

Run: `python3 -m unittest tests.test_verification_runner tests.test_verification_store -v`
Expected: PASS; new evidence has stable IDs, legacy evidence does not claim an invented identity.

Parent verification on the final prerequisite tree: `python3 -m unittest discover -s tests -q` passed 208 tests; `python3 -m py_compile engineering-gate/engineering_gate_core/*.py tests/test_*.py` and `git diff --check` passed.

## Proposed Contract

### Signed verdict wire format

Use versioned UTF-8 JSON with exact schema version `schema_version: 1` and exact `signature_algorithm: "Ed25519"`. The signed reviewer object has exactly these fields: `schema_version`, `signature_algorithm`, `key_id`, `review_id`, `reviewer_id`, `reviewer_provider`, `implementer_id`, `task_id`, `plan_revision`, `plan_digest`, `proposal_digest`, `verdict`, and `reviewed_at`. It deliberately contains no Gate `authorization_id`, `issued_at`, or lease `expires_at`: those are generated by Gate only after successful verification. `verdict` is exactly `approve` or `reject`; valid rejected reviews are durably audited but never create a lease. Both identities/providers are nonempty bounded strings. Reviewer identity must differ from immutable Gate-configured implementer identity. `reviewed_at` is a canonical UTC RFC3339 whole-second string ending `Z`; it must not be in the future and must be no older than the immutable `AUTHORIZATION_TIMING_V1.max_review_age_seconds` (300 seconds; no clock-skew allowance). For an `approve`, the Gate authority generates a fresh authorization ID and `issued_at` from its trusted clock and sets `expires_at = issued_at + AUTHORIZATION_TIMING_V1.max_active_lease_seconds` (300 seconds); these timestamps limit only the interval before reservation. No API accepts timing overrides.

Canonical signed bytes are UTF-8 JSON with recursively sorted object keys, no insignificant whitespace, `ensure_ascii=False`, no NaN/Infinity, and no duplicate keys; arrays retain order. The detached Ed25519 signature covers `b"engineering-gate/reviewer-verdict/v1\x00" + canonical_payload`, with the NUL byte as an unambiguous domain separator. Reject duplicate/ambiguous JSON keys, unknown or missing fields, unknown schema versions, unsupported algorithms, wrong types, alternate number/string encodings, malformed UTF-8, and noncanonical timestamps. Resolve `key_id` only through trusted Gate configuration and require its configured reviewer ID/provider to match the signed values. Compute SHA-256 of the canonical payload for audit. Do not sign an unsigned payload and then append binding fields.

### Key configuration and lifecycle

The durable Gate key registry maps `key_id -> (reviewer_id, reviewer_provider, raw 32-byte Ed25519 public key, enabled/revoked state)` in the protected SQLite store. It stores only reviewer public-key records and lifecycle status—not a general credential platform, passwords, or private keys. Only enabled, non-revoked keys may authorize a new reservation. Key IDs are stable and unique; duplicate mappings fail closed. A trusted operator-only control path provisions and revokes keys; it is not exposed to the autonomous executor. Gate never receives or stores a private key. The external reviewer signer retains the private key and signs only after reviewing the exact proposal digest and plan/task binding. Rotation adds a new key before signing with it, then revokes the prior key for new executions; historical signatures remain verifiable using the retained public key, but cannot grant or retain ACTIVE capability. Key status, signature, and lease state are checked in the same SQLite transaction at execution reservation time. No PKI or key server is in scope.

### API and durable lease

Proposed public API:

```python
@dataclass(frozen=True)
class SignedMutationVerdict:
    canonical_payload: bytes
    signature: bytes

@dataclass(frozen=True)
class VerifiedReviewerVerdict:
    review_id: str
    task_id: str
    plan_revision: int
    plan_digest: str
    proposal_digest: str
    reviewer_id: str
    reviewer_provider: str
    implementer_id: str
    verdict: str
    reviewed_at: datetime
    key_id: str
    payload_digest: str

@dataclass(frozen=True)
class MutationLeaseRecord:
    authorization_id: str
    review_id: str
    task_id: str
    plan_revision: int
    plan_digest: str
    proposal_digest: str
    reviewer_id: str
    reviewer_provider: str
    implementer_id: str
    key_id: str
    reviewed_at: datetime
    issued_at: datetime
    expires_at: datetime
    status: AuthorizationLeaseStatus  # ACTIVE, RESERVED, CONSUMED, CONSUMED_UNCERTAIN, REVOKED, EXPIRED
    reservation_id: str | None
    payload_digest: str

class GateMutationAuthority:
    def __init__(self, store: StateStore, *, implementer_id: str): ...
    def record_signed_verdict(self, task_id: str, verdict: SignedMutationVerdict) -> MutationLeaseRecord | None: ...
    def get_active_authorization(self, task_id: str, proposal: MutationProposal) -> MutationLeaseRecord: ...
    def register_reviewer_key(self, key_id: str, reviewer_id: str, reviewer_provider: str, public_key: bytes) -> None: ...  # trusted operator-only
    def revoke_reviewer_key(self, key_id: str, *, reason: str) -> None: ...  # trusted operator-only
    def revoke(self, authorization_id: str, *, reason: str) -> None: ...
    def acquire_write_lease(self, task_id: str, authorization_id: str, proposal: MutationProposal) -> AbstractContextManager[MutationLease]: ...
```

`implementer_id` is a required immutable value from trusted Gate configuration at authority construction; it is never accepted per-verdict or from the autonomous executor. `GateMutationAuthority` obtains UTC time internally; the production constructor accepts no caller-supplied clock. Tests freeze the private clock seam only. `record_signed_verdict` reloads state itself, checks that the task is still `IMPLEMENTING`, has current plan-level human approval, plan/revision and exact current proposal all match the signed reviewer verdict, verifies trusted active reviewer key/provider and reviewer independence against that configured implementer identity, and enforces reviewer freshness. It persists each valid signed verdict once. For `reject`, it records the audit verdict and returns `None`; it does not create an authorization row. For `approve`, it generates a new Gate-owned `authorization_id`, `issued_at`, and pre-reservation `expires_at` and transactionally persists these values with signed verdict bytes, signature, payload digest, verification metadata, and status `ACTIVE`. Repeated `review_id` or payload digest is rejected (no idempotent replay); reviewers cannot choose or extend Gate lease IDs or timestamps. `get_active_authorization` returns only the exact current ACTIVE row matching task/proposal; `issue_permit` binds that authorization ID without reserving it. `acquire_write_lease` requires the permit's same authorization ID, so it cannot silently switch to another approval. The Gate persists a UTC high-water mark and fails closed if the system clock moves backwards; a forward jump may expire an ACTIVE authorization early, never extend it. The exact proposal uses the existing `canonical_mutation_proposal_digest`; the signed task plan binding uses existing `canonical_plan_digest`.

`acquire_write_lease` opens and commits its own `BEGIN IMMEDIATE` StateStore transaction before the final filesystem/state transaction; it must never be called from inside a `with_current_state_transaction` callback. It reloads and re-verifies the persisted signed reviewer bytes and current reviewer-key mapping/enabled/revoked state, every task/plan/proposal binding, ACTIVE authorization expiry, current plan-level approval, and exact operation/arguments. In that transaction it transitions `ACTIVE -> RESERVED`, assigns/persists a fresh reservation ID, and commits the reservation durably before any target replacement. `GateWriteService.execute` holds the resulting lease context around the separate `with_current_state_transaction` call. Inside that callback it revalidates current task/proposal/approval/workspace against the already-persisted RESERVED lease, performs final identity/edge checks and `os.replace`, and writes execution audit. This avoids nested `BEGIN IMMEDIATE` and ensures a later audit/state-transaction rollback cannot undo the reservation. The context finalizer uses a new transaction: known completion/failure becomes `CONSUMED`; ambiguous outcome becomes `CONSUMED_UNCERTAIN`. If finalization itself fails, the durable row remains RESERVED and restart recovery makes it uncertain. Wall-clock expiry never returns RESERVED to ACTIVE; no timeout makes it reusable. Only an unreserved ACTIVE authorization can transition to REVOKED or EXPIRED. Revocation and reservation serialize on the same database: if revocation wins, reservation is denied; if reservation wins, that already-reserved atomic WRITE may finish, but the authorization cannot be used again. Revocation is append-only audit evidence.

On restart, every `RESERVED` authorization is conservatively changed to `CONSUMED_UNCERTAIN` before any new authorization can be accepted; never restore it to `ACTIVE`, regardless of elapsed time, and require a newly signed verdict/new authorization ID. Only an unreserved `ACTIVE` authorization can expire. State corruption or inability to complete recovery blocks writes. Persist authorization state, audit rows, and the UTC high-water mark in SQLite, not in-memory locks alone. V1 supports one active Gate authority process per DB; an encountered reservation is treated as orphaned and consumed uncertain. The existing in-process write permit remains bound to the authorization and exact proposal but cannot independently restore authority.

### Fail-closed matrix

Block without writing if: trust configuration absent/ambiguous; crypto backend absent; malformed/noncanonical/duplicate-key payload; signature invalid; unknown, inactive, expired, or revoked key; key/reviewer/provider mismatch; reviewer equals implementer; wrong schema/verdict; reviewer timestamp invalid/future/stale; repeated review ID, authorization ID, or payload replay; task/plan revision/plan digest/proposal digest mismatch; task lacks current human plan approval or is not implementing; proposal/arguments differ; Gate lease expired/revoked/used/reserved; DB busy/corrupt/unavailable; restart finds unresolved reservation; clock is not UTC-aware; or any verifier/storage callback raises. No permissive injected provider fallback is allowed in production construction.

---

### Task 1: Define and Verify the Signed Verdict Contract

**Files:**
- Create: `engineering-gate/engineering_gate_core/signed_authorization.py`
- Create: `engineering-gate/requirements.txt`
- Create: `docs/development/signed-authorization.md`
- Modify: `engineering-gate/engineering_gate_core/models.py`
- Create: `tests/test_signed_authorization.py`

**Interfaces:**
- Produces `SignedMutationVerdict`, `ReviewerPublicKey`, `VerifiedReviewerVerdict`, and `SignatureVerificationError` with the exact fields and checks defined above; the reviewer public-key registry is persisted and queried through `StateStore`.
- `canonical_signed_verdict(payload: Mapping[str, object]) -> bytes` and `verify_signed_verdict(verdict: SignedMutationVerdict, key_record: ReviewerPublicKey, *, now: datetime, implementer_id: str) -> VerifiedReviewerVerdict`; fixed v1 timing policy is applied internally, and `GateMutationAuthority` obtains `key_record` from the current trusted registry inside `StateStore` transactions.
- Requires `cryptography` Ed25519 public-key verification; no handwritten crypto or implicit key loading.

- [ ] **Step 1: Add failing tests for canonical schema and cryptographic verification**

Test canonical serialization against a fixed, literal expected byte string and fixed Ed25519 public key/signature test vector; assert valid verdict returns all bindings and payload digest. Add rejection tests for noncanonical whitespace/key order, duplicate/ambiguous keys, unknown/missing fields, unsupported schema version, unsupported signature algorithm, non-UTF-8, wrong types, invalid signature, wrong domain separator, mismatched reviewer/key mapping, revoked/unknown key ID, and unavailable crypto backend. Assert the missing-backend path raises a specific actionable error.

- [ ] **Step 2: Run the focused tests and verify the expected failures**

Run: `python3 -m unittest tests.test_signed_authorization -v`
Expected: FAIL because module/types are not implemented.

- [ ] **Step 3: Implement strict parser, canonical bytes, trust lookup, and verification**

Implement exact-field validation, duplicate-key-rejecting JSON parsing, canonical-byte equality, domain-separated Ed25519 verification, explicit schema/algorithm checks, `key_id` lookup and enabled/revoked-state validation, reviewer/provider match, reviewer/implementer distinction, canonical UTC timestamp validation, future/staleness checks, and maximum review age. Preserve signature bytes and payload digest only; never accept private key material. Keep the core import usable for read-only operations when `cryptography` is missing, but raise the documented fail-closed error on signature verification.

- [ ] **Step 4: Add field-by-field binding and clock-boundary tests**

For each of review ID, task ID, plan revision, plan digest, proposal digest, reviewer identity/provider, implementer identity, key ID, and `reviewed_at`, mutate only that claim after signing and assert verification fails. Test stale/future review time and UTC-naive clock rejection. Separately assert Gate rejects any reviewer-supplied `authorization_id` or lease timestamps as unknown schema fields and creates its own authorization ID and lease timestamps from the trusted Gate clock source.

- [ ] **Step 5: Run focused suite**

Run: `python3 -m unittest tests.test_signed_authorization -v`
Expected: PASS; no test may accept a noncanonical or untrusted signed representation.

### Task 2: Persist Verdicts, Lease State, Revocation, and Restart Recovery

**Files:**
- Modify: `engineering-gate/engineering_gate_core/models.py`
- Modify: `engineering-gate/engineering_gate_core/state_store.py`
- Create: `tests/test_authorization_leases.py`
- Modify: `tests/test_state_store.py`

**Interfaces:**
- Add immutable `MutationLeaseRecord` with Gate-generated authorization ID, reviewer `review_id`, task/plan/proposal bindings, reviewer/key identity, reviewer `reviewed_at`, Gate-generated `issued_at`/pre-reservation `expires_at`, status (`ACTIVE`, `RESERVED`, `CONSUMED`, `CONSUMED_UNCERTAIN`, `REVOKED`, `EXPIRED`), reservation ID, and signed-payload digest.
- Internal `StateStore._record_verified_verdict(task_id, verified, signed_payload, signature, *, authorization_id: str | None, issued_at: datetime | None, expires_at: datetime | None) -> MutationLeaseRecord | None` stores every valid review audit; it creates a lease only when verdict is `approve`. `get_active_authorization` performs a read-only exact task/proposal lookup. `reserve_mutation_lease(task_id, authorization_id, expected_proposal_digest, now)` opens and commits its own `BEGIN IMMEDIATE` transaction before the write transaction; `finish_mutation_lease(...)` uses a separate transaction. These must not be called from inside `with_current_state_transaction`. That existing transaction validates the `ExecutionTransactionResult` by querying the RESERVED lease through its already-open connection (no nested `_connect`/`BEGIN IMMEDIATE`), matching authorization ID and task/plan/proposal bindings. `revoke_mutation_authorization`, key revocation, and restart recovery are transactional. Only `GateMutationAuthority` records/verifies leases; plain task-state `MutationAuthorization` is ignored for production authority.
- When plan revision or exact mutation proposal changes, atomically revoke any unreserved ACTIVE authorization rows for that task and append the invalidation reason; stale rows must also fail digest/revision checks at lookup/reservation.
- Migrate schema v4 to v5 transactionally; v1-v3 migration behavior remains supported. Legacy injected `MutationAuthorization` records cannot become trusted signed leases.

- [ ] **Step 1: Write failing transactional and restart tests**

Test one ACTIVE authorization reserves once; a second reservation fails; wrong task/proposal fails; valid `reject` is durably audited but returns no lease; key registration/revocation is persisted; revocation before reserve blocks; revocation and reservation serialize deterministically; a key revoked after authorization issuance prevents reservation; only unreserved ACTIVE authorizations expire/revoke; RESERVED never returns to ACTIVE after elapsed time; known completion becomes CONSUMED; crash/ambiguous completion becomes CONSUMED_UNCERTAIN; a failure to update final execution audit after `os.replace` cannot roll back the already-committed RESERVED row; replayed review ID is rejected; Gate-generated authorization ID/issued/expiry timestamps are persisted and are not selectable in the signed reviewer payload; closing/reopening with a RESERVED row marks it `CONSUMED_UNCERTAIN`; a backwards UTC clock step fails closed; corrupt migration/recovery blocks writes; v4 task data remains loadable but has no trusted signed authorization.

- [ ] **Step 2: Run focused store tests to verify failure**

Run: `python3 -m unittest tests.test_authorization_leases tests.test_state_store -v`
Expected: FAIL because lease records and APIs/schema v5 do not exist.

- [ ] **Step 3: Implement schema-v5 migration and durable transitions**

Add validated `reviewer_keys`, signed-verdict/audit, and authorization/lease tables or equivalent store schema with unique key/review/authorization IDs and payload digest, task bindings, key-enabled/revoked state, lease status, reservation ID, timestamps, and append-only revocation audit. Use `BEGIN IMMEDIATE` for key registration/revocation, verdict recording, reserve, finish, and authorization revocation. In the reservation transaction, reload the stored public key, verify its current identity/provider/status and signed verdict, validate every task/plan/proposal binding, then transition ACTIVE to RESERVED. Revoking a key atomically disables it and marks all unreserved ACTIVE authorizations from that key REVOKED. Preserve revoked public keys for historical audit verification. Validate schema constraints and indexes as strictly as existing `execution_audit`; never decode a legacy provider claim as verified.

- [ ] **Step 4: Implement conservative recovery and migration cases**

At Store initialization, transactionally convert every persisted `RESERVED` authorization to `CONSUMED_UNCERTAIN`; expire only elapsed unreserved `ACTIVE` authorizations; reject corrupted records and unsupported versions. Recovery must be idempotent and can never transition `RESERVED` back to `ACTIVE`.

- [ ] **Step 5: Run focused store tests**

Run: `python3 -m unittest tests.test_authorization_leases tests.test_state_store -v`
Expected: PASS with assertions for both migrated legacy state and restart safety.

### Task 3: Bind Signed Review to Existing Lifecycle and Exact Proposal

**Files:**
- Create: `engineering-gate/engineering_gate_core/mutation_authority.py`
- Modify: `engineering-gate/engineering_gate_core/workflow.py`
- Modify: `engineering-gate/engineering_gate_core/state_store.py`
- Modify: `tests/test_workflow.py`
- Modify: `tests/test_authorization_leases.py`

**Interfaces:**
- Add `GateMutationAuthority.record_signed_verdict(...)` as specified above, delegating signature checks to Task 1 and transactional persistence to Task 2.
- Continue using `canonical_plan_digest(plan)` and `canonical_mutation_proposal_digest(proposal)` as the authoritative digests; do not create a second proposal canonicalizer. Remove/restrict `StateStore.record_mutation_authorization` and `workflow.record_mutation_authorization` so a caller-created plain `MutationAuthorization` can never establish an authorization row or make the state appear write-authorized.

- [ ] **Step 1: Write failing lifecycle binding tests**

Build a task through current plan-level requester approval and `IMPLEMENTING`; sign and record a correct verdict. Assert rejection if user approval is missing/denied/stale, reviewer is implementer, task is in another lifecycle state, proposal is absent/changed, plan is revised, any digest differs, or signed `review_id` is replayed. Assert an approved proposal change clears its prior authorization as existing workflow invalidation rules require.

- [ ] **Step 2: Run focused workflow tests to verify failure**

Run: `python3 -m unittest tests.test_workflow tests.test_authorization_leases -v`
Expected: FAIL because no GateMutationAuthority binds signed claims to live workflow state.

- [ ] **Step 3: Implement Gate-owned record path**

On each verdict submission, reload latest state, verify signature and configured independent reviewer, compare every signed binding to that state and canonical proposal, require current human approval and `IMPLEMENTING`, then persist exactly once under transaction-time revalidation. Revalidate signature/trust status in the transaction or bind a trust-configuration generation so rotation/revocation cannot be bypassed between verification and record.

- [ ] **Step 4: Test trust rotation and workflow invalidation**

Test that a disabled/revoked key after authorization issuance prevents that still-ACTIVE authorization from reserving; a valid old signature remains audit-verifiable but not leaseable, plan/proposal updates atomically revoke unreserved ACTIVE leases, and requester approval remains separately required. Test key revocation racing reservation through the same StateStore transaction: revocation first denies; reservation first may finish once but can never be reused.

- [ ] **Step 5: Run focused workflow suite**

Run: `python3 -m unittest tests.test_workflow tests.test_authorization_leases -v`
Expected: PASS; signatures never impersonate or replace the requester approval receipt.

### Task 4: Integrate Durable One-Shot Authority With Gate-Owned WRITE

**Files:**
- Modify: `engineering-gate/engineering_gate_core/a3_execution.py`
- Modify: `engineering-gate/engineering_gate_core/__init__.py`
- Modify: `tests/test_a3_gate_owned_write.py`

**Interfaces:**
- `GateMutationAuthority.get_active_authorization(task_id, proposal)` returns a currently valid exact `MutationLeaseRecord`; `GateWriteService.issue_permit` binds its authorization ID. `GateMutationAuthority.acquire_write_lease(task_id, authorization_id, proposal)` returns a context manager that durably reserves that same ID in its own SQLite transaction and yields typed `MutationLease` bound to authorization ID, reservation ID, task/revision/plan/proposal digests, and reviewer identity.
- `GateWriteService` receives a Gate-owned `GateMutationAuthority` backed by the same StateStore; remove the production contract requiring arbitrary `authorization_verifier`, `authorization_lease_provider`, or caller-supplied `MutationAuthorization` objects. Do not expose operator-only key registration/revocation controls to the executor.
- Existing write permit still binds exact operation, argument digest and authorization; filesystem replacement remains descriptor-relative and single-file WRITE only.

- [ ] **Step 1: Add failing end-to-end real-signature WRITE tests**

Replace the production-path synthetic provider fixture with a deterministic Ed25519 test key/public-key registry, signed exact verdict, StateStore authorization, and actual `GateWriteService`. Assert valid signed review plus separate requester approval allows exactly one exact WRITE. Assert invalid signature, wrong payload/arguments, expired-before-reservation authorization, revoked key after issuance, duplicate execution, missing trust config, consumed authorization, direct caller-created `MutationAuthorization`, and direct legacy state transition perform no file change. Assert an expired RESERVED operation never returns to ACTIVE and an ambiguous/crashed execution is CONSUMED_UNCERTAIN.

- [ ] **Step 2: Run focused WRITE tests to verify failure**

Run: `python3 -m unittest tests.test_a3_gate_owned_write -v`
Expected: FAIL because production execution still depends on injected trust callbacks.

- [ ] **Step 3: Integrate reserve/hold/consume around existing critical section**

`GateWriteService.issue_permit` performs non-reserving current-state/authorization checks. In `execute`, enter `GateMutationAuthority.acquire_write_lease` before calling the existing `state_transaction`; lease acquisition opens and commits its own SQLite reservation transaction and must never run inside the `with_current_state_transaction` callback. Then the existing callback revalidates live task/plan/proposal/approval/workspace against the RESERVED lease, performs descriptor-relative staging/final checks/`os.replace`, and inserts execution audit. Exit the lease context only after the state transaction has committed or failed. Finalization uses a separate transaction. If replacement succeeded but the audit/state commit fails, preserve the already committed reservation as CONSUMED_UNCERTAIN (or leave RESERVED for startup recovery); never roll it back to ACTIVE. A known pre-replacement failure after reservation burns it as CONSUMED. Return/audit authorization ID, payload digest, key ID, reviewer/provider, and reservation ID without signature secrets.

- [ ] **Step 4: Add race and exception-path tests**

Test two concurrent attempts with one authorization (only one reaches replacement); revoke-key-before-reserve blocks even an existing ACTIVE authorization, revoke-authorization-before-reserve blocks, revoke-after-reserve cannot split the already-reserved write, state transaction failure after filesystem replacement reports outcome unknown and leaves it CONSUMED_UNCERTAIN, and pre-reservation validation failures do not consume an unused ACTIVE authorization.

- [ ] **Step 5: Run focused WRITE suite**

Run: `python3 -m unittest tests.test_a3_gate_owned_write -v`
Expected: PASS, preserving the existing no-follow/descriptor-relative WRITE guarantees and failing closed for every denied case.

### Task 5: Public API, Regression Verification, and Contract Closure

**Files:**
- Modify: `engineering-gate/engineering_gate_core/__init__.py`
- Modify: `tests/test_a3_gate_owned_write.py`
- Modify: `tests/test_authorization_leases.py`
- Modify: `tests/test_state_store.py`
- Create: `docs/development/signed-authorization.md`
- Completed prerequisite, unchanged during authorization work: `engineering-gate/engineering_gate_core/verification_execution.py`, `engineering-gate/engineering_gate_core/models.py`, `tests/test_verification_runner.py`, `tests/test_verification_store.py`

**Interfaces:**
- Export `GateMutationAuthority`, `ReviewerPublicKey`, and signed verdict/lease types from the core package. Do not export private-key loading helpers or operator-only key registry controls to the autonomous executor.
- The execute-once regression is **completed and verified**: a command covering multiple criteria executes once, all criterion associations share one Gate-issued `execution_id`, separate commands have distinct IDs, persisted IDs round-trip, and pre-field legacy evidence remains `None`. Do not alter this prerequisite during authorization work.

- [ ] **Step 1: Add public import and cross-task isolation regression tests**

Assert the core public API imports without Hermes/runtime modules. Assert two tasks with identical proposal contents but different task IDs cannot share verdicts/leases, a public key configured for one reviewer/provider cannot verify as another, revoked keys cannot authorize previously ACTIVE rows, and directly constructed/stale `MutationAuthorization` objects cannot cause `GateWriteService` to mutate without a currently persisted signed authorization and one-shot reservation.

- [ ] **Step 2: Run full focused and regression suites**

Run: `python3 -m unittest tests.test_signed_authorization tests.test_authorization_leases tests.test_workflow tests.test_state_store tests.test_a3_gate_owned_write tests.test_verification_runner tests.test_verification_store -v`
Expected: PASS, including execute-once regression.

- [ ] **Step 3: Run complete checks**

Run: `python3 -m unittest discover -s tests -q`
Expected: all tests pass. Then run `python3 -m py_compile engineering-gate/engineering_gate_core/*.py tests/test_*.py` and `git diff --check`. Confirm the missing-crypto test fails closed with its documented actionable error; confirm `docs/development/signed-authorization.md` states that `cryptography` is required, missing backend blocks verification, and the copy-only `setup.sh` is the old v4 installer, not a v6 installer.

- [ ] **Step 4: Review change scope and migration behavior**

Run: `git status --short` and inspect the full diff. Confirm only the File Map production/test/docs paths changed, plus the approved plan; `setup.sh` remains untouched, no private keys/secrets are added, and no adapter/UI/deployment changes or unsupported mutation surfaces appear. After all tests, compile, and diff checks pass, commit the execute-once regression and authority work together on the current branch, then push the branch. Do not push if any check fails.

---

## Approved Implementation Boundaries and Defaults

Nik approved the plan with the following required refinements: (1) expiry applies only while an authorization is unreserved ACTIVE; once RESERVED, it cannot expire back into usability and recovery consumes it or marks it uncertain; (2) the signed envelope explicitly includes `schema_version: 1` and `signature_algorithm: "Ed25519"`; (3) live key/reviewer mapping and status are revalidated transactionally before reservation so revocation blocks existing ACTIVE authorizations; and (4) dependency/missing-backend behavior and the legacy v4 installer limitation are documented without changing `setup.sh`.

1. **Signature primitive/dependency:** Use Ed25519 through `cryptography>=46,<51`, declared in `engineering-gate/requirements.txt`; do not substitute custom cryptography or silently switch algorithms.
2. **Reviewer and implementer identities:** Bind reviewer ID/provider to configured trusted public keys. Require an immutable `implementer_id` in Gate configuration, never per verdict/request. The signature proves key possession, not the human behind the key; actual provider/account separation remains an operator policy.
3. **Key provisioning/storage:** Store only public reviewer keys and enabled/revoked status in the protected SQLite registry. Key registration/revocation is operator-only and not exposed to the executor; reviewer private keys remain external. `setup.sh` stays unchanged as the old v4 copy-only installer; developers/operators must explicitly install the declared requirement. The new development doc describes this and the fail-closed missing-backend behavior.
4. **Freshness/lease lifetime/clock:** Reviewer verdict freshness and unreserved ACTIVE authorization lifetime are each 300 seconds; use whole-second UTC with zero clock-skew tolerance. RESERVED never expires back to usability or returns to ACTIVE. Persist a UTC high-water mark; fail closed on clock rollback; forward jumps may expire unreserved ACTIVE authorization early.
5. **Crash/revocation semantics:** On restart, any persisted RESERVED authorization becomes permanently CONSUMED_UNCERTAIN. Revocation blocks unreserved authorization; an already atomically RESERVED critical section may finish, but cannot be reused.
6. **Storage evolution:** Migrate StateStore schema v4 to v5; retain legacy records as readable evidence but never trust unsigned/injected legacy authorizations. Keep append-only application-level audit; direct same-UID/database-file tampering is outside this slice's threat model.
7. **Reviewer independence:** Configured reviewer ID/provider must differ from Gate's immutable implementer ID. Core does not prove real-world human/account separation; enforce that operationally through distinct reviewer-key custody.
8. **Process/recovery limit:** V1 supports one active authority process per SQLite StateStore. A RESERVED record found on recovery becomes CONSUMED_UNCERTAIN; multi-process ownership/heartbeat coordination is deferred.
9. **Reviewer implementation boundary:** Core validates signed verdicts but does not implement the independent reviewer model/service, private-key custody, or review UX. The external reviewer signer must inspect the exact bound proposal before signing.
10. **Gate capability representation:** The reviewer signature plus Gate-generated durable SQLite lease row is the capability; no second Gate signing key is added. `GateWriteService` revalidates the signature and row on each write. A portable Gate-signed token or protection against direct local DB tampering is outside scope.
11. **Scope boundary:** Core-only WRITE authorization; Hermes adapter, `PATCH`/`DELETE`/`RENAME`, deployment/installer changes, UI, and cleanup remain deferred.

## Self-Review

- **Spec coverage:** Implements task/plan/proposal-bound authorization and independently attributable adversarial review evidence while preserving the separate plan-level requester receipt; fail-closed rules, task isolation, auditable evidence, core host-neutrality, and exact proposal enforcement each have test tasks. Explicitly deferred components remain outside the file map.
- **Placeholder scan:** No TODO/TBD/fill-in details or unspecified generic “add validation” steps remain; APIs, record fields, canonical encoding, migration version, lease states, behavior, commands, and expected outcomes are specified here.
- **Type consistency:** The verifier returns `VerifiedReviewerVerdict`; `GateMutationAuthority` records it through `StateStore` and returns a Gate-generated `MutationLeaseRecord`; lease acquisition yields an internal typed `MutationLease`; execution consumes that lease. Existing digest helpers remain the single source for plans/proposals.
- **Review Focus coverage:** Each listed input/race/restart condition has a named test in Tasks 1–4.
- **Forgery boundary:** Direct model construction cannot create production authority; the persistence state and signature must be rechecked at the write boundary. Task 5 verifies this with an attempted forged legacy authorization and no filesystem change.
- **Regression status:** Task 0 is complete; authorization Tasks 1–4 must preserve its files/contracts. Parent verification is repeated on the final combined tree before authority implementation.
