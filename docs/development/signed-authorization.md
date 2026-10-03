# Signed reviewer-verdict contract (development)

The v6 signed-verdict verifier requires Python package `cryptography>=46,<51` for Ed25519. Provision it in the runtime with `python3 -m pip install -r engineering-gate/requirements.txt` (prefer an isolated virtual environment). The core remains importable for read-only operations if the backend is absent, but any attempted signature verification fails closed with an actionable `SignatureVerificationError`; there is no handwritten or fallback cryptography.

Verdicts are canonical UTF-8 JSON with an exact schema and detached Ed25519 signature over the domain-prefixed canonical bytes. The Gate resolves reviewer keys from trusted configuration, validates identity/provider, key status, bindings, and strict UTC freshness. Keep private signing keys outside this repository and outside Gate state.

Authorization timing uses one immutable effective `AuthorizationTimingPolicy`, configured on StateStore and shared by verdict verification, authority issuance, persistence, and reservation-time signature revalidation. The v1 defaults are 300 seconds for reviewer freshness and 300 seconds for an unreserved ACTIVE lease; deployments may configure stricter limits (review age may be zero, lease lifetime must be positive) but never exceed either v1 ceiling. StateStore rejects stored lease rows whose expiry interval exceeds the effective policy. RESERVED leases remain one-shot and are not made reusable by expiry.

For A3 WRITE, all preflight binding checks complete before durable lease reservation. The `ACTIVE → RESERVED` transition commits before any staging filesystem object is created. If reviewer-key revocation commits first, reservation is denied: the authorization becomes `REVOKED`, and no staging object is created. If reservation commits first, it is the mutation linearization point: a later key revocation does not cancel the already-reserved attempt, which may stage, replace, read back, and audit; it ends `CONSUMED` on ordinary success/failure or `CONSUMED_UNCERTAIN` after an ambiguous crash. A staging failure also burns the reservation as `CONSUMED` and cleans up the temporary file. Process recovery converts any still-`RESERVED` lease to `CONSUMED_UNCERTAIN`; orphan staging files are not reusable. The final target replacement, readback, and audit remain in the final StateStore transaction.

`setup.sh` remains the old v4 copy-only installer. It does not provision this dependency and is **not a v6 installer**. This core slice is not yet a Hermes integration; callers must provision the declared dependency separately and must not treat missing verification capability as authorization.
# Approval packet and runtime dispatch correlation

Telegram plan approval discloses and binds one canonical packet containing the
task objective, inspection evidence, analysis, plan, blast radius, plan-review
verdict/findings, revision, plan digest, workspace identity, and approval request
ID. The adapter serializes this packet deterministically, displays those exact
bytes with their SHA-256 packet digest, and stores that digest in the approval
sidecar. Callback consumption and Stage-2 write interception independently
rederive the packet from current Gate state and fail closed on any mismatch.

Hermes `turn_id` and `tool_call_id` are runtime-dispatch correlation values,
not durable approval identity. The adapter compares them against the current
trusted dispatch context when handling each call; they intentionally are not
persisted in the approval sidecar because subsequent dispatches can have new
correlation IDs while referring to the same approved task and Telegram route.
