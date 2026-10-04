# Engineering Gate v5 Core: Verification and Nested WRITE

## Scope

This note documents the checked v5 core slice on branch `engineering-gate-v5-binding-audit`. It covers provenance-bound verification execution and descriptor-relative nested `WRITE` only; it does not describe a live Hermes integration.

## Gate-observed verification

An approved `Plan` digest binds each `VerificationCommand`'s structured argv, criterion IDs, timeout, and output cap. `GateVerificationRunner.run_all(task_id)` loads the task and resolves commands only from its approved plan; callers cannot substitute a command at run time. Commands are executed without a shell (`shell=False`).

Verification records bind task ID, plan revision and digest, criterion ID, and workspace identity. A criterion passes only when the observed process has `exit_code == 0` and `timed_out` is false. `AGENT_CLAIM` evidence is not verification and cannot satisfy a criterion. Captured stdout/stderr are drained to EOF and hashed in full while retained output and the redacted summary are capped. If either stream fails to reach EOF within the drain deadline, the runner raises `OutputIncompleteError` with the direct process return code and persists no evidence for that attempt. Summary truncation at the configured output cap does not change the observed exit-code result.

Persistence uses an atomic `StateStore` transaction that revalidates the task, revision, plan digest, criterion, and workspace bindings before recording evidence. Migrations from v1–v3 clear legacy verification, result-review, and handoff claims and reopen affected planned records (or fail them closed when no plan exists). Legacy claims are never reconstructed as `GATE_OBSERVED` or treated as passing.

## Nested WRITE path handling

Nested `WRITE` accepts canonical relative POSIX paths only. It does not create directories. The writer traverses each component relative to a pinned workspace-root descriptor, opening directories descriptor-by-descriptor with `O_DIRECTORY` and `O_NOFOLLOW`; symlink traversal is rejected. Staging, final replace, readback, and cleanup operate via the pinned leaf-parent directory descriptor, rather than resolving the path again from the ambient filesystem namespace.

Atomic replacement preserves an existing regular file's mode and replaces its directory entry rather than mutating the existing inode; replacing a nested hard link therefore leaves the external inode's content unchanged. Review the implementation/tests when changing these invariants; do not infer that a pathname remains attached to the same directory merely because its text is unchanged.

Ancestor renames/detachment have explicit semantics: components not yet opened are resolved at safe open time under their pinned parent; already-opened directory descriptors cannot be redirected by later renames. Detachment detected before final replacement fails. A race after the final detachment check can still cause the operation to write only to the pinned object; the audit records `path_detached`, then raises `WorkspacePathDetached` without exposing the path. This is a bounded descriptor-relative guarantee, not a general filesystem transaction against hostile actors.

## Security and platform limits

- This is not an OS sandbox. `shell=False` and the selected working directory do not restrict a verification command's filesystem or network access.
- There is no protection against hostile same-UID processes or OS-level tampering.
- Verification's pinned working directory currently uses Linux `/proc/self/fd`; unsupported platforms fail closed.
- The implementation depends on directory-FD and related `O_DIRECTORY`/`O_NOFOLLOW` behavior. Platforms lacking the required features cannot claim these traversal guarantees and must fail closed rather than silently fall back to pathname traversal.
- The audit is append-only through the application interface, not immutable against direct database-file tampering.
- The authorization verifier/lease remains an injected boundary. Tests use synthetic implementations; there is no production human-authority implementation in this slice.

## Deferred

This iteration does not include a Hermes adapter, any live Hermes changes or installation, `PATCH`, `DELETE`, `RENAME`, `EXECUTE`, delegation, or broader version cleanup.

## Verification performed

The checked tree passed:

```sh
python3 -m unittest discover -s tests -q
python3 -m py_compile engineering-gate/engineering_gate_core/*.py tests/test_*.py
git diff --check
```

The unit suite reported **205 tests passed**.
