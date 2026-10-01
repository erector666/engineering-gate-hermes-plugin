"""Host-neutral SQLite persistence for lifecycle state (single-host only)."""
from __future__ import annotations

from dataclasses import fields, is_dataclass, replace
from enum import Enum
import json
import os
from pathlib import Path
import stat
import sqlite3
import tempfile
import types
import typing

from . import models
from .models import ApprovalReceipt, MutationAuthorization, MutationProposal, TaskID, TaskStateRecord
from .workflow import Event, TransitionError, canonical_mutation_proposal_digest, canonical_plan_digest, new_task, record_approval, _record_gate_observed_verification, record_mutation_authorization, record_mutation_proposal, capture_workspace_identity, transition

_SCHEMA_VERSION = 4
_DATACLASSES = {name: value for name, value in vars(models).items()
                if isinstance(value, type) and is_dataclass(value)}
_ENUMS = {name: value for name, value in vars(models).items()
          if isinstance(value, type) and issubclass(value, Enum)}
_ENUMS["Event"] = Event


class StateStoreError(RuntimeError):
    """Stored lifecycle state is missing, corrupt, or incompatible."""


def _ensure_private_parent(parent: Path) -> None:
    """Create missing path components and validate the immediate parent on POSIX."""
    if os.name == "posix":
        absolute = Path(os.path.abspath(parent))
        component = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            component = component / part
            try:
                mode = component.lstat().st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(mode):
                raise StateStoreError("database parent path must not contain symlinks")
    missing = []
    current = parent
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    if current.exists() and not current.is_dir():
        raise StateStoreError("database parent is not a directory")
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
            if os.name == "posix" and stat.S_IMODE(directory.stat().st_mode) != 0o700:
                raise StateStoreError("unable to create private database directory")
        except FileExistsError:
            if not directory.is_dir():
                raise StateStoreError("database parent is not a directory")
    if os.name == "posix":
        info = parent.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise StateStoreError("database parent must be owned by the current user and not writable by others")


def _prepare_database(path: Path) -> None:
    """Create database without following symlinks; validate existing target."""
    if os.name != "posix":
        return
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        try:
            info = path.lstat()
        except OSError as exc:
            raise StateStoreError("unable to inspect database path") from exc
        if not stat.S_ISREG(info.st_mode):
            raise StateStoreError("database path must be a regular file, not a symlink")
        if info.st_uid != os.getuid():
            raise StateStoreError("database file must be owned by the current user")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise StateStoreError("database file permissions must be exactly 0600")
    except OSError as exc:
        raise StateStoreError("unable to create private database file") from exc
    else:
        os.close(fd)


def _encode(value):
    if isinstance(value, Enum):
        return {"$enum": type(value).__name__, "value": value.value}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        return {"$type": type(value).__name__, **{f.name: _encode(getattr(value, f.name)) for f in fields(value)}}
    if isinstance(value, tuple):
        return {"$tuple": [_encode(item) for item in value]}
    raise TypeError(f"unsupported lifecycle value: {type(value).__name__}")


def _matches_type(value, annotation):
    """Check a decoded value against the JSON-safe model annotation."""
    if hasattr(annotation, "__supertype__"):
        return _matches_type(value, annotation.__supertype__)
    if annotation is typing.Any:
        return False
    if annotation is type(None):
        return value is None
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin in (typing.Union, types.UnionType):
        return any(_matches_type(value, member) for member in args)
    if origin is tuple:
        if not isinstance(value, tuple):
            return False
        if len(args) == 2 and args[1] is Ellipsis:
            return all(_matches_type(item, args[0]) for item in value)
        return len(value) == len(args) and all(
            _matches_type(item, item_type) for item, item_type in zip(value, args)
        )
    if origin is not None:
        return False
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return type(value) is annotation
    if isinstance(annotation, type) and is_dataclass(annotation):
        return type(value) is annotation
    if annotation is int:
        return type(value) is int
    if annotation is bool:
        return type(value) is bool
    if annotation is float:
        return type(value) is float
    if annotation is str:
        return type(value) is str
    return isinstance(value, annotation) if isinstance(annotation, type) else False


def _decode(value, *, allow_legacy_missing=False):
    if isinstance(value, list):
        raise StateStoreError("unexpected untyped JSON list")
    if not isinstance(value, dict):
        return value
    if "$tuple" in value:
        if set(value) != {"$tuple"} or not isinstance(value["$tuple"], list):
            raise StateStoreError("malformed tuple")
        return tuple(_decode(item, allow_legacy_missing=allow_legacy_missing) for item in value["$tuple"])
    if "$enum" in value:
        if set(value) != {"$enum", "value"} or value["$enum"] not in _ENUMS:
            raise StateStoreError("unknown enum")
        try:
            return _ENUMS[value["$enum"]](value["value"])
        except (ValueError, TypeError) as exc:
            raise StateStoreError("invalid enum value") from exc
    if "$type" in value:
        name = value["$type"]
        cls = _DATACLASSES.get(name)
        if cls is None:
            raise StateStoreError("unknown record type")
        expected = {f.name for f in fields(cls)}
        actual = set(value) - {"$type"}
        missing = expected - actual
        allowed = (({"mutation_proposal", "mutation_authorization"} if name == "TaskStateRecord" else
                    {"workspace_identity", "verification_commands"} if name == "Plan" else
                    {"provenance"} if name == "Evidence" else set()) if allow_legacy_missing else set())
        if actual - expected or missing - allowed:
            raise StateStoreError("record fields do not match schema")
        try:
            decoded = {key: _decode(value[key], allow_legacy_missing=allow_legacy_missing) for key in actual}
            decoded.update({key: (() if key == "verification_commands" else
                              models.EvidenceProvenance.AGENT_CLAIM if key == "provenance" else None)
                            for key in missing})
            hints = typing.get_type_hints(cls)
            for key, annotation in hints.items():
                if hasattr(annotation, "__supertype__"):
                    decoded[key] = annotation(decoded[key])
                if not _matches_type(decoded[key], annotation):
                    raise StateStoreError("record field has invalid type")
            if cls is models.ObservedCommandEvidence:
                return cls._restore(**decoded)
            return cls(**decoded)
        except StateStoreError:
            raise
        except (TypeError, ValueError) as exc:
            raise StateStoreError("invalid record") from exc
    raise StateStoreError("untyped object in state")


def _record_json(record):
    return json.dumps(_encode(record), sort_keys=True, separators=(",", ":"))


def _legacy_record_from_json(text):
    """Decode legacy tagged state without treating old verification as trusted."""
    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, UnicodeError, TypeError) as exc:
        raise StateStoreError("corrupt state JSON") from exc
    if not isinstance(raw, dict) or raw.get("$type") != "TaskStateRecord":
        raise StateStoreError("unsupported legacy record type")
    claimed = (bool(raw.get("verification", {}).get("$tuple", ()))
               or raw.get("result_review") is not None or raw.get("handoff") is not None
               or raw.get("state", {}).get("value") == models.TaskState.COMPLETED.value)
    raw = dict(raw)
    raw["verification"] = {"$tuple": []}
    raw["result_review"] = None
    raw["handoff"] = None
    return _record_from_json(json.dumps(raw), allow_legacy_missing=True), claimed


def _record_from_json(text, *, allow_legacy_missing=False):
    try:
        record = _decode(json.loads(text), allow_legacy_missing=allow_legacy_missing)
    except (json.JSONDecodeError, UnicodeError, TypeError) as exc:
        raise StateStoreError("corrupt state JSON") from exc
    if not isinstance(record, TaskStateRecord):
        raise StateStoreError("stored value is not a task state record")
    return record


class StateStore:
    def __init__(self, path: Path):
        self.path = Path(os.path.abspath(Path(path)))
        _ensure_private_parent(self.path.parent)
        _prepare_database(self.path)

    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            connection.execute("BEGIN IMMEDIATE")
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )}
            if not tables:
                connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                connection.execute("INSERT INTO metadata(key,value) VALUES('schema_version',?)", (str(_SCHEMA_VERSION),))
                connection.execute("CREATE TABLE task_state (task_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
                self._create_audit_schema(connection)
            else:
                if "metadata" not in tables:
                    raise StateStoreError("database schema metadata is missing")
                metadata_columns = {row[1] for row in connection.execute("PRAGMA table_info(metadata)")}
                if not {"key", "value"}.issubset(metadata_columns):
                    raise StateStoreError("database schema metadata is malformed")
                rows = connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchall()
                if len(rows) != 1 or type(rows[0][0]) is not str or rows[0][0] not in ("1", "2", "3", str(_SCHEMA_VERSION)):
                    raise StateStoreError("missing, malformed, or unsupported database schema version")
                if "task_state" not in tables:
                    raise StateStoreError("database task state table is missing")
                # Schema v1 accepts only the exact columns used by CRUD: extra
                # columns can make inserts fail, while a non-unique key makes
                # reads and updates ambiguous.
                task_columns = connection.execute("PRAGMA table_xinfo(task_state)").fetchall()
                # table_xinfo includes generated/hidden columns; fail closed if
                # SQLite returns an unexpected row shape or hidden flag.
                if any(len(row) != 7 for row in task_columns):
                    raise StateStoreError("database task state schema is malformed or incompatible")
                actual_schema = [
                    (row[1], row[2].upper(), row[3], row[5], row[6]) for row in task_columns
                ]
                if actual_schema != [("task_id", "TEXT", 0, 1, 0), ("payload", "TEXT", 1, 0, 0)]:
                    raise StateStoreError("database task state schema is malformed or incompatible")
                if rows[0][0] == "1":
                    self._migrate_v1(connection)
                if rows[0][0] in ("1", "2"):
                    self._migrate_v2(connection)
                if rows[0][0] in ("1", "2", "3"):
                    self._migrate_v3(connection)
                self._validate_audit_schema(connection)
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )}
            if tables != {"metadata", "task_state", "execution_audit"}:
                raise StateStoreError("database schema contains missing or unexpected tables")
            metadata_info = connection.execute("PRAGMA table_xinfo(metadata)").fetchall()
            metadata_schema = [(r[1], r[2].upper(), r[3], r[5], r[6]) for r in metadata_info]
            if any(len(r) != 7 for r in metadata_info) or metadata_schema != [("key", "TEXT", 0, 1, 0), ("value", "TEXT", 1, 0, 0)]:
                raise StateStoreError("database schema metadata is malformed")
            metadata_sql = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='metadata'").fetchone()[0].lower().replace(" ", "")
            task_sql = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='task_state'").fetchone()[0].lower().replace(" ", "")
            if "keytextprimarykey" not in metadata_sql or "valuetextnotnull" not in metadata_sql or "task_idtextprimarykey" not in task_sql or "payloadtextnotnull" not in task_sql:
                raise StateStoreError("database table DDL is malformed")
            self._validate_audit_schema(connection)
            connection.commit()
            return connection
        except BaseException:
            connection.rollback()
            connection.close()
            raise

    @staticmethod
    def _create_audit_schema(connection):
        connection.execute("""CREATE TABLE IF NOT EXISTS execution_audit (
            audit_id TEXT NOT NULL PRIMARY KEY, task_id TEXT NOT NULL REFERENCES task_state(task_id),
            revision INTEGER NOT NULL, plan_digest TEXT NOT NULL, proposal_digest TEXT NOT NULL,
            authorization_id TEXT NOT NULL, permit_hash TEXT NOT NULL UNIQUE,
            operation_kind TEXT NOT NULL CHECK(operation_kind='write'), target TEXT NOT NULL,
            argument_digest TEXT NOT NULL, workspace_identity TEXT NOT NULL, started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL, outcome TEXT NOT NULL CHECK(outcome IN ('succeeded','outcome_unknown')),
            resulting_artifact_digest TEXT, path_detached INTEGER NOT NULL CHECK(path_detached IN (0,1)), error_class TEXT,
            CHECK((outcome='succeeded' AND resulting_artifact_digest IS NOT NULL) OR (outcome='outcome_unknown' AND resulting_artifact_digest IS NULL)))""")
        connection.execute("CREATE INDEX IF NOT EXISTS execution_audit_task_idx ON execution_audit(task_id, revision)")
        connection.execute("CREATE TRIGGER IF NOT EXISTS execution_audit_no_update BEFORE UPDATE ON execution_audit BEGIN SELECT RAISE(ABORT,'append-only'); END")
        connection.execute("CREATE TRIGGER IF NOT EXISTS execution_audit_no_delete BEFORE DELETE ON execution_audit BEGIN SELECT RAISE(ABORT,'append-only'); END")

    @staticmethod
    def _validate_audit_schema(connection):
        table = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='execution_audit'").fetchone()
        expected_columns = [
            ("audit_id", "TEXT", 1, 1, 0), ("task_id", "TEXT", 1, 0, 0),
            ("revision", "INTEGER", 1, 0, 0), ("plan_digest", "TEXT", 1, 0, 0),
            ("proposal_digest", "TEXT", 1, 0, 0), ("authorization_id", "TEXT", 1, 0, 0),
            ("permit_hash", "TEXT", 1, 0, 0), ("operation_kind", "TEXT", 1, 0, 0),
            ("target", "TEXT", 1, 0, 0), ("argument_digest", "TEXT", 1, 0, 0),
            ("workspace_identity", "TEXT", 1, 0, 0), ("started_at", "TEXT", 1, 0, 0),
            ("completed_at", "TEXT", 1, 0, 0), ("outcome", "TEXT", 1, 0, 0),
            ("resulting_artifact_digest", "TEXT", 0, 0, 0), ("path_detached", "INTEGER", 1, 0, 0),
            ("error_class", "TEXT", 0, 0, 0),
        ]
        if table is None or not table[0]:
            raise StateStoreError("execution audit schema is missing")
        schema_sql = StateStore._normalize_schema_sql(table[0])
        compact_sql = schema_sql.replace(" ", "")
        expected_checks = (
            "check(operation_kind='write')",
            "check(outcomein('succeeded','outcome_unknown'))",
            "check(path_detachedin(0,1))",
            "check((outcome='succeeded'andresulting_artifact_digestisnotnull)or(outcome='outcome_unknown'andresulting_artifact_digestisnull))",
        )
        if compact_sql.count("check(") != len(expected_checks) or any(check not in compact_sql for check in expected_checks):
            raise StateStoreError("execution audit CHECK constraints are malformed or incompatible")
        info = connection.execute("PRAGMA table_xinfo(execution_audit)").fetchall()
        actual = [(row[1], row[2].upper(), row[3], row[5], row[6]) for row in info]
        if any(len(row) != 7 for row in info) or actual != expected_columns:
            raise StateStoreError("execution audit schema is malformed or incompatible")
        indexes = connection.execute("PRAGMA index_list(execution_audit)").fetchall()
        unique_columns = set()
        for index in indexes:
            if len(index) != 5:
                raise StateStoreError("execution audit indexes are malformed")
            if index[2]:
                cols = [row[0] for row in connection.execute("SELECT name FROM pragma_index_info(?)", (index[1],))]
                if len(cols) == 1:
                    unique_columns.add(cols[0])
        if not {"audit_id", "permit_hash"}.issubset(unique_columns):
            raise StateStoreError("execution audit uniqueness constraints are missing")
        foreign_keys = connection.execute("PRAGMA foreign_key_list(execution_audit)").fetchall()
        if len(foreign_keys) != 1 or (foreign_keys[0][2], foreign_keys[0][3], foreign_keys[0][4]) != ("task_state", "task_id", "task_id"):
            raise StateStoreError("execution audit task binding is malformed")
        expected_indexes = {"sqlite_autoindex_execution_audit_1", "sqlite_autoindex_execution_audit_2", "execution_audit_task_idx"}
        if {row[1] for row in indexes} != expected_indexes:
            raise StateStoreError("execution audit indexes are malformed")
        task_index = next((row for row in indexes if row[1] == "execution_audit_task_idx"), None)
        if (task_index is None or task_index[2] != 0 or task_index[3] != "c"
                or task_index[4] != 0
                or [row[2] for row in connection.execute("PRAGMA index_xinfo('execution_audit_task_idx')") if row[5]] != ["task_id", "revision"]):
            raise StateStoreError("execution audit task index is malformed")
        foreign_keys = connection.execute("PRAGMA foreign_key_list(execution_audit)").fetchall()
        if len(foreign_keys) != 1 or (foreign_keys[0][2], foreign_keys[0][3], foreign_keys[0][4], foreign_keys[0][5], foreign_keys[0][6]) != ("task_state", "task_id", "task_id", "NO ACTION", "NO ACTION"):
            raise StateStoreError("execution audit task binding is malformed")
        triggers = {row[0]: StateStore._normalize_schema_sql(row[1] or "") for row in connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='execution_audit'")}
        expected_triggers = {
            "execution_audit_no_update": "create trigger execution_audit_no_update before update on execution_audit begin select raise(abort,'append-only'); end",
            "execution_audit_no_delete": "create trigger execution_audit_no_delete before delete on execution_audit begin select raise(abort,'append-only'); end",
        }
        if triggers != expected_triggers:
            raise StateStoreError("execution audit immutability triggers are malformed")

    @staticmethod
    def _normalize_schema_sql(sql):
        """Normalize insignificant whitespace/case, preserving SQL tokens and literals."""
        import re
        return re.sub(r"\s+", " ", sql.strip()).lower()

    @classmethod
    def _migrate_v1(cls, connection):
        for task_id, payload in connection.execute("SELECT task_id,payload FROM task_state").fetchall():
            record = cls._tagged_v1_record(payload)
            if str(record.task_id) != task_id:
                raise StateStoreError("task ID does not match stored key")
            if record.approval is not None or record.approval_request is not None:
                if record.plan is None:
                    raise StateStoreError("legacy approval has no plan")
                if record.plan.workspace_identity is None:
                    # Identity-less active plans are retained for review, but every
                    # approval-bound result and execution capability is invalidated.
                    record = replace(record, state=models.TaskState.PLAN,
                        revision=models.PlanRevision(int(record.revision) + 1),
                        plan_digest=canonical_plan_digest(record.plan), approval=None,
                        approval_request=None, permit=None, plan_review=None, result_review=None,
                        mutation_authorization=None, mutation_proposal=None, blast_radius=None,
                        verification=(), handoff=None, child_leases=(),
                        history=record.history + ((models.TaskState.PLAN,) if record.state is not models.TaskState.PLAN else ()))
            connection.execute("UPDATE task_state SET payload=? WHERE task_id=?", (_record_json(record), task_id))
        cls._create_audit_schema(connection)
        connection.execute("UPDATE metadata SET value='2' WHERE key='schema_version'")

    @classmethod
    def _migrate_v2(cls, connection):
        """Install the structured-command Plan shape and revoke legacy verification claims."""
        for task_id, payload in connection.execute("SELECT task_id,payload FROM task_state").fetchall():
            record, legacy_claim = _legacy_record_from_json(payload)
            if str(record.task_id) != task_id:
                raise StateStoreError("task ID does not match stored key")
            has_legacy_completion_claim = legacy_claim
            terminal = record.state in {models.TaskState.COMPLETED, models.TaskState.CANCELLED,
                                        models.TaskState.REJECTED, models.TaskState.FAILED}
            digest_changed = record.plan is not None and record.plan_digest != canonical_plan_digest(record.plan)
            must_revoke = has_legacy_completion_claim or record.state is models.TaskState.COMPLETED or (
                digest_changed and not terminal)
            if must_revoke:
                if record.plan is None:
                    record = replace(record, state=models.TaskState.FAILED, verification=(), result_review=None,
                                     handoff=None, history=record.history + ((models.TaskState.FAILED,) if not record.history or record.history[-1] is not models.TaskState.FAILED else ()),
                                     approval=None, approval_request=None, permit=None,
                                     plan_review=None, mutation_proposal=None, mutation_authorization=None,
                                     blast_radius=None)
                else:
                    record = replace(record, state=models.TaskState.PLAN,
                        revision=models.PlanRevision(int(record.revision) + 1),
                        plan_digest=canonical_plan_digest(record.plan), verification=(), result_review=None,
                        handoff=None, approval=None, approval_request=None, permit=None, plan_review=None,
                        mutation_proposal=None, mutation_authorization=None, blast_radius=None, child_leases=(),
                        history=record.history + ((models.TaskState.PLAN,) if record.state is not models.TaskState.PLAN else ()))
            elif digest_changed:
                # Terminal rejected/cancelled/failed records are preserved, but
                # their unused cached plan digest must still match the new schema.
                record = replace(record, plan_digest=canonical_plan_digest(record.plan))
            connection.execute("UPDATE task_state SET payload=? WHERE task_id=?", (_record_json(record), task_id))
        connection.execute("UPDATE metadata SET value='3' WHERE key='schema_version'")

    @classmethod
    def _migrate_v3(cls, connection):
        for task_id, payload in connection.execute("SELECT task_id,payload FROM task_state").fetchall():
            record, legacy_claim = _legacy_record_from_json(payload)
            if str(record.task_id) != task_id:
                raise StateStoreError("task ID does not match stored key")
            claimed = legacy_claim
            if claimed:
                if record.plan is None:
                    record = replace(record, state=models.TaskState.FAILED, verification=(), result_review=None, handoff=None,
                                     history=record.history + ((models.TaskState.FAILED,) if not record.history or record.history[-1] is not models.TaskState.FAILED else ()),
                                     approval=None, approval_request=None, permit=None, plan_review=None, mutation_proposal=None,
                                     mutation_authorization=None, blast_radius=None)
                else:
                    record = replace(record, state=models.TaskState.PLAN, revision=models.PlanRevision(int(record.revision)+1),
                                     plan_digest=canonical_plan_digest(record.plan), verification=(), result_review=None,
                                     handoff=None, approval=None, approval_request=None, permit=None, plan_review=None,
                                     mutation_proposal=None, mutation_authorization=None, blast_radius=None, child_leases=(),
                                     history=record.history + ((models.TaskState.PLAN,) if record.state is not models.TaskState.PLAN else ()))
            connection.execute("UPDATE task_state SET payload=? WHERE task_id=?", (_record_json(record), task_id))
        connection.execute("UPDATE metadata SET value='4' WHERE key='schema_version'")

    @staticmethod
    def _tagged_v1_record(payload):
        """Decode a tagged v1 record mapping, allowing only known v1 fields."""
        try:
            raw = json.loads(payload)
        except (json.JSONDecodeError, TypeError, UnicodeError) as exc:
            raise StateStoreError("corrupt legacy state JSON") from exc
        if not isinstance(raw, dict):
            raise StateStoreError("legacy state must be an object")
        if raw.get("$type") != "TaskStateRecord":
            raise StateStoreError("unsupported legacy record type")
        expected = {field.name for field in fields(TaskStateRecord)}
        actual = set(raw) - {"$type"}
        if actual - expected or expected - actual - {"mutation_proposal", "mutation_authorization", "verification_commands"}:
            raise StateStoreError("unsupported legacy record fields")
        record, legacy_claim = _legacy_record_from_json(payload)
        if legacy_claim or record.state is models.TaskState.COMPLETED:
            if record.plan is None:
                record = replace(record, state=models.TaskState.FAILED,
                    history=record.history + ((models.TaskState.FAILED,) if not record.history or record.history[-1] is not models.TaskState.FAILED else ()),
                    approval=None, approval_request=None, permit=None, plan_review=None,
                    mutation_proposal=None, mutation_authorization=None, blast_radius=None)
            else:
                record = replace(record, state=models.TaskState.PLAN,
                    revision=models.PlanRevision(int(record.revision) + 1), plan_digest=canonical_plan_digest(record.plan),
                    approval=None, approval_request=None, permit=None, plan_review=None,
                    mutation_proposal=None, mutation_authorization=None, blast_radius=None, child_leases=(),
                    history=record.history + ((models.TaskState.PLAN,) if record.state is not models.TaskState.PLAN else ()))
        if record.plan is not None and record.plan.workspace_identity is None:
            active = record.state not in {models.TaskState.COMPLETED, models.TaskState.CANCELLED,
                                          models.TaskState.REJECTED, models.TaskState.FAILED}
            plan = record.plan
            record = replace(record, plan_digest=canonical_plan_digest(plan))
            if active:
                record = replace(record, state=models.TaskState.PLAN, revision=models.PlanRevision(int(record.revision) + 1),
                    history=record.history + (models.TaskState.PLAN,), approval=None, approval_request=None,
                    permit=None, plan_review=None, mutation_proposal=None, mutation_authorization=None,
                    blast_radius=None, child_leases=())
            else:
                record = replace(record, approval=None, approval_request=None, permit=None,
                    mutation_proposal=None, mutation_authorization=None)
        return record

    def create(self, state: TaskStateRecord) -> None:
        if not isinstance(state, TaskStateRecord):
            raise TypeError("state must be TaskStateRecord")
        canonical = new_task(state.task.task_id, state.task.objective, state.task.requester)
        if state != canonical:
            raise StateStoreError("new tasks must start from canonical intake state")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT INTO task_state(task_id,payload) VALUES(?,?)", (str(state.task_id), _record_json(state)))
            connection.commit()
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StateStoreError("task already exists") from exc
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def load(self, task_id: TaskID | str) -> TaskStateRecord:
        connection = self._connect()
        try:
            row = connection.execute("SELECT payload FROM task_state WHERE task_id=?", (str(task_id),)).fetchone()
        finally:
            connection.close()
        if row is None:
            raise StateStoreError("task not found")
        record = _record_from_json(row[0])
        if str(record.task_id) != str(task_id):
            raise StateStoreError("task ID does not match stored key")
        return record

    def with_current_state_transaction(self, task_id: TaskID | str, callback):
        """Run callback with validated current state while holding the write lock."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload FROM task_state WHERE task_id=?", (str(task_id),)).fetchone()
            if row is None:
                raise StateStoreError("task not found")
            current = _record_from_json(row[0])
            if str(current.task_id) != str(task_id):
                raise StateStoreError("task ID does not match stored key")
            result = callback(current)
            if type(result) is models.ExecutionTransactionResult:
                audit = result.audit_record
                auth, proposal, plan = current.mutation_authorization, current.mutation_proposal, current.plan
                if (auth is None or proposal is None or plan is None or current.permit is None
                        or audit.task_id != current.task_id or audit.revision != current.revision
                        or audit.plan_digest != current.plan_digest or audit.plan_digest != canonical_plan_digest(plan)
                        or current.permit.task_id != current.task_id or current.permit.revision != current.revision
                        or current.permit.digest != current.plan_digest
                        or proposal.operation not in current.permit.scope.operations
                        or proposal.task_id != current.task_id or proposal.revision != current.revision
                        or proposal.plan_digest != current.plan_digest
                        or auth.task_id != current.task_id or auth.revision != current.revision
                        or auth.plan_digest != current.plan_digest
                        or audit.proposal_digest != auth.proposal_digest
                        or audit.proposal_digest != canonical_mutation_proposal_digest(proposal)
                        or audit.authorization_id != auth.authorization_id
                        or audit.workspace_identity != plan.workspace_identity
                        or audit.operation_kind is not proposal.operation.kind
                        or proposal.operation not in plan.operations
                        or audit.target != proposal.operation.target
                        or audit.argument_digest != proposal.argument_digest
                        or audit.path_detached != result.path_detached):
                    raise StateStoreError("execution audit binding does not match current authorized state")
                connection.execute("INSERT INTO execution_audit VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                    audit.audit_id, str(audit.task_id), audit.revision, audit.plan_digest, audit.proposal_digest,
                    audit.authorization_id, audit.permit_hash, audit.operation_kind.value, audit.target,
                    audit.argument_digest, json.dumps(_encode(audit.workspace_identity), sort_keys=True), audit.started_at,
                    audit.completed_at, audit.outcome.value, audit.resulting_artifact_digest,
                    int(result.path_detached), audit.error_class))
            connection.commit()
            return result
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def list_execution_audits(self, task_id: TaskID | str):
        connection = self._connect()
        try:
            rows = connection.execute("SELECT audit_id,task_id,revision,plan_digest,proposal_digest,authorization_id,permit_hash,operation_kind,target,argument_digest,workspace_identity,started_at,completed_at,outcome,resulting_artifact_digest,path_detached,error_class FROM execution_audit WHERE task_id=? ORDER BY rowid", (str(task_id),)).fetchall()
        finally:
            connection.close()
        result = []
        for row in rows:
            values = list(row)
            values[10] = _decode(json.loads(values[10]))
            values[7] = models.OperationKind(values[7])
            values[13] = models.ExecutionOutcome(values[13])
            values[15] = bool(values[15])
            result.append(models.ExecutionAuditRecord(*values))
        return tuple(result)

    def record_approval(self, task_id: TaskID | str, receipt: ApprovalReceipt) -> TaskStateRecord:
        """Validate and persist an approval receipt under the SQLite write lock."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload FROM task_state WHERE task_id=?", (str(task_id),)).fetchone()
            if row is None:
                raise StateStoreError("task not found")
            current = _record_from_json(row[0])
            if str(current.task_id) != str(task_id):
                raise StateStoreError("task ID does not match stored key")
            updated = record_approval(current, receipt)
            connection.execute("UPDATE task_state SET payload=? WHERE task_id=?", (_record_json(updated), str(task_id)))
            connection.commit()
            return updated
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _record_gate_verification(self, task_id: TaskID | str, *, expected_revision, expected_plan_digest, observations):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload FROM task_state WHERE task_id=?", (str(task_id),)).fetchone()
            if row is None:
                raise StateStoreError("task not found")
            current = _record_from_json(row[0])
            if (str(current.task_id) != str(task_id) or current.state is not models.TaskState.IMPLEMENTING
                    or current.revision != expected_revision or current.plan_digest != expected_plan_digest
                    or current.plan is None or current.plan_digest != canonical_plan_digest(current.plan)
                    or current.plan.workspace_identity is None
                    or capture_workspace_identity(current.plan.workspace_root) != current.plan.workspace_identity):
                raise StateStoreError("verification context is stale or workspace identity changed")
            updated = _record_gate_observed_verification(current, observations)
            if capture_workspace_identity(current.plan.workspace_root) != current.plan.workspace_identity:
                raise StateStoreError("workspace identity changed during verification persistence")
            connection.execute("UPDATE task_state SET payload=? WHERE task_id=?", (_record_json(updated), str(task_id)))
            connection.commit()
            return updated
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def record_mutation_proposal(self, task_id: TaskID | str, proposal: MutationProposal) -> TaskStateRecord:
        return self._record_mutation(task_id, lambda current: record_mutation_proposal(current, proposal))

    def record_mutation_authorization(self, task_id: TaskID | str, authorization: MutationAuthorization, *, now=None) -> TaskStateRecord:
        return self._record_mutation(task_id, lambda current: record_mutation_authorization(current, authorization, now=now))

    def _record_mutation(self, task_id, apply):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload FROM task_state WHERE task_id=?", (str(task_id),)).fetchone()
            if row is None:
                raise StateStoreError("task not found")
            current = _record_from_json(row[0])
            if str(current.task_id) != str(task_id):
                raise StateStoreError("task ID does not match stored key")
            updated = apply(current)
            connection.execute("UPDATE task_state SET payload=? WHERE task_id=?", (_record_json(updated), str(task_id)))
            connection.commit()
            return updated
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def transition(self, task_id: TaskID | str, event: Event, artifact=None) -> TaskStateRecord:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload FROM task_state WHERE task_id=?", (str(task_id),)).fetchone()
            if row is None:
                raise StateStoreError("task not found")
            current = _record_from_json(row[0])
            if str(current.task_id) != str(task_id):
                raise StateStoreError("task ID does not match stored key")
            updated = transition(current, event, artifact)
            connection.execute("UPDATE task_state SET payload=? WHERE task_id=?", (_record_json(updated), str(task_id)))
            connection.commit()
            return updated
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
