"""Host-neutral SQLite persistence for lifecycle state (single-host only)."""
from __future__ import annotations

from dataclasses import fields, is_dataclass
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
from .models import ApprovalReceipt, TaskID, TaskStateRecord
from .workflow import Event, TransitionError, new_task, record_approval, transition

_SCHEMA_VERSION = 1
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


def _decode(value):
    if isinstance(value, list):
        raise StateStoreError("unexpected untyped JSON list")
    if not isinstance(value, dict):
        return value
    if "$tuple" in value:
        if set(value) != {"$tuple"} or not isinstance(value["$tuple"], list):
            raise StateStoreError("malformed tuple")
        return tuple(_decode(item) for item in value["$tuple"])
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
        if set(value) != expected | {"$type"}:
            raise StateStoreError("record fields do not match schema")
        try:
            decoded = {key: _decode(value[key]) for key in expected}
            hints = typing.get_type_hints(cls)
            for key, annotation in hints.items():
                if hasattr(annotation, "__supertype__"):
                    decoded[key] = annotation(decoded[key])
                if not _matches_type(decoded[key], annotation):
                    raise StateStoreError("record field has invalid type")
            return cls(**decoded)
        except StateStoreError:
            raise
        except (TypeError, ValueError) as exc:
            raise StateStoreError("invalid record") from exc
    raise StateStoreError("untyped object in state")


def _record_json(record):
    return json.dumps(_encode(record), sort_keys=True, separators=(",", ":"))


def _record_from_json(text):
    try:
        record = _decode(json.loads(text))
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
        try:
            connection.execute("BEGIN IMMEDIATE")
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )}
            if not tables:
                connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                connection.execute("INSERT INTO metadata(key,value) VALUES('schema_version',?)", (str(_SCHEMA_VERSION),))
                connection.execute("CREATE TABLE task_state (task_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
            else:
                if "metadata" not in tables:
                    raise StateStoreError("database schema metadata is missing")
                metadata_columns = {row[1] for row in connection.execute("PRAGMA table_info(metadata)")}
                if not {"key", "value"}.issubset(metadata_columns):
                    raise StateStoreError("database schema metadata is malformed")
                rows = connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchall()
                if len(rows) != 1 or type(rows[0][0]) is not str or rows[0][0] != str(_SCHEMA_VERSION):
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
            connection.commit()
            return connection
        except BaseException:
            connection.rollback()
            connection.close()
            raise

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
            connection.commit()
            return result
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

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
