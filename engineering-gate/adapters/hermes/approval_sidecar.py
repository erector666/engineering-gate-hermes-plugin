"""SQLite-backed, one-shot Gate Telegram approval records."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time


class ApprovalSidecar:
    _REQUIRED = (
        "profile_id", "session_id", "telegram_user_id", "telegram_chat_id",
        "task_id", "plan_revision", "plan_digest", "workspace_identity",
        "approval_request_id", "plan_display_digest", "created_at", "expires_at",
    )
    _RECORD_FIELDS = frozenset(_REQUIRED) | {
        "nonce", "prompt_message_id", "delivered", "state",
    }
    _STATES = {"pending", "approved", "denied", "cancelled"}

    def __init__(self, profile_home):
        self.profile_home = Path(profile_home)

    def _db(self, profile):
        if not isinstance(profile, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", profile) or profile in {".", ".."}:
            raise ValueError("invalid profile")
        root = self.profile_home
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        path = root / "engineering-gate-approvals.sqlite3"
        conn = sqlite3.connect(path, timeout=10, isolation_level=None)
        os.chmod(path, 0o600)
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("CREATE TABLE IF NOT EXISTS approvals (nonce TEXT PRIMARY KEY, data TEXT NOT NULL, state TEXT NOT NULL)")
        return conn

    @staticmethod
    def _validate(data):
        if type(data) is not dict or set(data) != set(ApprovalSidecar._REQUIRED):
            raise ValueError("approval binding fields do not match schema")
        for key in ("profile_id", "session_id", "task_id", "approval_request_id"):
            value = data[key]
            if type(value) is not str or not value or len(value) > 1024 or "\x00" in value:
                raise ValueError("invalid " + key)
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", data["profile_id"]) or data["profile_id"] in {".", ".."}:
            raise ValueError("invalid profile_id")
        workspace = data["workspace_identity"]
        if (type(workspace) is not dict or set(workspace) != {"canonical_path", "device", "inode"}
                or type(workspace["canonical_path"]) is not str
                or not workspace["canonical_path"] or len(workspace["canonical_path"]) > 4096
                or "\x00" in workspace["canonical_path"]):
            raise ValueError("invalid workspace_identity")
        for key in ("device", "inode"):
            if type(workspace[key]) is not int or workspace[key] < 0:
                raise ValueError("invalid workspace_identity " + key)
        for key in ("telegram_user_id", "telegram_chat_id", "plan_revision"):
            if type(data[key]) is not int or data[key] < (0 if key == "plan_revision" else 1):
                raise ValueError("invalid " + key)
        for key in ("plan_digest", "plan_display_digest"):
            if type(data[key]) is not str or not re.fullmatch(r"[0-9a-f]{64}", data[key]):
                raise ValueError("invalid " + key)
        for key in ("created_at", "expires_at"):
            if type(data[key]) not in (int, float) or data[key] < 0:
                raise ValueError("invalid " + key)
        if data["expires_at"] <= data["created_at"]:
            raise ValueError("invalid expiry")

    @classmethod
    def _validate_record(cls, record, nonce, row_state, profile_id):
        if type(record) is not dict or set(record) != cls._RECORD_FIELDS:
            raise ValueError("invalid approval record schema")
        binding = {key: record[key] for key in cls._REQUIRED}
        cls._validate(binding)
        if (record["profile_id"] != profile_id or record["nonce"] != nonce
                or type(nonce) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce)
                or record["state"] not in cls._STATES or row_state != record["state"]
                or type(record["delivered"]) is not bool):
            raise ValueError("invalid approval record binding/state")
        prompt_id = record["prompt_message_id"]
        if record["delivered"]:
            if type(prompt_id) is not int or prompt_id <= 0:
                raise ValueError("invalid delivered prompt")
        elif prompt_id is not None:
            raise ValueError("undelivered record has prompt id")
        return record

    def create_pending(self, **data):
        self._validate(data)
        nonce = secrets.token_urlsafe(32)
        record = dict(data, nonce=nonce, prompt_message_id=None, delivered=False, state="pending")
        conn = self._db(data["profile_id"])
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT data FROM approvals WHERE state='pending'").fetchall()
            scope_keys = ("profile_id", "session_id", "telegram_user_id", "telegram_chat_id", "task_id", "plan_revision", "approval_request_id")
            for (raw,) in existing:
                try:
                    other = json.loads(raw)
                except (ValueError, TypeError):
                    raise ValueError("corrupt active approval record")
                if type(other) is not dict:
                    raise ValueError("corrupt active approval record")
                if all(other.get(key) == data[key] for key in scope_keys):
                    raise ValueError("duplicate active approval scope")
            conn.execute("INSERT INTO approvals VALUES (?, ?, 'pending')", (nonce, json.dumps(record, sort_keys=True, separators=(",", ":"))))
            conn.commit()
            return nonce
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get(self, nonce, *, profile_id):
        conn = None
        try:
            if type(nonce) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce):
                return None
            conn = self._db(profile_id)
            row = conn.execute("SELECT data,state FROM approvals WHERE nonce=?", (nonce,)).fetchone()
            if not row:
                return None
            return self._validate_record(json.loads(row[0]), nonce, row[1], profile_id)
        except Exception:
            return None
        finally:
            if conn is not None:
                conn.close()

    def find_unique_approved(self, profile_id, task_id, approval_request_id):
        """Return the sole valid delivered approval matching this exact binding.

        Returns None when there is no match, more than one match, or any
        approved row in this profile database is corrupt/invalid. The profile
        database itself is selected through _db(profile_id).
        """
        conn = None
        try:
            if (type(task_id) is not str or not task_id or len(task_id) > 1024
                    or "\x00" in task_id or type(approval_request_id) is not str
                    or not approval_request_id or len(approval_request_id) > 1024
                    or "\x00" in approval_request_id):
                return None
            conn = self._db(profile_id)
            rows = conn.execute(
                "SELECT nonce,data,state FROM approvals WHERE state='approved'"
            ).fetchall()
            matches = []
            for nonce, raw, row_state in rows:
                record = self._validate_record(json.loads(raw), nonce, row_state, profile_id)
                if (record["state"] == "approved" and record["delivered"]
                        and record["task_id"] == task_id
                        and record["approval_request_id"] == approval_request_id):
                    matches.append(record)
            return matches[0] if len(matches) == 1 else None
        except Exception:
            return None
        finally:
            if conn is not None:
                conn.close()

    def find_unique_approved_for_context(self, profile_id, session_id, telegram_user_id, telegram_chat_id):
        """Resolve one unexpired, delivered approval from trusted Telegram identity only."""
        conn = None
        try:
            if (type(session_id) is not str or not session_id or type(telegram_user_id) is not int
                    or telegram_user_id <= 0 or type(telegram_chat_id) is not int or telegram_chat_id <= 0):
                return None
            conn = self._db(profile_id)
            rows = conn.execute("SELECT nonce,data,state FROM approvals WHERE state='approved'").fetchall()
            matches = []
            now = time.time()
            for nonce, raw, row_state in rows:
                record = self._validate_record(json.loads(raw), nonce, row_state, profile_id)
                if (record["state"] == "approved" and record["delivered"] and record["expires_at"] > now
                        and record["session_id"] == session_id
                        and record["telegram_user_id"] == telegram_user_id
                        and record["telegram_chat_id"] == telegram_chat_id):
                    matches.append(record)
            return matches[0] if len(matches) == 1 else None
        except Exception:
            return None
        finally:
            if conn is not None:
                conn.close()

    def mark_prompt_delivered(self, nonce, *, profile_id, prompt_message_id, plan_chunks_confirmed, buttons_sent):
        if (type(prompt_message_id) is not int or prompt_message_id <= 0
                or type(plan_chunks_confirmed) is not bool or type(buttons_sent) is not bool
                or not plan_chunks_confirmed or not buttons_sent):
            return False
        conn = None
        try:
            conn = self._db(profile_id)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT data,state FROM approvals WHERE nonce=?", (nonce,)).fetchone()
            if not row:
                conn.rollback()
                return False
            data = self._validate_record(json.loads(row[0]), nonce, row[1], profile_id)
            if data["state"] != "pending" or data["delivered"]:
                conn.rollback()
                return False
            data["prompt_message_id"] = prompt_message_id
            data["delivered"] = True
            cursor = conn.execute("UPDATE approvals SET data=? WHERE nonce=? AND state='pending'", (json.dumps(data, sort_keys=True, separators=(",", ":")), nonce))
            conn.commit()
            return cursor.rowcount == 1
        except Exception:
            if conn is not None:
                conn.rollback()
            return False
        finally:
            if conn is not None:
                conn.close()

    def consume_callback(self, nonce, *, actor_id, chat_id, chat_type, choice, expected_context):
        if (type(nonce) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce)
                or type(actor_id) is not int or type(chat_id) is not int
                or chat_type != "private" or choice not in {"approve_once", "deny"}
                or type(expected_context) is not dict or set(expected_context) != set(self._REQUIRED)):
            return False
        conn = None
        try:
            self._validate(expected_context)
            conn = self._db(expected_context["profile_id"])
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT data,state FROM approvals WHERE nonce=?", (nonce,)).fetchone()
            if not row:
                conn.rollback()
                return False
            data = self._validate_record(json.loads(row[0]), nonce, row[1], expected_context["profile_id"])
            if (data["state"] != "pending" or not data["delivered"]
                    or data["expires_at"] <= time.time()
                    or data["telegram_user_id"] != actor_id or data["telegram_chat_id"] != chat_id
                    or any(data[key] != value for key, value in expected_context.items())):
                conn.rollback()
                return False
            state = "approved" if choice == "approve_once" else "denied"
            data["state"] = state
            cursor = conn.execute("UPDATE approvals SET data=?,state=? WHERE nonce=? AND state='pending'", (json.dumps(data, sort_keys=True, separators=(",", ":")), state, nonce))
            conn.commit()
            return (True, choice == "approve_once") if cursor.rowcount == 1 else False
        except Exception:
            if conn is not None:
                conn.rollback()
            return False
        finally:
            if conn is not None:
                conn.close()

    def invalidate(self, nonce, profile):
        conn = self._db(profile)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT data,state FROM approvals WHERE nonce=?", (nonce,)).fetchone()
            if row and row[1] == "pending":
                data = self._validate_record(json.loads(row[0]), nonce, row[1], profile)
                data["state"] = "cancelled"
                conn.execute("UPDATE approvals SET data=?,state='cancelled' WHERE nonce=? AND state='pending'", (json.dumps(data, sort_keys=True, separators=(",", ":")), nonce))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
