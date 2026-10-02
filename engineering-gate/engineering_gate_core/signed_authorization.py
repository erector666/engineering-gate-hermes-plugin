"""Strict signed reviewer-verdict parsing and Ed25519 verification."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # Read-only core imports remain usable without optional crypto runtime.
    InvalidSignature = None
    Ed25519PublicKey = None

DOMAIN_PREFIX = b"engineering-gate/reviewer-verdict/v1\x00"
FIELDS = frozenset({"schema_version", "signature_algorithm", "key_id", "review_id", "reviewer_id",
                    "reviewer_provider", "implementer_id", "task_id", "plan_revision", "plan_digest",
                    "proposal_digest", "verdict", "reviewed_at"})
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class SignatureVerificationError(ValueError):
    """Signed evidence cannot be trusted or verified."""


@dataclass(frozen=True)
class SignedMutationVerdict:
    canonical_payload: bytes
    signature: bytes


@dataclass(frozen=True)
class ReviewerPublicKey:
    key_id: str
    reviewer_id: str
    reviewer_provider: str
    public_key: bytes
    enabled: bool = True
    revoked: bool = False


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


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SignatureVerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_json(value):
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SignatureVerificationError("verdict is not canonicalizable JSON") from exc


def canonical_signed_verdict(payload):
    if not isinstance(payload, dict):
        raise SignatureVerificationError("verdict payload must be an object")
    return _canonical_json(payload)


def _fail(message):
    raise SignatureVerificationError(message)


def verify_signed_verdict(verdict, key_record, *, now, implementer_id, max_review_age_seconds=300):
    if Ed25519PublicKey is None:
        _fail("Ed25519 verification unavailable: install cryptography>=46,<51 with `pip install -r engineering-gate/requirements.txt`")
    if type(verdict) is not SignedMutationVerdict or type(key_record) is not ReviewerPublicKey:
        _fail("verdict and trusted ReviewerPublicKey record are required")
    if type(verdict.canonical_payload) is not bytes or type(verdict.signature) is not bytes:
        _fail("payload and signature must be bytes")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
        _fail("now must be a UTC-aware datetime")
    if type(max_review_age_seconds) is not int or max_review_age_seconds < 0:
        _fail("max_review_age_seconds must be a nonnegative integer")
    try:
        text = verdict.canonical_payload.decode("utf-8", errors="strict")
        payload = json.loads(text, object_pairs_hook=_pairs_no_duplicates,
                             parse_constant=lambda v: _fail(f"invalid JSON number: {v}"))
    except SignatureVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SignatureVerificationError("invalid UTF-8 JSON verdict") from exc
    if type(payload) is not dict or set(payload) != FIELDS:
        _fail("verdict has unknown or missing fields")
    if _canonical_json(payload) != verdict.canonical_payload:
        _fail("verdict payload is not canonical JSON")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        _fail("unsupported schema_version")
    if payload["signature_algorithm"] != "Ed25519":
        _fail("unsupported signature_algorithm")
    for name in ("key_id", "review_id", "reviewer_id", "reviewer_provider", "implementer_id", "task_id"):
        val = payload[name]
        if type(val) is not str or not val or len(val) > 256 or not val.strip():
            _fail(f"{name} must be a nonempty bounded string")
    for name in ("plan_digest", "proposal_digest"):
        if type(payload[name]) is not str or not _DIGEST.fullmatch(payload[name]):
            _fail(f"{name} must be a lowercase SHA-256 digest")
    if type(payload["plan_revision"]) is not int or payload["plan_revision"] < 0:
        _fail("plan_revision must be a nonnegative integer")
    if payload["verdict"] not in ("approve", "reject") or type(payload["verdict"]) is not str:
        _fail("verdict must be approve or reject")
    if type(implementer_id) is not str or not implementer_id or payload["implementer_id"] != implementer_id:
        _fail("signed implementer identity does not match configured implementer")
    if payload["reviewer_id"] == implementer_id:
        _fail("reviewer must differ from implementer")
    if key_record.enabled is not True or key_record.revoked is not False:
        _fail("reviewer key is disabled or revoked")
    if (payload["key_id"] != key_record.key_id or payload["reviewer_id"] != key_record.reviewer_id
            or payload["reviewer_provider"] != key_record.reviewer_provider):
        _fail("signed reviewer identity/provider does not match trusted key record")
    stamp = payload["reviewed_at"]
    if type(stamp) is not str or not _TIMESTAMP.fullmatch(stamp):
        _fail("reviewed_at must be canonical UTC whole-second RFC3339")
    try:
        reviewed_at = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SignatureVerificationError("invalid reviewed_at timestamp") from exc
    now = now.astimezone(timezone.utc)
    if reviewed_at > now:
        _fail("reviewed_at is in the future")
    if now - reviewed_at > timedelta(seconds=max_review_age_seconds):
        _fail("reviewed_at exceeds maximum reviewer age")
    if type(key_record.public_key) is not bytes or len(key_record.public_key) != 32:
        _fail("trusted Ed25519 public key must be 32 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(key_record.public_key).verify(verdict.signature, DOMAIN_PREFIX + verdict.canonical_payload)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise SignatureVerificationError("Ed25519 signature verification failed") from exc
    return VerifiedReviewerVerdict(payload["review_id"], payload["task_id"], payload["plan_revision"],
                                    payload["plan_digest"], payload["proposal_digest"], payload["reviewer_id"],
                                    payload["reviewer_provider"], payload["implementer_id"], payload["verdict"],
                                    reviewed_at, payload["key_id"], hashlib.sha256(verdict.canonical_payload).hexdigest())
