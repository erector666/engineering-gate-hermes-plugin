"""Strict one-shot Unix-socket client for the Gate Reviewer Service v1."""
from __future__ import annotations

import base64
import binascii
import json
import socket
import struct
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path

MAX_FRAME = 65_536
IMPLEMENTER_ID = "engineering-gate-hermes"
REVIEWER_ID = "engineering-gate-reviewer-v1"
REVIEWER_PROVIDER = "openai:gpt-6.1-sol"


def _json_value(value):
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        if any(type(key) is not str for key in value):
            raise TypeError("non-JSON proposal key")
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise TypeError("non-JSON proposal value")


def _recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ValueError("truncated reviewer-service frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class ReviewerServiceClient:
    """Fail-closed synchronous client; exactly one request and no retries."""
    def __init__(self, socket_path, *, key_id, reviewer_id=REVIEWER_ID,
                 reviewer_provider=REVIEWER_PROVIDER, timeout=75.0):
        if (type(socket_path) is not str or not socket_path or type(key_id) is not str or not key_id
                or reviewer_id != REVIEWER_ID or reviewer_provider != REVIEWER_PROVIDER
                or type(timeout) not in (int, float) or timeout < 75):
            raise ValueError("invalid reviewer service configuration")
        self.socket_path, self.key_id = socket_path, key_id
        self.reviewer_id, self.reviewer_provider = reviewer_id, reviewer_provider
        self.timeout = float(timeout)

    def __call__(self, task_id, proposal, *, state, approval_packet, approval_packet_digest, content):
        from ._core_import import import_core
        workflow = import_core("workflow")
        proposal_value = _json_value(proposal)
        proposal_digest = workflow.canonical_mutation_proposal_digest(proposal)
        request = {
            "schema_version": 1, "review_request_id": __import__("uuid").uuid4().hex,
            "task_id": str(task_id), "plan_revision": int(state.revision),
            "plan_digest": str(state.plan_digest), "approval_packet": json.loads(approval_packet),
            "approval_packet_digest": approval_packet_digest,
            "proposal": proposal_value, "proposal_digest": proposal_digest,
            "mutation_arguments": {"content": content}, "implementer_id": IMPLEMENTER_ID,
        }
        encoded = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                             allow_nan=False).encode("utf-8")
        if len(encoded) > MAX_FRAME:
            raise ValueError("review request exceeds frame limit")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(self.timeout)
            client.connect(self.socket_path)
            client.sendall(struct.pack("!I", len(encoded)) + encoded)
            length = struct.unpack("!I", _recv_exact(client, 4))[0]
            if length == 0 or length > MAX_FRAME:
                raise ValueError("invalid reviewer-service response frame length")
            response_bytes = _recv_exact(client, length)
            if client.recv(1):
                raise ValueError("trailing reviewer-service response data")
        response = json.loads(response_bytes.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
        if type(response) is not dict or set(response) != {"canonical_payload_b64", "signature_b64"}:
            raise ValueError("invalid reviewer-service response schema")
        payload = _decode_b64(response["canonical_payload_b64"])
        signature = _decode_b64(response["signature_b64"])
        signed = import_core("signed_authorization")
        verdict = signed.SignedMutationVerdict(payload, signature)
        current_key = self._store.get_reviewer_key(self.key_id)
        # The host can expose the store through a different import namespace in tests;
        # normalize the persisted value object into this adapter's pinned Gate namespace.
        current_key = signed.ReviewerPublicKey(current_key.key_id, current_key.reviewer_id,
                                               current_key.reviewer_provider, current_key.public_key,
                                               current_key.enabled, current_key.revoked)
        if current_key.key_id != self.key_id or current_key.reviewer_id != self.reviewer_id or current_key.reviewer_provider != self.reviewer_provider:
            raise ValueError("reviewer identity does not match configured identity")
        policy = self._store.timing_policy
        policy = signed.AuthorizationTimingPolicy(policy.max_review_age_seconds,
                                                  policy.max_active_lease_seconds)
        verified = signed.verify_signed_verdict(verdict, current_key, now=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(microsecond=0), implementer_id=IMPLEMENTER_ID, timing_policy=policy)
        if (verified.task_id != str(task_id) or verified.plan_revision != int(state.revision)
                or verified.plan_digest != str(state.plan_digest) or verified.proposal_digest != proposal_digest
                or verified.implementer_id != IMPLEMENTER_ID or verified.key_id != self.key_id
                or verified.reviewer_id != self.reviewer_id or verified.reviewer_provider != self.reviewer_provider):
            raise ValueError("signed reviewer verdict binding mismatch")
        return verdict

    def bind_store(self, store):
        self._store = store
        return self


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response JSON key")
        result[key] = value
    return result


def _decode_b64(value):
    if type(value) is not str:
        raise ValueError("response binary fields must be base64 strings")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64 in reviewer-service response") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("noncanonical base64 in reviewer-service response")
    return decoded


__all__ = ["ReviewerServiceClient"]
