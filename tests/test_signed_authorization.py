import unittest
from datetime import datetime, timezone

from engineering_gate_core.signed_authorization import (
    ReviewerPublicKey, SignedMutationVerdict, canonical_signed_verdict,
    verify_signed_verdict,
)


class SignedAuthorizationTests(unittest.TestCase):
    # RFC 8032 Ed25519 test vector 1 (fixed public key and signature).
    PUBLIC_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    SIGNATURE = bytes.fromhex("033747f92db4ca5a2a1ebd731fc11aae3a87fb9d4119a5dbfb53ed3f258a9a89d6c33ed46491f4f4add4ac57498b2c3342de83fe0df4bf5b0c74df9555277c08")

    def payload(self):
        return {"schema_version": 1, "signature_algorithm": "Ed25519", "key_id": "key-1",
                "review_id": "review-1", "reviewer_id": "reviewer", "reviewer_provider": "test",
                "implementer_id": "agent", "task_id": "task-1", "plan_revision": 2,
                "plan_digest": "a" * 64, "proposal_digest": "b" * 64, "verdict": "approve",
                "reviewed_at": "2026-10-02T10:00:00Z"}

    def test_canonical_serialization_has_stable_utf8_bytes(self):
        expected = (b'{"implementer_id":"agent","key_id":"key-1","plan_digest":"' + b'a' * 64 +
                    b'","plan_revision":2,"proposal_digest":"' + b'b' * 64 +
                    b'","review_id":"review-1","reviewed_at":"2026-10-02T10:00:00Z",'
                    b'"reviewer_id":"reviewer","reviewer_provider":"test","schema_version":1,'
                    b'"signature_algorithm":"Ed25519","task_id":"task-1","verdict":"approve"}')
        self.assertEqual(canonical_signed_verdict(self.payload()), expected)

    def test_fixed_signature_vector_verifies(self):
        payload = self.payload()
        canonical = canonical_signed_verdict(payload)
        verdict = SignedMutationVerdict(canonical, self.SIGNATURE)
        key = ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY)
        result = verify_signed_verdict(verdict, key, now=datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc), implementer_id="agent")
        self.assertEqual(result.review_id, "review-1")
        self.assertEqual(result.payload_digest, __import__("hashlib").sha256(canonical).hexdigest())

    def test_rejects_noncanonical_payload(self):
        canonical = canonical_signed_verdict(self.payload())
        with self.assertRaises(ValueError):
            verify_signed_verdict(SignedMutationVerdict(canonical + b" ", b"x"),
                                  ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY),
                                  now=datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc), implementer_id="agent")

    def test_rejects_field_mutations_with_original_signature(self):
        key = ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY)
        for changes in ({"review_id": "other"}, {"task_id": "other"}, {"plan_revision": 3},
                        {"plan_digest": "c" * 64}, {"proposal_digest": "d" * 64},
                        {"reviewer_id": "other"}, {"reviewer_provider": "other"},
                        {"implementer_id": "other"}, {"key_id": "other"},
                        {"reviewed_at": "2026-10-02T10:00:01Z"}):
            raw = canonical_signed_verdict(self.payload() | changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify_signed_verdict(SignedMutationVerdict(raw, self.SIGNATURE), key,
                                      now=datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc), implementer_id="agent")

    def test_rejects_schema_extensions_malformed_types_and_timestamp_bounds(self):
        key = ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY)
        for payload in (self.payload() | {"authorization_id": "caller"},
                        self.payload() | {"schema_version": True},
                        self.payload() | {"signature_algorithm": "RSA"},
                        self.payload() | {"plan_revision": True},
                        self.payload() | {"reviewed_at": "2026-10-02T10:00:00+00:00"}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                verify_signed_verdict(SignedMutationVerdict(canonical_signed_verdict(payload), self.SIGNATURE), key,
                                      now=datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc), implementer_id="agent")
        for stamp in ("2026-10-02T10:00:01Z", "2026-10-02T09:54:59Z"):
            payload = self.payload() | {"reviewed_at": stamp}
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                verify_signed_verdict(SignedMutationVerdict(canonical_signed_verdict(payload), self.SIGNATURE), key,
                                      now=datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc), implementer_id="agent")

    def test_rejects_naive_clock_bad_signature_and_key_trust_mismatch(self):
        raw = canonical_signed_verdict(self.payload())
        key = ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY)
        with self.assertRaises(ValueError):
            verify_signed_verdict(SignedMutationVerdict(raw, self.SIGNATURE), key,
                                  now=datetime(2026, 10, 2, 10), implementer_id="agent")
        for sig, trusted in ((b"x" * 64, key), (self.SIGNATURE, ReviewerPublicKey("key-1", "wrong", "test", self.PUBLIC_KEY)),
                             (self.SIGNATURE, ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY, enabled=False)),
                             (self.SIGNATURE, ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY, revoked=True))):
            with self.subTest(trusted=trusted), self.assertRaises(ValueError):
                verify_signed_verdict(SignedMutationVerdict(raw, sig), trusted,
                                      now=datetime(2026, 10, 2, 10, tzinfo=timezone.utc), implementer_id="agent")
        payload = self.payload() | {"reviewer_id": "agent"}
        with self.assertRaises(ValueError):
            verify_signed_verdict(SignedMutationVerdict(canonical_signed_verdict(payload), self.SIGNATURE),
                                  ReviewerPublicKey("key-1", "agent", "test", self.PUBLIC_KEY),
                                  now=datetime(2026, 10, 2, 10, tzinfo=timezone.utc), implementer_id="agent")

    def test_rejects_invalid_utf8(self):
        from engineering_gate_core.signed_authorization import SignatureVerificationError
        with self.assertRaises(SignatureVerificationError):
            verify_signed_verdict(SignedMutationVerdict(bytes((0xff,)), b"x"),
                                  ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY),
                                  now=datetime(2026, 10, 2, 10, tzinfo=timezone.utc), implementer_id="agent")

    def test_rejects_missing_field(self):
        from engineering_gate_core.signed_authorization import SignatureVerificationError
        payload = self.payload()
        del payload["review_id"]
        with self.assertRaises(SignatureVerificationError):
            verify_signed_verdict(SignedMutationVerdict(canonical_signed_verdict(payload), self.SIGNATURE),
                                  ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY),
                                  now=datetime(2026, 10, 2, 10, tzinfo=timezone.utc), implementer_id="agent")

    def test_rejects_duplicate_json_key(self):
        from engineering_gate_core.signed_authorization import SignatureVerificationError
        raw = canonical_signed_verdict(self.payload())[:-1] + b',"review_id":"duplicate"}'
        with self.assertRaises(SignatureVerificationError):
            verify_signed_verdict(SignedMutationVerdict(raw, self.SIGNATURE),
                                  ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY),
                                  now=datetime(2026, 10, 2, 10, tzinfo=timezone.utc), implementer_id="agent")

    def test_missing_crypto_backend_error_names_install_requirements(self):
        from unittest.mock import patch
        from engineering_gate_core import signed_authorization
        with patch.object(signed_authorization, "Ed25519PublicKey", None):
            with self.assertRaisesRegex(ValueError, r"cryptography>=46,<51.*engineering-gate/requirements\.txt"):
                signed_authorization.verify_signed_verdict(
                    SignedMutationVerdict(b"{}", b"x"),
                    ReviewerPublicKey("key-1", "reviewer", "test", self.PUBLIC_KEY),
                    now=datetime(2026, 10, 2, 10, tzinfo=timezone.utc), implementer_id="agent")
