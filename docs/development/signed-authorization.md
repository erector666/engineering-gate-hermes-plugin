# Signed reviewer-verdict contract (development)

The v6 signed-verdict verifier requires Python package `cryptography>=46,<51` for Ed25519. Provision it in the runtime with `python3 -m pip install -r engineering-gate/requirements.txt` (prefer an isolated virtual environment). The core remains importable for read-only operations if the backend is absent, but any attempted signature verification fails closed with an actionable `SignatureVerificationError`; there is no handwritten or fallback cryptography.

Verdicts are canonical UTF-8 JSON with an exact schema and detached Ed25519 signature over the domain-prefixed canonical bytes. The Gate resolves reviewer keys from trusted configuration, validates identity/provider, key status, bindings, and strict UTC freshness. Keep private signing keys outside this repository and outside Gate state.

`setup.sh` remains the old v4 copy-only installer. It does not provision this dependency and is **not a v6 installer**. This core slice is not yet a Hermes integration; callers must provision the declared dependency separately and must not treat missing verification capability as authorization.
