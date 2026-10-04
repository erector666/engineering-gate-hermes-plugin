# Reviewer Service v1 (operator-run, separate process)

This process validates the complete approval packet and WRITE proposal, obtains one independent review, and signs only its own v1 verdict. Reviewer provider configuration is trusted operator input loaded at startup; review requests cannot choose providers, models, endpoints, credentials, or quotas. Configuration, transport, refusal, malformed output, or binding failures fail closed. There is no retry or fallback.

## Operator profile

Create a UTF-8 JSON file owned by the service account and mode 0600. Example values and paths are deliberately fake:

```json
{
  "provider": "ExampleCompatible",
  "model": "example-model-exact-v3",
  "adapter": "responses",
  "endpoint": "https://review.example.invalid/v1/responses",
  "api_key_file": "/secure/fake/example-api-key",
  "timeout_seconds": 45,
  "max_output_tokens": 1024,
  "input_price_per_million_usd": 0.80,
  "output_price_per_million_usd": 3.20,
  "daily_budget_usd": 2.50,
  "max_calls_per_day": 6,
  "privacy": {"store": false, "tools": false}
}
```

`api_key_file` may be the empty string only for HTTP/HTTPS loopback endpoints; no Authorization header is sent then. Remote endpoints require a key file and HTTPS. The exact Gate identity belongs in the active Hermes profile's `config.yaml`, under plugin settings:

```yaml
plugins:
  entries:
    engineering-gate:
      settings:
        reviewer_provider: "ExampleCompatible:example-model-exact-v3"
```

This is the sole source of Gate's expected provider:model identity. It must exactly match the service's configured provider and model and the registered public key for fixed reviewer ID `engineering-gate-reviewer-v1`. The service sidecar at `<profile_home>/engineering-gate-reviewer-service.json` is transport-only and accepts exactly these three fields:

```json
{
  "socket_path": "/secure/run/reviewer.sock",
  "key_id": "EXAMPLE_KEY",
  "timeout_seconds": 75
}
```

Unknown or duplicate fields—including an injected `reviewer_provider`—fail closed. Missing or malformed active plugin identity also disables the reviewer client. Review requests cannot override the identity, and the fixed reviewer ID is `engineering-gate-reviewer-v1`.

Endpoints reject userinfo, query strings and fragments. Remote endpoints must use HTTPS; HTTP is accepted only for localhost/IP loopback. Redirects and ambient proxies are disabled. Only the configured endpoint is used, never request-controlled data. Operator must assess data-egress/privacy obligations and provider rate limits; daily call/budget limits here are local controls, not provider-side rate limiting.

The key file must be a regular file owned by the service UID, mode 0600 or more restrictive, and contain only the credential (no newline). Credentials are never logged. Logs exclude prompts, review content and provider exception details.

## Key registration and identity

Generate/signing-key handling is described by `reviewer_service.key_cli`. Derive the exact provider identity from the trusted profile (this prints only the identity, not credentials):

```sh
PYTHONPATH=engineering-gate python -c 'import sys; from reviewer_service.provider_config import load_profile; print(load_profile(sys.argv[1]).provider_identity)' /secure/provider-profile.json
```

The derived value must exactly match the active Hermes profile's `plugins.entries.engineering-gate.settings.reviewer_provider` value and the registry entry identity for reviewer ID `engineering-gate-reviewer-v1`. Do not append a hash or normalize either provider or model. Gate matches the identity against the public-key registry entry and signed verdict. Key material stays in restrictive files.

## Service

Example invocation:

```sh
PYTHONPATH=engineering-gate python -m reviewer_service.service \
  --socket /secure/run/reviewer.sock --ledger /secure/state/reviewer-ledger.sqlite \
  --private-key /secure/fake/reviewer-private.key --profile /secure/fake/provider-profile.json \
  --key-id EXAMPLE_KEY --client-uid 1200 --socket-gid 1201 --socket-mode 0660
```

The service authenticates Linux Unix-socket peers with `SO_PEERCRED`; provisioning accounts, groups, service installation, key registration and live activation are operator responsibilities and are not performed by this change. One request ID permits one attempt; ambiguous failures retain their reservation. The ledger reserves from serialized request size using configured upper-bound prices and computes actual usage cost from those same prices. Tests inject fake transports; no live activation is implied.

## Local offline tests

From repository root: `PYTHONPATH=engineering-gate PYTHONDONTWRITEBYTECODE=1 pytest -q tests/reviewer_service`. Tests use fake transports and do not make network calls.
