# Microsoft Identity Zero Trust — Local Identity Policy Study

Independent GlacierEQ portfolio work modeling two identity-security boundaries:

1. a deterministic zero-trust access policy over caller-supplied risk, device-health, MFA, location-anomaly, and privilege signals; and
2. a hash-bound workload-identity envelope with exact audience, scope, lifetime, and source binding.

**Evidence state:** `LOCAL_IDENTITY_POLICY_AND_WORKLOAD_MODEL_NOT_MICROSOFT_ENTRA_AUTHORITY`

This repository is not affiliated with, endorsed by, or operated by Microsoft. It does not contact Microsoft Entra, mint real credentials, inspect real devices, or grant production access.

## Current mechanisms

### Zero-trust policy

`src/zero_trust.py` validates every numeric signal as finite and bounded in `0..1`, rejects malformed boolean state, and produces `DENY`, `STEP_UP`, or `ALLOW` from an explicit weighted policy.

A privileged role without MFA is denied directly.

The earlier artificial `0.31415` confidence floor has been removed. A fully adverse input can report a score of exactly `0.0`; the repository no longer raises weak evidence to a decorative minimum.

Every result records:

- `LOCAL_ZERO_TRUST_POLICY_NOT_MICROSOFT_ENTRA_AUTHORITY`
- `operational_authority=false`
- `entra_api_call=false`

### Workload identity envelope

`src/workload_identity.py` creates a deterministic, non-credential identity envelope containing:

- subject;
- exact audience;
- deduplicated exact scopes;
- explicit issue and expiry times;
- source SHA;
- SHA-256 receipt.

Authorization fails closed on:

- receipt tampering;
- audience mismatch;
- missing scope;
- use outside the validity window.

The envelope is deliberately **not a token or Entra credential**. It is a local contract for reasoning about workload identity and least privilege before a future provider adapter exists.

## Proof surfaces

| Surface | Purpose |
|---|---|
| `src/zero_trust.py` | validated local risk/conditional-access decision |
| `src/workload_identity.py` | audience/scope/lifetime-bound workload identity envelope |
| `tests/test_zero_trust.py` | allow/deny, zero-floor score, malformed-signal refusal |
| `tests/test_workload_identity.py` | scope/audience/lifetime/tamper refusal |
| `.github/workflows/ci.yml` | repository CI entrypoint |

## Native proof

```bash
PYTHONPATH=src python -m pytest -q
```

## Evidence boundary

Current source does **not** establish:

- Microsoft Entra integration;
- real token validation or issuance;
- device-compliance telemetry;
- behavioral biometrics;
- live MCP or APEX registration;
- production federation, traffic, scale, reliability, or deployment.

Those are separate evidence states. The current project proves deterministic local policy, least-privilege identity structure, and fail-closed authorization semantics.
