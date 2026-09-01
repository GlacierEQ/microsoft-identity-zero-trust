# Microsoft Identity Zero Trust — Local Identity Policy Study

Independent GlacierEQ portfolio work modeling three identity-security boundaries:

1. a deterministic zero-trust access policy over caller-supplied risk, device-health, MFA, location-anomaly, and privilege signals;
2. a hash-bound workload-identity envelope with exact audience, scope, lifetime, and source binding; and
3. a policy-bound agent action authorization plane that derives audience, scopes, allowed execution modes, and workload controls from trusted action policy rather than caller self-description.

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


### Agent / workload authorization plane

`src/authorization_plane.py` composes the existing local mechanisms without
pretending that human and nonhuman identities are the same principal type.

For every modeled agent action it evaluates:

1. explicit action assignment from `src/action_policy.py`;
2. policy-derived audience and one-or-more exact required scopes;
3. workload identity integrity plus exact audience, scope, and lifetime;
4. action-specific allowed modes, service-principal risk threshold, and trusted-location controls; and
5. for `DELEGATED` actions only, the separate human zero-trust decision.

Unknown actions fail closed with `ACTION_NOT_ASSIGNED`. The runtime request no longer supplies its own required scope. Each action policy and policy set has a deterministic SHA-256 receipt that is bound into the authorization result.

The result is a deterministic receipt-bound `ALLOW`, `STEP_UP`, or `DENY`
decision with explicit reason codes.

This is intentionally a local model. It does not create Microsoft Entra Agent
ID objects, consume tenant risk telemetry, enforce production Conditional
Access, or grant real access.

## Proof surfaces

| Surface | Purpose |
|---|---|
| `src/zero_trust.py` | validated local risk/conditional-access decision |
| `src/workload_identity.py` | audience/scope/lifetime-bound workload identity envelope |
| `src/action_policy.py` | immutable action-to-audience/scope/mode/risk policy binding |
| `src/authorization_plane.py` | principal-aware autonomous/delegated action authorization |
| `tests/test_authorization_plane.py` | assignment, scope, mode, identity, risk, location, and delegation refusal paths |
| `docs/RESEARCH_2026-09-01_AGENT_AUTHORIZATION.md` | current Agent ID / workload identity research basis |
| `docs/RESEARCH_2026-09-01_ACTION_POLICY_BINDING.md` | least-privilege action-policy research and design decision |
| `tests/test_zero_trust.py` | allow/deny, zero-floor score, malformed-signal refusal |
| `tests/test_workload_identity.py` | scope/audience/lifetime/tamper refusal |
| `.github/workflows/ci.yml` | repository CI entrypoint |

## Native proof

```bash
bash .github/verification/python.sh
```

## Evidence boundary

Current source does **not** establish:

- Microsoft Entra integration;
- real token validation or issuance;
- device-compliance telemetry;
- behavioral biometrics;
- live MCP or APEX registration;
- production federation, traffic, scale, reliability, or deployment;
- real Microsoft Entra Agent ID provisioning or tenant policy enforcement.

Those are separate evidence states. The current project proves deterministic local policy, least-privilege identity structure, fail-closed action assignment, policy-derived multi-scope authorization, and receipt-bound authorization semantics.
