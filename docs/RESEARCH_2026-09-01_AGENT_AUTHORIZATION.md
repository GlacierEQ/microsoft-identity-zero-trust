# Research Wave — Agent / Workload Authorization Plane

Date: 2026-09-01

## Why this wave

The repository already proved two local mechanisms: a caller-supplied zero-trust risk policy and a receipt-bound workload identity envelope. The missing leverage was composition: there was no single action-authorization path that preserved the distinction between autonomous nonhuman identity access and delegated human access.

## Current Microsoft alignment studied

- Microsoft Entra Workload ID treats apps and service principals as workload identities and supports Conditional Access for workload identities.
- Conditional Access for workload identities can block access based on location and service-principal risk.
- Continuous access evaluation can enforce workload identity location/risk policy changes in real time.
- Microsoft Entra Agent ID defines agent identities as a distinct identity type for AI agents, including autonomous and delegated access patterns.

Primary sources:
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation-workload
- https://learn.microsoft.com/en-us/entra/agent-id/what-are-agent-identities
- https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id

## Design decision

Do not collapse human and nonhuman identities into one generic score.

The new local authorization plane evaluates three explicit gates:

1. workload identity integrity plus exact audience/scope/lifetime;
2. modeled service-principal risk and trusted-location controls;
3. for delegated actions only, the existing human zero-trust decision.

The output is a deterministic receipt-bound decision with explicit reason codes.

## Evidence boundary

This remains an independent local model. It does not create Microsoft Entra agent identities, call Microsoft Graph, mint credentials, consume tenant telemetry, enforce production Conditional Access, or grant real access.
