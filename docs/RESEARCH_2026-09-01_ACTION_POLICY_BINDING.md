# Research Wave — Action-to-Permission Binding

Date: 2026-09-01

## Trigger

The first principal-aware authorization wave still accepted a caller-supplied
`required_scope`. That leaves an avoidable policy-confusion surface: an action
could describe itself with a weaker scope than the operation actually requires.

## Current Microsoft alignment studied

Microsoft Entra Agent ID currently separates permission declaration from runtime
action requests:

- agent identity blueprints declare required resource access;
- inheritable permissions establish a common baseline, while direct grants can
  remain role-specific;
- Microsoft recommends starting with enumerated essential scopes for least
  privilege;
- app roles can separate duties and responsibilities;
- assignment-required access prevents unassigned principals from invoking
  sensitive agent functionality;
- autonomous agents act with their own identity and must receive appropriate
  application permissions.

Primary sources:

- https://learn.microsoft.com/en-us/entra/agent-id/agent-blueprint
- https://learn.microsoft.com/en-us/entra/agent-id/manage-agent-identities-admin
- https://learn.microsoft.com/en-us/entra/agent-id/control-user-access-agents
- https://learn.microsoft.com/en-us/entra/agent-id/autonomous-agent-authentication-authorization-flow

## Design decision

Move audience, required scopes, allowed execution modes, risk threshold, and
trusted-location requirements into an immutable `ActionPolicySet`.

The runtime request now supplies facts about the attempted action, not its own
authorization requirements.

Unknown actions fail closed with `ACTION_NOT_ASSIGNED`.

Each policy and policy set has a deterministic SHA-256 receipt, and every
authorization result binds to those receipts.

## Security consequence

This closes the local model's caller-controlled-scope weakness and makes
least-privilege requirements reviewable independently of the request being
authorized.

## Evidence boundary

This remains a local portfolio model. It does not configure Microsoft Graph
permissions, create Entra Agent ID blueprints or identities, perform tenant
consent, enforce production Conditional Access, or grant operational access.
