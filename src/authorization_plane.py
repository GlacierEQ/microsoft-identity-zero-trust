"""Principal-aware local authorization plane for autonomous and delegated agents.

This module composes the repository's workload-identity envelope with its
human zero-trust policy without pretending they are the same identity type.
Action requirements come from a trusted policy set rather than from the caller.

It performs no Microsoft Entra operation and grants no production authority.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .action_policy import ActionPolicySet
from .workload_identity import authorize_scope, verify_identity
from .zero_trust import AccessContext, decide

AUTHORIZATION_SCHEMA = "glaciereq.microsoft-agent-authorization.v2"
AUTHORIZATION_EVIDENCE_STATE = (
    "LOCAL_AGENT_AND_WORKLOAD_AUTHORIZATION_MODEL_NOT_MICROSOFT_ENTRA_AUTHORITY"
)

Mode = Literal["AUTONOMOUS", "DELEGATED"]


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _unit_interval(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a finite number in 0..1")
    numeric = float(value)
    if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
        raise ValueError(f"{name} must be a finite number in 0..1")
    return numeric


@dataclass(frozen=True, slots=True)
class AgentActionRequest:
    """Runtime facts for an action whose requirements are policy-defined."""

    mode: Mode
    action: str
    now: int
    service_principal_risk: float
    trusted_location: bool
    human_context: AccessContext | None = None

    def __post_init__(self) -> None:
        if self.mode not in ("AUTONOMOUS", "DELEGATED"):
            raise ValueError("mode must be AUTONOMOUS or DELEGATED")
        if not isinstance(self.action, str):
            raise TypeError("action must be text")
        if not self.action.strip():
            raise ValueError("action must be non-empty text")
        object.__setattr__(self, "action", self.action.strip())
        if isinstance(self.now, bool) or not isinstance(self.now, int):
            raise TypeError("now must be an integer")
        object.__setattr__(
            self,
            "service_principal_risk",
            _unit_interval("service_principal_risk", self.service_principal_risk),
        )
        if not isinstance(self.trusted_location, bool):
            raise TypeError("trusted_location must be boolean")
        if self.human_context is not None and not isinstance(
            self.human_context, AccessContext
        ):
            raise TypeError("human_context must be an AccessContext or None")


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def authorize_action(
    identity: Mapping[str, object],
    request: AgentActionRequest,
    *,
    policies: ActionPolicySet,
) -> dict[str, object]:
    """Evaluate one action against explicit least-privilege policy bindings."""

    if not isinstance(request, AgentActionRequest):
        raise TypeError("request must be an AgentActionRequest")
    if not isinstance(policies, ActionPolicySet):
        raise TypeError("policies must be an ActionPolicySet")

    reasons: list[str] = []
    policy = policies.resolve(request.action)
    scope_receipts: list[str] = []

    if policy is None:
        _append_reason(reasons, "ACTION_NOT_ASSIGNED")
    elif request.mode not in policy.allowed_modes:
        _append_reason(reasons, "MODE_NOT_ALLOWED")

    identity_receipt = identity.get("receipt_sha256")
    identity_valid = verify_identity(identity)
    if not identity_valid:
        _append_reason(reasons, "IDENTITY_INTEGRITY_FAILED")

    if policy is not None and identity_valid:
        for required_scope in policy.required_scopes:
            scope_decision = authorize_scope(
                identity,
                audience=policy.audience,
                required_scope=required_scope,
                now=request.now,
            )
            for reason in scope_decision["reasons"]:
                _append_reason(reasons, str(reason))
            receipt = scope_decision.get("receipt_sha256")
            if isinstance(receipt, str):
                scope_receipts.append(receipt)

    if policy is not None:
        if request.service_principal_risk >= policy.risk_block_threshold:
            _append_reason(reasons, "WORKLOAD_RISK_BLOCKED")
        if policy.require_trusted_location and not request.trusted_location:
            _append_reason(reasons, "UNTRUSTED_LOCATION")

    human_decision: dict[str, object] | None = None
    if request.mode == "DELEGATED":
        if request.human_context is None:
            _append_reason(reasons, "HUMAN_CONTEXT_REQUIRED")
        else:
            human_decision = decide(request.human_context)
            if human_decision["decision"] == "DENY":
                _append_reason(reasons, "HUMAN_ACCESS_DENIED")
            elif human_decision["decision"] == "STEP_UP":
                _append_reason(reasons, "HUMAN_STEP_UP_REQUIRED")

    if reasons:
        decision = "STEP_UP" if reasons == ["HUMAN_STEP_UP_REQUIRED"] else "DENY"
    else:
        decision = "ALLOW"

    body: dict[str, object] = {
        "schema": AUTHORIZATION_SCHEMA,
        "mode": request.mode,
        "action": request.action,
        "decision": decision,
        "reasons": reasons,
        "policy_assigned": policy is not None,
        "policy_receipt_sha256": policy.receipt_sha256 if policy else None,
        "policy_set_receipt_sha256": policies.receipt_sha256,
        "audience": policy.audience if policy else None,
        "required_scopes": list(policy.required_scopes) if policy else [],
        "allowed_modes": list(policy.allowed_modes) if policy else [],
        "risk_block_threshold": policy.risk_block_threshold if policy else None,
        "require_trusted_location": (
            policy.require_trusted_location if policy else None
        ),
        "identity_receipt_sha256": identity_receipt,
        "scope_authorization_receipts_sha256": scope_receipts,
        "human_decision": human_decision["decision"] if human_decision else None,
        "service_principal_risk": request.service_principal_risk,
        "trusted_location": request.trusted_location,
        "evidence_state": AUTHORIZATION_EVIDENCE_STATE,
        "assignment_required": True,
        "credential": False,
        "operational_authority": False,
        "entra_api_call": False,
    }
    body["receipt_sha256"] = _digest(body)
    return body
