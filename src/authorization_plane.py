"""Principal-aware local authorization plane for autonomous and delegated agents.

This module composes the repository's workload-identity envelope with its
human zero-trust policy without pretending they are the same identity type.
Autonomous actions are evaluated with workload controls. Delegated actions
add the human access decision as a separate gate.

It performs no Microsoft Entra operation and grants no production authority.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .workload_identity import authorize_scope, verify_identity
from .zero_trust import AccessContext, decide

AUTHORIZATION_SCHEMA = "glaciereq.microsoft-agent-authorization.v1"
AUTHORIZATION_EVIDENCE_STATE = (
    "LOCAL_AGENT_AND_WORKLOAD_AUTHORIZATION_MODEL_NOT_MICROSOFT_ENTRA_AUTHORITY"
)

Mode = Literal["AUTONOMOUS", "DELEGATED"]


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _unit_interval(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number in 0..1")
    numeric = float(value)
    if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
        raise ValueError(f"{name} must be a finite number in 0..1")
    return numeric


@dataclass(frozen=True, slots=True)
class WorkloadAccessPolicy:
    """Local modeled controls for nonhuman identity access."""

    risk_block_threshold: float = 0.70
    require_trusted_location: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "risk_block_threshold",
            _unit_interval("risk_block_threshold", self.risk_block_threshold),
        )
        if not isinstance(self.require_trusted_location, bool):
            raise ValueError("require_trusted_location must be boolean")


@dataclass(frozen=True, slots=True)
class AgentActionRequest:
    """A bounded action request evaluated by the local authorization plane."""

    mode: Mode
    action: str
    audience: str
    required_scope: str
    now: int
    service_principal_risk: float
    trusted_location: bool
    human_context: AccessContext | None = None

    def __post_init__(self) -> None:
        if self.mode not in ("AUTONOMOUS", "DELEGATED"):
            raise ValueError("mode must be AUTONOMOUS or DELEGATED")
        for name, value in (
            ("action", self.action),
            ("audience", self.audience),
            ("required_scope", self.required_scope),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty text")
        if isinstance(self.now, bool) or not isinstance(self.now, int):
            raise ValueError("now must be an integer")
        object.__setattr__(
            self,
            "service_principal_risk",
            _unit_interval("service_principal_risk", self.service_principal_risk),
        )
        if not isinstance(self.trusted_location, bool):
            raise ValueError("trusted_location must be boolean")
        if self.human_context is not None and not isinstance(
            self.human_context, AccessContext
        ):
            raise ValueError("human_context must be an AccessContext or None")


def authorize_action(
    identity: Mapping[str, object],
    request: AgentActionRequest,
    *,
    policy: WorkloadAccessPolicy | None = None,
) -> dict[str, object]:
    """Return a deterministic, receipt-bound local authorization decision.

    The gates remain explicit:
    1. workload identity integrity + exact audience/scope/lifetime;
    2. nonhuman identity risk/location policy;
    3. when delegated, a separate human zero-trust decision.
    """

    if not isinstance(request, AgentActionRequest):
        raise ValueError("request must be an AgentActionRequest")
    policy = policy or WorkloadAccessPolicy()
    if not isinstance(policy, WorkloadAccessPolicy):
        raise ValueError("policy must be a WorkloadAccessPolicy")

    reasons: list[str] = []
    identity_receipt = identity.get("receipt_sha256")

    if not verify_identity(identity):
        reasons.append("IDENTITY_INTEGRITY_FAILED")
        scope_decision: dict[str, object] | None = None
    else:
        scope_decision = authorize_scope(
            identity,
            audience=request.audience,
            required_scope=request.required_scope,
            now=request.now,
        )
        reasons.extend(str(reason) for reason in scope_decision["reasons"])

    if request.service_principal_risk >= policy.risk_block_threshold:
        reasons.append("WORKLOAD_RISK_BLOCKED")
    if policy.require_trusted_location and not request.trusted_location:
        reasons.append("UNTRUSTED_LOCATION")

    human_decision: dict[str, object] | None = None
    if request.mode == "DELEGATED":
        if request.human_context is None:
            reasons.append("HUMAN_CONTEXT_REQUIRED")
        else:
            human_decision = decide(request.human_context)
            if human_decision["decision"] == "DENY":
                reasons.append("HUMAN_ACCESS_DENIED")
            elif human_decision["decision"] == "STEP_UP":
                reasons.append("HUMAN_STEP_UP_REQUIRED")

    if reasons:
        decision = "STEP_UP" if reasons == ["HUMAN_STEP_UP_REQUIRED"] else "DENY"
    else:
        decision = "ALLOW"

    body: dict[str, object] = {
        "schema": AUTHORIZATION_SCHEMA,
        "mode": request.mode,
        "action": request.action.strip(),
        "audience": request.audience.strip(),
        "required_scope": request.required_scope.strip(),
        "now": request.now,
        "decision": decision,
        "reasons": reasons,
        "identity_receipt_sha256": identity_receipt,
        "scope_authorization_receipt_sha256": (
            scope_decision.get("receipt_sha256") if scope_decision else None
        ),
        "human_decision": human_decision["decision"] if human_decision else None,
        "service_principal_risk": request.service_principal_risk,
        "trusted_location": request.trusted_location,
        "evidence_state": AUTHORIZATION_EVIDENCE_STATE,
        "credential": False,
        "operational_authority": False,
        "entra_api_call": False,
    }
    body["receipt_sha256"] = _digest(body)
    return body
