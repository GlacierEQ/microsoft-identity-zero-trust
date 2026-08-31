#!/usr/bin/env python3
"""Deterministic local zero-trust access policy.

This module evaluates caller-supplied risk/device/MFA/location signals. It is an
independent portfolio policy model: it does not contact Microsoft Entra, mint
real credentials, inspect real devices, or grant production access.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

EVIDENCE_STATE = "LOCAL_ZERO_TRUST_POLICY_NOT_MICROSOFT_ENTRA_AUTHORITY"


def _unit_interval(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number in 0..1")
    numeric = float(value)
    if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
        raise ValueError(f"{name} must be a finite number in 0..1")
    return numeric


@dataclass(frozen=True, slots=True)
class AccessContext:
    user_risk: float
    device_health: float
    mfa_ok: bool
    geo_anomaly: float
    priv_role: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "user_risk", _unit_interval("user_risk", self.user_risk))
        object.__setattr__(
            self, "device_health", _unit_interval("device_health", self.device_health)
        )
        object.__setattr__(
            self, "geo_anomaly", _unit_interval("geo_anomaly", self.geo_anomaly)
        )
        if not isinstance(self.mfa_ok, bool):
            raise ValueError("mfa_ok must be boolean")
        if not isinstance(self.priv_role, bool):
            raise ValueError("priv_role must be boolean")


def decide(ctx: AccessContext) -> dict[str, object]:
    """Return a bounded local access decision with no artificial score floor."""

    if not isinstance(ctx, AccessContext):
        raise ValueError("ctx must be an AccessContext")
    score = (
        0.35 * (1.0 - ctx.user_risk)
        + 0.30 * ctx.device_health
        + 0.20 * (1.0 if ctx.mfa_ok else 0.0)
        + 0.15 * (1.0 - ctx.geo_anomaly)
    )
    if ctx.priv_role and not ctx.mfa_ok:
        decision = "DENY"
        reason = "privileged role requires MFA"
    elif score < 0.45:
        decision = "DENY"
        reason = "weighted local risk score below allow threshold"
    elif score < 0.70:
        decision = "STEP_UP"
        reason = "weighted local risk score requires additional verification"
    else:
        decision = "ALLOW"
        reason = "weighted local risk score satisfies modeled policy"

    return {
        "decision": decision,
        "score": round(score, 4),
        "reason": reason,
        "evidence_state": EVIDENCE_STATE,
        "operational_authority": False,
        "entra_api_call": False,
    }


if __name__ == "__main__":
    print(decide(AccessContext(0.1, 0.95, True, 0.05, False)))
    print(decide(AccessContext(0.8, 0.4, False, 0.7, True)))
