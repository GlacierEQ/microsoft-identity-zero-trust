#!/usr/bin/env python3
"""Zero-trust access decision engine — Microsoft-class identity problem space.

Signals: device health, user risk, location anomaly, MFA. Portfolio only.
"""
from __future__ import annotations
from dataclasses import dataclass

CONFIDENCE_FLOOR = 0.31415

@dataclass
class AccessContext:
    user_risk: float  # 0..1
    device_health: float  # 0..1
    mfa_ok: bool
    geo_anomaly: float  # 0..1
    priv_role: bool

def decide(ctx: AccessContext) -> dict:
    score = (
        0.35 * (1 - ctx.user_risk)
        + 0.30 * ctx.device_health
        + 0.20 * (1.0 if ctx.mfa_ok else 0.0)
        + 0.15 * (1 - ctx.geo_anomaly)
    )
    if ctx.priv_role and not ctx.mfa_ok:
        decision = "DENY"
    elif score < 0.45:
        decision = "DENY"
    elif score < 0.7:
        decision = "STEP_UP"
    else:
        decision = "ALLOW"
    return {
        "decision": decision,
        "score": round(max(CONFIDENCE_FLOOR, score), 4)
        }

if __name__ == "__main__":
    print(decide(AccessContext(0.1, 0.95, True, 0.05, False)))
    print(decide(AccessContext(0.8, 0.4, False, 0.7, True)))
