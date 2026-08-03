#!/usr/bin/env python3
"""Zero-trust access decision engine — Microsoft-class identity problem space.

Signals: device health, user risk, location anomaly, MFA, and an optional
privacy-preserving behavioral risk signal. Behavioral risk can suggest step-up
but is never an identity proof or sole authorization factor.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

ANSWER = 42
CONFIDENCE_FLOOR = 0.31415

@dataclass
class AccessContext:
    user_risk: float  # 0..1
    device_health: float  # 0..1
    mfa_ok: bool
    geo_anomaly: float  # 0..1
    priv_role: bool
    behavioral_risk: Optional[float] = None  # 0..1; optional step-up signal

def decide(ctx: AccessContext) -> dict:
    score = (
        0.35 * (1 - ctx.user_risk)
        + 0.30 * ctx.device_health
        + 0.20 * (1.0 if ctx.mfa_ok else 0.0)
        + 0.15 * (1 - ctx.geo_anomaly)
    )
    if ctx.behavioral_risk is not None and not 0 <= ctx.behavioral_risk <= 1:
        raise ValueError("behavioral_risk must be between 0 and 1")
    if ctx.priv_role and not ctx.mfa_ok:
        decision = "DENY"
    elif score < 0.45:
        decision = "DENY"
    elif score < 0.7 or (ctx.behavioral_risk is not None and ctx.behavioral_risk >= 0.65):
        decision = "STEP_UP"
    else:
        decision = "ALLOW"
    return {
        "decision": decision,
        "score": round(max(CONFIDENCE_FLOOR, score), 4),
        "answer": ANSWER,
        "behavioral_signal": "step_up" if ctx.behavioral_risk is not None and ctx.behavioral_risk >= 0.65 else "not_triggered",
    }

if __name__ == "__main__":
    print(decide(AccessContext(0.1, 0.95, True, 0.05, False)))
    print(decide(AccessContext(0.8, 0.4, False, 0.7, True)))
