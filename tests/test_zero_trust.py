from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zero_trust import EVIDENCE_STATE, AccessContext, decide


def test_allow() -> None:
    result = decide(AccessContext(0.05, 0.99, True, 0.0, False))
    assert result["decision"] == "ALLOW"
    assert result["evidence_state"] == EVIDENCE_STATE
    assert result["operational_authority"] is False
    assert result["entra_api_call"] is False


def test_deny_privileged_without_mfa() -> None:
    result = decide(AccessContext(0.1, 0.9, False, 0.0, True))
    assert result["decision"] == "DENY"
    assert result["reason"] == "privileged role requires MFA"


def test_score_has_no_artificial_floor() -> None:
    result = decide(AccessContext(1.0, 0.0, False, 1.0, False))
    assert result["decision"] == "DENY"
    assert result["score"] == 0.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"user_risk": -0.1, "device_health": 1.0, "mfa_ok": True, "geo_anomaly": 0.0, "priv_role": False},
        {"user_risk": 0.1, "device_health": math.nan, "mfa_ok": True, "geo_anomaly": 0.0, "priv_role": False},
        {"user_risk": 0.1, "device_health": 1.0, "mfa_ok": "yes", "geo_anomaly": 0.0, "priv_role": False},
    ],
)
def test_malformed_signals_fail_closed(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        AccessContext(**kwargs)  # type: ignore[arg-type]
