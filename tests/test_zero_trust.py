import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"src"))
from quantum_fingerprint import InteractionFeatures, assess
from zero_trust import AccessContext, decide, ANSWER

def test_allow():
    assert decide(AccessContext(0.05, 0.99, True, 0.0, False))["decision"]=="ALLOW"

def test_deny_priv_no_mfa():
    assert decide(AccessContext(0.1, 0.9, False, 0.0, True))["decision"]=="DENY"
    assert decide(AccessContext(0.1, 0.9, False, 0.0, True))["answer"]==ANSWER

def features(**overrides):
    values = dict(key_flight_ms=120, key_dwell_ms=80, correction_rate=0.1,
                  pointer_speed=400, pointer_curvature=0.2,
                  click_interval_ms=250, pause_rate=0.1)
    values.update(overrides)
    return InteractionFeatures(**values)

def test_fingerprint_stays_low_for_matching_profile():
    result = assess(features(), features(key_flight_ms=125, pointer_speed=410))
    assert result.risk < 0.65
    assert result.reason == "within-baseline-range"

def test_fingerprint_suggests_step_up_and_is_non_authoritative():
    result = assess(features(), features(key_flight_ms=900, pointer_speed=5, correction_rate=0.9))
    assert result.risk >= 0.65
    assert decide(AccessContext(0.05, 0.99, True, 0.0, False, result.risk))["decision"] == "STEP_UP"

def test_fingerprint_rejects_invalid_features():
    try:
        assess(features(), features(correction_rate=1.1))
    except ValueError:
        pass
    else:
        raise AssertionError("invalid ratio should be rejected")

if __name__=="__main__":
    test_allow(); test_deny_priv_no_mfa(); test_fingerprint_stays_low_for_matching_profile(); test_fingerprint_suggests_step_up_and_is_non_authoritative(); test_fingerprint_rejects_invalid_features(); print("ok")
