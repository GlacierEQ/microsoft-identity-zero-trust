"""Privacy-preserving behavioral risk signal for continuous authentication.

This module consumes aggregate interaction features, never raw keystrokes or
pointer traces. It produces a bounded risk signal for policy step-up; it is
not an identity proof and must not authorize high-impact actions by itself.

Callers remain responsible for consent, local collection, retention limits,
accessibility accommodation, rate limiting, and secure template storage.
"""
from __future__ import annotations
from dataclasses import dataclass
from math import isfinite
from typing import Mapping

FEATURES = (
    "key_flight_ms",
    "key_dwell_ms",
    "correction_rate",
    "pointer_speed",
    "pointer_curvature",
    "click_interval_ms",
    "pause_rate",
)

# Conservative ingestion bounds prevent malformed or adversarial values from
# dominating the score. They are validation limits, not identity assumptions.
MAX_FEATURE = {
    "key_flight_ms": 10_000.0,
    "key_dwell_ms": 10_000.0,
    "correction_rate": 1.0,
    "pointer_speed": 10_000.0,
    "pointer_curvature": 1.0,
    "click_interval_ms": 60_000.0,
    "pause_rate": 1.0,
}

@dataclass(frozen=True)
class InteractionFeatures:
    key_flight_ms: float
    key_dwell_ms: float
    correction_rate: float
    pointer_speed: float
    pointer_curvature: float
    click_interval_ms: float
    pause_rate: float

    def as_mapping(self) -> Mapping[str, float]:
        return {name: float(getattr(self, name)) for name in FEATURES}

@dataclass(frozen=True)
class BehavioralAssessment:
    risk: float
    confidence: float
    reason: str


def _validate(features: InteractionFeatures) -> None:
    for name in FEATURES:
        raw_value = getattr(features, name)
        # bool is an int subclass; reject it so true/false cannot masquerade
        # as measurements.
        if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
            raise ValueError(f"feature must be numeric: {name}")
        value = float(raw_value)
        if not isfinite(value):
            raise ValueError(f"non-finite feature: {name}")
        if value < 0 or value > MAX_FEATURE[name]:
            raise ValueError(f"feature out of bounds: {name}")


def assess(baseline: InteractionFeatures, current: InteractionFeatures) -> BehavioralAssessment:
    """Compare aggregate profiles and return a bounded step-up risk signal.

    The relative distance is intentionally simple and explainable. Production
    use requires calibration, consent, accessibility review, replay/injection
    testing, minimum-sample policy, and independent false-accept/false-reject
    measurement. Do not use this result as sole authorization or expose raw
    interaction events to a remote service.
    """
    _validate(baseline)
    _validate(current)
    distances = []
    for name in FEATURES:
        reference = max(abs(float(getattr(baseline, name))), 1.0)
        distances.append(min(abs(float(getattr(current, name)) - float(getattr(baseline, name))) / reference, 1.0))
    distance = sum(distances) / len(distances)
    risk = round(min(1.0, max(0.0, distance)), 4)
    confidence = round(min(1.0, max(0.0, 1.0 - risk)), 4)
    reason = "step-up-suggested" if risk >= 0.65 else "within-baseline-range"
    return BehavioralAssessment(risk=risk, confidence=confidence, reason=reason)
