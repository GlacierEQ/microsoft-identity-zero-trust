"""Privacy-preserving behavioral risk signal for continuous authentication.

This module consumes aggregate interaction features, not raw keystrokes or
pointer traces. It produces a bounded risk signal for policy step-up; it is
not an identity proof and must not authorize high-impact actions by itself.
"""
from __future__ import annotations
from dataclasses import dataclass
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
    for name, value in features.as_mapping().items():
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"non-finite feature: {name}")
        if value < 0:
            raise ValueError(f"negative feature: {name}")
    for name in ("correction_rate", "pointer_curvature", "pause_rate"):
        if getattr(features, name) > 1:
            raise ValueError(f"ratio out of range: {name}")


def assess(baseline: InteractionFeatures, current: InteractionFeatures) -> BehavioralAssessment:
    """Compare aggregate profiles and return a bounded step-up risk signal.

    The relative distance is intentionally simple and explainable. Production
    use requires calibration, consent, accessibility review, replay/injection
    testing, and independent false-accept/false-reject measurement.
    """
    _validate(baseline)
    _validate(current)
    distances = []
    for name in FEATURES:
        reference = max(abs(getattr(baseline, name)), 1.0)
        distances.append(min(abs(getattr(current, name) - getattr(baseline, name)) / reference, 1.0))
    distance = sum(distances) / len(distances)
    risk = round(distance, 4)
    confidence = round(min(1.0, max(0.0, 1.0 - distance)), 4)
    reason = "step-up-suggested" if risk >= 0.65 else "within-baseline-range"
    return BehavioralAssessment(risk=risk, confidence=confidence, reason=reason)
