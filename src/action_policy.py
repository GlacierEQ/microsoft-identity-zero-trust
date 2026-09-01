"""Immutable local action-to-permission policy bindings.

The policy set models the declaration side of least privilege: the action,
audience, scopes, allowed execution modes, and workload controls are defined by
trusted policy rather than supplied by the caller requesting authorization.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass

ACTION_POLICY_SCHEMA = "glaciereq.microsoft-agent-action-policy.v1"
ACTION_POLICY_SET_SCHEMA = "glaciereq.microsoft-agent-action-policy-set.v1"
_VALID_MODES = frozenset({"AUTONOMOUS", "DELEGATED"})


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _nonempty_text(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be text")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{name} must be non-empty text")
    return normalized


def _unit_interval(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a finite number in 0..1")
    numeric = float(value)
    if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
        raise ValueError(f"{name} must be a finite number in 0..1")
    return numeric


@dataclass(frozen=True, slots=True)
class ActionPolicy:
    """Trusted declaration of what one agent action actually requires."""

    action: str
    audience: str
    required_scopes: tuple[str, ...]
    allowed_modes: tuple[str, ...] = ("AUTONOMOUS", "DELEGATED")
    risk_block_threshold: float = 0.70
    require_trusted_location: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _nonempty_text("action", self.action))
        object.__setattr__(self, "audience", _nonempty_text("audience", self.audience))

        if not isinstance(self.required_scopes, tuple):
            raise TypeError("required_scopes must be a tuple")
        scopes = tuple(
            sorted(
                {
                    _nonempty_text("required_scope", scope)
                    for scope in self.required_scopes
                }
            )
        )
        if not scopes:
            raise ValueError("required_scopes must not be empty")
        object.__setattr__(self, "required_scopes", scopes)

        if not isinstance(self.allowed_modes, tuple):
            raise TypeError("allowed_modes must be a tuple")
        modes = tuple(sorted(set(self.allowed_modes)))
        if not modes:
            raise ValueError("allowed_modes must not be empty")
        if any(mode not in _VALID_MODES for mode in modes):
            raise ValueError("allowed_modes contains an unsupported mode")
        object.__setattr__(self, "allowed_modes", modes)

        object.__setattr__(
            self,
            "risk_block_threshold",
            _unit_interval("risk_block_threshold", self.risk_block_threshold),
        )
        if not isinstance(self.require_trusted_location, bool):
            raise TypeError("require_trusted_location must be boolean")

    def contract(self) -> dict[str, object]:
        return {
            "schema": ACTION_POLICY_SCHEMA,
            "action": self.action,
            "audience": self.audience,
            "required_scopes": list(self.required_scopes),
            "allowed_modes": list(self.allowed_modes),
            "risk_block_threshold": self.risk_block_threshold,
            "require_trusted_location": self.require_trusted_location,
        }

    @property
    def receipt_sha256(self) -> str:
        return _digest(self.contract())


@dataclass(frozen=True, slots=True)
class ActionPolicySet:
    """Fail-closed collection of explicitly assigned action policies."""

    policies: tuple[ActionPolicy, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.policies, tuple):
            raise TypeError("policies must be a tuple")
        if not self.policies:
            raise ValueError("policies must not be empty")
        if any(not isinstance(policy, ActionPolicy) for policy in self.policies):
            raise TypeError("policies must contain only ActionPolicy values")
        actions = [policy.action for policy in self.policies]
        if len(actions) != len(set(actions)):
            raise ValueError("action policies must have unique action names")

    def resolve(self, action: str) -> ActionPolicy | None:
        normalized = _nonempty_text("action", action)
        for policy in self.policies:
            if policy.action == normalized:
                return policy
        return None

    @property
    def receipt_sha256(self) -> str:
        body = {
            "schema": ACTION_POLICY_SET_SCHEMA,
            "policies": [
                policy.contract()
                for policy in sorted(self.policies, key=lambda policy: policy.action)
            ],
        }
        return _digest(body)
