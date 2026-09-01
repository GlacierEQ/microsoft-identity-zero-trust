from __future__ import annotations

from src.authorization_plane import (
    AUTHORIZATION_EVIDENCE_STATE,
    AgentActionRequest,
    WorkloadAccessPolicy,
    authorize_action,
)
from src.workload_identity import mint_workload_identity
from src.zero_trust import AccessContext


def _identity(
    *, scopes: tuple[str, ...] = ("repo.read", "evidence.read")
) -> dict[str, object]:
    return mint_workload_identity(
        subject="agent:portfolio-reviewer",
        audience="portfolio-control-plane",
        scopes=scopes,
        issued_at=100,
        expires_at=200,
        source_sha="a" * 40,
    )


def _request(**overrides: object) -> AgentActionRequest:
    values: dict[str, object] = {
        "mode": "AUTONOMOUS",
        "action": "repository.inspect",
        "audience": "portfolio-control-plane",
        "required_scope": "repo.read",
        "now": 150,
        "service_principal_risk": 0.10,
        "trusted_location": True,
    }
    values.update(overrides)
    return AgentActionRequest(**values)  # type: ignore[arg-type]


def test_autonomous_action_requires_identity_scope_risk_and_location() -> None:
    result = authorize_action(_identity(), _request())
    assert result["decision"] == "ALLOW"
    assert result["reasons"] == []
    assert result["evidence_state"] == AUTHORIZATION_EVIDENCE_STATE
    assert result["operational_authority"] is False
    assert result["entra_api_call"] is False
    assert isinstance(result["receipt_sha256"], str)


def test_identity_scope_failure_blocks_before_action() -> None:
    result = authorize_action(_identity(scopes=("evidence.read",)), _request())
    assert result["decision"] == "DENY"
    assert "SCOPE_MISSING" in result["reasons"]


def test_workload_risk_and_location_are_explicit_block_controls() -> None:
    result = authorize_action(
        _identity(),
        _request(service_principal_risk=0.70, trusted_location=False),
    )
    assert result["decision"] == "DENY"
    assert result["reasons"] == ["WORKLOAD_RISK_BLOCKED", "UNTRUSTED_LOCATION"]


def test_delegated_action_requires_separate_human_context() -> None:
    result = authorize_action(_identity(), _request(mode="DELEGATED"))
    assert result["decision"] == "DENY"
    assert result["reasons"] == ["HUMAN_CONTEXT_REQUIRED"]


def test_delegated_action_allows_when_both_identity_and_human_gates_allow() -> None:
    human = AccessContext(0.05, 0.99, True, 0.0, False)
    result = authorize_action(
        _identity(), _request(mode="DELEGATED", human_context=human)
    )
    assert result["decision"] == "ALLOW"
    assert result["human_decision"] == "ALLOW"


def test_delegated_step_up_is_preserved_instead_of_collapsed_to_allow() -> None:
    human = AccessContext(0.50, 0.70, True, 0.50, False)
    result = authorize_action(
        _identity(), _request(mode="DELEGATED", human_context=human)
    )
    assert result["decision"] == "STEP_UP"
    assert result["reasons"] == ["HUMAN_STEP_UP_REQUIRED"]


def test_tampered_identity_fails_closed_without_throwing_away_receipt() -> None:
    identity = _identity()
    identity["audience"] = "tampered"
    result = authorize_action(identity, _request())
    assert result["decision"] == "DENY"
    assert result["reasons"] == ["IDENTITY_INTEGRITY_FAILED"]
    assert isinstance(result["receipt_sha256"], str)


def test_policy_threshold_is_configurable_but_bounded() -> None:
    policy = WorkloadAccessPolicy(risk_block_threshold=0.90)
    result = authorize_action(
        _identity(), _request(service_principal_risk=0.80), policy=policy
    )
    assert result["decision"] == "ALLOW"
