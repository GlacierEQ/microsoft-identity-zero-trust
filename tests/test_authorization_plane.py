from __future__ import annotations

from src.action_policy import ActionPolicy, ActionPolicySet
from src.authorization_plane import (
    AUTHORIZATION_EVIDENCE_STATE,
    AgentActionRequest,
    authorize_action,
)
from src.workload_identity import mint_workload_identity
from src.zero_trust import AccessContext


def _policies() -> ActionPolicySet:
    return ActionPolicySet(
        (
            ActionPolicy(
                action="repository.inspect",
                audience="portfolio-control-plane",
                required_scopes=("repo.read", "evidence.read"),
            ),
            ActionPolicy(
                action="repository.mutate",
                audience="portfolio-control-plane",
                required_scopes=("repo.write",),
                allowed_modes=("DELEGATED",),
                risk_block_threshold=0.30,
            ),
        )
    )


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
        "now": 150,
        "service_principal_risk": 0.10,
        "trusted_location": True,
    }
    values.update(overrides)
    return AgentActionRequest(**values)  # type: ignore[arg-type]


def test_action_policy_receipts_are_deterministic() -> None:
    first = _policies()
    second = _policies()
    assert first.receipt_sha256 == second.receipt_sha256
    assert first.resolve("repository.inspect") is not None


def test_autonomous_action_derives_required_scopes_from_policy() -> None:
    result = authorize_action(_identity(), _request(), policies=_policies())
    assert result["decision"] == "ALLOW"
    assert result["reasons"] == []
    assert result["required_scopes"] == ["evidence.read", "repo.read"]
    assert result["evidence_state"] == AUTHORIZATION_EVIDENCE_STATE
    assert result["assignment_required"] is True
    assert result["operational_authority"] is False


def test_missing_any_policy_required_scope_fails_closed() -> None:
    result = authorize_action(
        _identity(scopes=("repo.read",)),
        _request(),
        policies=_policies(),
    )
    assert result["decision"] == "DENY"
    assert result["reasons"] == ["SCOPE_MISSING"]


def test_unknown_action_is_denied_instead_of_self_describing_permissions() -> None:
    result = authorize_action(
        _identity(),
        _request(action="repository.delete-everything"),
        policies=_policies(),
    )
    assert result["decision"] == "DENY"
    assert "ACTION_NOT_ASSIGNED" in result["reasons"]
    assert result["policy_assigned"] is False
    assert result["required_scopes"] == []


def test_autonomous_mode_cannot_invoke_delegated_only_mutation() -> None:
    result = authorize_action(
        _identity(scopes=("repo.write",)),
        _request(action="repository.mutate"),
        policies=_policies(),
    )
    assert result["decision"] == "DENY"
    assert "MODE_NOT_ALLOWED" in result["reasons"]


def test_delegated_mutation_allows_only_when_all_gates_allow() -> None:
    human = AccessContext(0.05, 0.99, True, 0.0, False)
    result = authorize_action(
        _identity(scopes=("repo.write",)),
        _request(
            mode="DELEGATED",
            action="repository.mutate",
            human_context=human,
            service_principal_risk=0.20,
        ),
        policies=_policies(),
    )
    assert result["decision"] == "ALLOW"
    assert result["human_decision"] == "ALLOW"
    assert result["required_scopes"] == ["repo.write"]


def test_action_specific_risk_threshold_is_enforced() -> None:
    human = AccessContext(0.05, 0.99, True, 0.0, False)
    result = authorize_action(
        _identity(scopes=("repo.write",)),
        _request(
            mode="DELEGATED",
            action="repository.mutate",
            human_context=human,
            service_principal_risk=0.30,
        ),
        policies=_policies(),
    )
    assert result["decision"] == "DENY"
    assert "WORKLOAD_RISK_BLOCKED" in result["reasons"]


def test_delegated_action_requires_separate_human_context() -> None:
    result = authorize_action(
        _identity(scopes=("repo.write",)),
        _request(mode="DELEGATED", action="repository.mutate"),
        policies=_policies(),
    )
    assert result["decision"] == "DENY"
    assert "HUMAN_CONTEXT_REQUIRED" in result["reasons"]


def test_delegated_step_up_is_preserved_when_it_is_the_only_blocker() -> None:
    human = AccessContext(0.50, 0.70, True, 0.50, False)
    result = authorize_action(
        _identity(),
        _request(mode="DELEGATED", human_context=human),
        policies=_policies(),
    )
    assert result["decision"] == "STEP_UP"
    assert result["reasons"] == ["HUMAN_STEP_UP_REQUIRED"]


def test_tampered_identity_fails_closed_and_still_produces_receipt() -> None:
    identity = _identity()
    identity["audience"] = "tampered"
    result = authorize_action(identity, _request(), policies=_policies())
    assert result["decision"] == "DENY"
    assert "IDENTITY_INTEGRITY_FAILED" in result["reasons"]
    assert isinstance(result["receipt_sha256"], str)
