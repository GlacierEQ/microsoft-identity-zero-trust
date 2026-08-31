from __future__ import annotations

import pytest

from src.workload_identity import (
    IDENTITY_EVIDENCE_STATE,
    authorize_scope,
    mint_workload_identity,
    verify_identity,
)


def _identity() -> dict[str,object]:
    return mint_workload_identity(
        subject="agent:portfolio-reviewer",
        audience="portfolio-control-plane",
        scopes=["repo.read","evidence.read"],
        issued_at=100,
        expires_at=200,
        source_sha="a"*40,
    )


def test_identity_is_deterministic_noncredential_and_scope_bound() -> None:
    first=_identity()
    second=_identity()
    assert first==second
    assert verify_identity(first)
    assert first["evidence_state"]==IDENTITY_EVIDENCE_STATE
    assert first["credential"] is False
    assert first["entra_api_call"] is False
    result=authorize_scope(
        first,
        audience="portfolio-control-plane",
        required_scope="repo.read",
        now=150,
    )
    assert result["allowed"] is True
    assert result["reasons"]==[]


@pytest.mark.parametrize(
    ("audience","scope","now","reason"),
    [
        ("other","repo.read",150,"AUDIENCE_MISMATCH"),
        ("portfolio-control-plane","repo.write",150,"SCOPE_MISSING"),
        ("portfolio-control-plane","repo.read",200,"OUTSIDE_VALIDITY_WINDOW"),
    ],
)
def test_wrong_audience_scope_or_lifetime_fails_closed(
    audience:str,scope:str,now:int,reason:str
) -> None:
    result=authorize_scope(_identity(),audience=audience,required_scope=scope,now=now)
    assert result["allowed"] is False
    assert reason in result["reasons"]


def test_tampered_identity_fails_integrity() -> None:
    identity=_identity()
    identity["audience"]="other"
    assert verify_identity(identity) is False
    with pytest.raises(ValueError,match="integrity"):
        authorize_scope(identity,audience="other",required_scope="repo.read",now=150)


def test_invalid_lifetime_source_and_scope_fail_closed() -> None:
    with pytest.raises(ValueError):
        mint_workload_identity(
            subject="agent:x",audience="a",scopes=[],issued_at=100,expires_at=200,source_sha="a"*40
        )
    with pytest.raises(ValueError):
        mint_workload_identity(
            subject="agent:x",audience="a",scopes=["read"],issued_at=200,expires_at=200,source_sha="a"*40
        )
    with pytest.raises(ValueError):
        mint_workload_identity(
            subject="agent:x",audience="a",scopes=["read"],issued_at=100,expires_at=200,source_sha="bad"
        )
