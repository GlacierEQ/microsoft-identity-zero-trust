"""Hash-bound local workload identity envelope.

The envelope models least-privilege workload identity properties: exact
audience, exact scopes, explicit lifetime, and source identity. It performs no
Microsoft Entra operation and is not a credential.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping

IDENTITY_SCHEMA = "glaciereq.microsoft-workload-identity.v1"
IDENTITY_EVIDENCE_STATE = "LOCAL_WORKLOAD_IDENTITY_MODEL_NOT_MICROSOFT_ENTRA_CREDENTIAL"
_SOURCE_RE = re.compile(r"^[0-9a-f]{40,64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _digest(value: object) -> str:
    payload=json.dumps(value,sort_keys=True,separators=(",",":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def mint_workload_identity(
    *,
    subject: str,
    audience: str,
    scopes: Iterable[str],
    issued_at: int,
    expires_at: int,
    source_sha: str,
) -> dict[str, object]:
    """Create a deterministic non-credential identity envelope."""

    for name,value in (("subject",subject),("audience",audience)):
        if not isinstance(value,str) or not value.strip():
            raise ValueError(f"{name} must be non-empty text")
    if isinstance(issued_at,bool) or not isinstance(issued_at,int):
        raise ValueError("issued_at must be an integer")
    if isinstance(expires_at,bool) or not isinstance(expires_at,int) or expires_at <= issued_at:
        raise ValueError("expires_at must be an integer greater than issued_at")
    if not _SOURCE_RE.fullmatch(source_sha):
        raise ValueError("source_sha must be lowercase hexadecimal with length 40-64")
    normalized=tuple(sorted(set(scopes)))
    if not normalized or any(not isinstance(scope,str) or not scope.strip() for scope in normalized):
        raise ValueError("scopes must contain non-empty text values")
    normalized=tuple(scope.strip() for scope in normalized)

    body:dict[str,object]={
        "schema":IDENTITY_SCHEMA,
        "subject":subject.strip(),
        "audience":audience.strip(),
        "scopes":list(normalized),
        "issued_at":issued_at,
        "expires_at":expires_at,
        "source_sha":source_sha,
        "evidence_state":IDENTITY_EVIDENCE_STATE,
        "credential":False,
        "entra_api_call":False,
        "operational_authority":False,
    }
    body["receipt_sha256"]=_digest(body)
    return body


def verify_identity(identity: Mapping[str,object]) -> bool:
    observed=identity.get("receipt_sha256")
    if not isinstance(observed,str) or not _SHA256_RE.fullmatch(observed):
        return False
    body={key:value for key,value in identity.items() if key!="receipt_sha256"}
    return _digest(body)==observed


def authorize_scope(
    identity: Mapping[str,object],
    *,
    audience: str,
    required_scope: str,
    now: int,
) -> dict[str,object]:
    """Evaluate exact audience/scope/time binding without granting real access."""

    if not verify_identity(identity):
        raise ValueError("identity integrity verification failed")
    if isinstance(now,bool) or not isinstance(now,int):
        raise ValueError("now must be an integer")
    if not isinstance(audience,str) or not audience.strip():
        raise ValueError("audience must be non-empty text")
    if not isinstance(required_scope,str) or not required_scope.strip():
        raise ValueError("required_scope must be non-empty text")

    reasons:list[str]=[]
    if identity.get("audience") != audience.strip():
        reasons.append("AUDIENCE_MISMATCH")
    scopes=identity.get("scopes")
    if not isinstance(scopes,list) or required_scope.strip() not in scopes:
        reasons.append("SCOPE_MISSING")
    issued_at=identity.get("issued_at")
    expires_at=identity.get("expires_at")
    if not isinstance(issued_at,int) or not isinstance(expires_at,int) or not issued_at <= now < expires_at:
        reasons.append("OUTSIDE_VALIDITY_WINDOW")

    allowed=not reasons
    body={
        "schema":"glaciereq.microsoft-workload-identity.authorization.v1",
        "identity_receipt_sha256":identity["receipt_sha256"],
        "audience":audience.strip(),
        "required_scope":required_scope.strip(),
        "now":now,
        "allowed":allowed,
        "reasons":reasons,
        "operational_authority":False,
        "entra_api_call":False,
    }
    body["receipt_sha256"]=_digest(body)
    return body
