"""Agent output contracts, exactly as spec section 6. A Finding with no evidence id is invalid."""

from typing import Literal

from pydantic import BaseModel, Field

Status = Literal["benign", "suspected", "attempted", "confirmed"]
Severity = Literal["none", "low", "medium", "high", "critical"]
Source = Literal["access_log", "auth_log", "process"]


class Finding(BaseModel):
    claim: str
    evidence_ids: list[str] = Field(min_length=1)


class DetectionOutput(BaseModel):
    attack_type: Literal["rce", "brute_force", "unknown"]
    hypothesis: str
    indicators: list[Finding]
    suggested_sources: list[Source]


class EvidenceRequest(BaseModel):
    source: Source
    reason: str


class InvestigationOutput(BaseModel):
    hypothesis_holds: bool
    findings: list[Finding]
    counter_evidence: list[Finding]
    scanner_likely: bool
    ruled_benign: bool
    evidence_requests: list[EvidenceRequest]  # empty = done
    proposed_status: Status


class ForensicsOutput(BaseModel):
    impact_found: bool
    impact_type: Literal["code_execution", "outbound_connection", "account_login", "none"]
    findings: list[Finding]
    checked_sources: list[Source]
    missing_sources: list[Source]  # sources that were unavailable


class Recommendation(BaseModel):
    action: Literal["block_ip", "reset_password", "isolate_host", "patch_endpoint", "monitor"]
    target: str
    reason: str


class DecisionOutput(BaseModel):
    proposed_status: Status
    proposed_severity: Severity
    summary: str  # max 2 sentences
    report_md: str
    recommendations: list[Recommendation]
