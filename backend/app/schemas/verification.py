from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class InvestigationClaimInput(BaseModel):
    """Structured assertion boundary suitable for future local LLM output."""
    text: str = Field(min_length=1, max_length=2000)
    claim_type: Literal["fact", "hypothesis"] = "fact"
    event_ids: list[int] = Field(default_factory=list, max_length=500)
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    timestamp: datetime | None = None
    successful_login: bool | None = None


class ResponseRecommendationInput(BaseModel):
    text: str = Field(min_length=1, max_length=2000)
    action_type: Literal["review_logs", "block_source_ip", "rate_limit_source_ip", "disable_account", "reset_password", "other"] = "other"
    event_ids: list[int] = Field(default_factory=list, max_length=500)
    source_ip: str | None = None
    username: str | None = None
    approval_status: Literal["pending", "approved", "rejected", "not_required"] = "pending"


class VerificationRequest(BaseModel):
    claims: list[InvestigationClaimInput] = Field(default_factory=list, max_length=500)
    recommendations: list[ResponseRecommendationInput] = Field(default_factory=list, max_length=100)


class ClaimCheckRead(BaseModel):
    text: str
    claim_type: Literal["fact", "hypothesis"]
    status: Literal["supported", "unsupported", "unverified", "contradicted"]
    event_ids: list[int]
    reasons: list[str]


class RecommendationCheckRead(BaseModel):
    text: str
    action_type: Literal["review_logs", "block_source_ip", "rate_limit_source_ip", "disable_account", "reset_password", "other"]
    consistency: Literal["consistent", "unsupported", "unverified"]
    approval_status: Literal["pending", "approved", "rejected", "not_required"]
    event_ids: list[int]
    reasons: list[str]


class VerificationReportRead(BaseModel):
    status: Literal["verified", "partially_verified", "unverified", "contradicted"]
    supported_claims: list[ClaimCheckRead]
    unsupported_claims: list[ClaimCheckRead]
    warnings: list[str]
    contradictions: list[str]
    missing_evidence: list[str]
    recommendations: list[RecommendationCheckRead]
