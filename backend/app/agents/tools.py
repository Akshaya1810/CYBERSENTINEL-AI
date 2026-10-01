"""Typed adapters from future agent calls to existing security services."""

from dataclasses import dataclass
from typing import Sequence

from pydantic import BaseModel, ConfigDict, Field

from app.agents.contracts import (
    AlertTriageOutput,
    KnowledgeContextEntry,
    ThreatIntelligenceOutput,
)
from app.models.detection_record import DetectionRecord
from app.models.enums import IncidentSeverity
from app.models.incident import Incident
from app.models.security_event import SecurityEvent
from app.schemas.investigation import RiskAssessment
from app.schemas.reports import IncidentReportRead
from app.schemas.verification import (
    InvestigationClaimInput,
    ResponseRecommendationInput,
    VerificationReportRead,
    VerificationRequest,
)
from app.security.investigation_pipeline import (
    build_deterministic_risk_assessment,
    build_deterministic_triage,
    build_evidence_context,
)
from app.security.rag import retrieve_security_context
from app.security.reporting import build_incident_report, lookup_attack_mappings
from app.security.verification import verify_investigation


@dataclass(frozen=True)
class IncidentDetectionsInput:
    incident: Incident
    detections: Sequence[DetectionRecord]


class CorrelatedDetection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_name: str
    severity: IncidentSeverity
    description: str
    event_ids: list[int]


class EventCorrelationToolOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: int
    correlations: list[CorrelatedDetection] = Field(default_factory=list)


KnowledgeEntryOutput = KnowledgeContextEntry


class LocalKnowledgeToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=500)
    top_k: int = Field(default=3, ge=1, le=10)


class LocalKnowledgeToolOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str
    retrieved_context: list[KnowledgeEntryOutput] = Field(default_factory=list)


@dataclass(frozen=True)
class EvidenceVerificationInput:
    evidence: Sequence[SecurityEvent]
    claims: Sequence[InvestigationClaimInput]
    recommendations: Sequence[ResponseRecommendationInput] = ()


@dataclass(frozen=True)
class IncidentReportInput:
    incident: Incident
    detections: Sequence[DetectionRecord]
    verification_request: VerificationRequest | None = None


def run_alert_triage_tool(inputs: IncidentDetectionsInput) -> AlertTriageOutput:
    """Return the existing deterministic event summary and stored incident severity."""
    return AlertTriageOutput(
        summary=build_deterministic_triage(inputs.incident, list(inputs.detections)),
        severity=inputs.incident.severity,
    )


def run_event_correlation_tool(inputs: IncidentDetectionsInput) -> EventCorrelationToolOutput:
    """Expose persisted detection-to-event links from the existing evidence context."""
    context = build_evidence_context(inputs.incident, list(inputs.detections))
    return EventCorrelationToolOutput(
        incident_id=inputs.incident.id,
        correlations=[
            CorrelatedDetection(
                rule_id=item["rule_id"],
                rule_name=item["name"],
                severity=IncidentSeverity(item["severity"]),
                description=item["description"],
                event_ids=item["event_ids"],
            )
            for item in context["deterministic_detections"]
        ],
    )


def run_attack_lookup_tool(inputs: IncidentDetectionsInput) -> ThreatIntelligenceOutput:
    """Return evidence-qualified mappings from the bundled local ATT&CK SSH catalog."""
    return ThreatIntelligenceOutput(
        attack_mappings=lookup_attack_mappings(inputs.incident, list(inputs.detections))
    )


def run_local_rag_tool(inputs: LocalKnowledgeToolInput) -> LocalKnowledgeToolOutput:
    """Return reference knowledge as a distinct type, never as incident evidence."""
    return LocalKnowledgeToolOutput(
        query=inputs.query,
        retrieved_context=[
            KnowledgeEntryOutput.model_validate(item)
            for item in retrieve_security_context(inputs.query, inputs.top_k)
        ],
    )


def run_risk_assessment_tool(inputs: IncidentDetectionsInput) -> RiskAssessment:
    """Return the existing deterministic risk estimate based on persisted severity."""
    return build_deterministic_risk_assessment(inputs.incident, list(inputs.detections))


def run_evidence_verification_tool(inputs: EvidenceVerificationInput) -> VerificationReportRead:
    """Delegate to the independent verifier using incident event rows only."""
    return verify_investigation(inputs.evidence, inputs.claims, inputs.recommendations)


def run_incident_report_tool(inputs: IncidentReportInput) -> IncidentReportRead:
    """Build the existing report; its verification is recalculated against event evidence."""
    return build_incident_report(
        inputs.incident,
        list(inputs.detections),
        inputs.verification_request,
    )
