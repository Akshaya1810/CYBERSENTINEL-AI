from datetime import datetime
from typing import Generic, Literal, Protocol, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import IncidentSeverity
from app.schemas.detections import DetectionHistoryRead
from app.schemas.incidents import IncidentRead, SecurityEventRead
from app.schemas.investigation import (
    EvidenceStatement,
    NarrativeSection,
    RecommendationDraft,
    RiskAssessment,
)
from app.schemas.reports import AttackMappingRead, IncidentReportRead
from app.schemas.verification import VerificationReportRead

AgentName = Literal[
    "alert_triage",
    "event_correlation",
    "investigation",
    "attack_reconstruction",
    "threat_intelligence",
    "risk_assessment",
    "response_planning",
    "verification",
    "incident_report_generation",
]
InvestigationStatus = Literal["pending", "running", "completed", "failed"]
OutputT_co = TypeVar("OutputT_co", covariant=True)


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AlertTriageOutput(ContractModel):
    summary: NarrativeSection
    severity: IncidentSeverity


class CorrelationGroup(ContractModel):
    event_ids: list[int] = Field(min_length=2)
    detection_ids: list[int] = Field(default_factory=list)
    rationale: str = Field(min_length=1, max_length=500)


class EventCorrelationOutput(ContractModel):
    groups: list[CorrelationGroup] = Field(default_factory=list)


class InvestigationAgentOutput(ContractModel):
    summary: NarrativeSection
    findings: list[EvidenceStatement] = Field(default_factory=list, max_length=10)


class AttackReconstructionStep(ContractModel):
    order: int = Field(ge=1)
    classification: Literal["observed", "hypothesized"]
    description: str = Field(min_length=1, max_length=500)
    event_ids: list[int] = Field(default_factory=list, max_length=10)
    timestamp: datetime | None = None
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    successful_login: bool | None = None
    confidence: Literal["high", "low"]
    uncertainty: str = Field(min_length=1, max_length=240)

    @model_validator(mode="after")
    def observed_step_requires_evidence(self):
        if self.classification == "observed" and not self.event_ids:
            raise ValueError("Observed reconstruction steps require supporting event IDs.")
        if self.classification == "hypothesized" and self.confidence != "low":
            raise ValueError("Hypothesized reconstruction steps must have low confidence.")
        return self


class AttackReconstructionOutput(ContractModel):
    reconstruction: NarrativeSection
    steps: list[AttackReconstructionStep] = Field(default_factory=list)
    contextual_attack_references: list[AttackMappingRead] = Field(default_factory=list)
    reference_note: str = (
        "ATT&CK mappings are contextual references, not evidence that an attack occurred."
    )


class KnowledgeContextEntry(ContractModel):
    """Local reference material; intentionally contains no incident evidence IDs."""

    id: str
    title: str
    description: str
    guidance: str
    relevance_score: float


class ThreatIntelligenceOutput(ContractModel):
    attack_mappings: list[AttackMappingRead] = Field(default_factory=list)
    knowledge_query: str = ""
    retrieved_context: list[KnowledgeContextEntry] = Field(default_factory=list)
    context_note: str = (
        "Retrieved knowledge and ATT&CK mappings are context, not incident evidence."
    )


class ResponsePlanRecommendation(RecommendationDraft):
    priority: Literal["low", "medium", "high", "critical"]
    requires_human_approval: bool
    approval_status: Literal["pending", "approved", "rejected"] = "pending"
    uncertainty: str = Field(min_length=1, max_length=240)
    actions_executed: Literal[False] = False

    @model_validator(mode="after")
    def high_impact_requires_approval(self):
        if self.action_type in {
            "block_source_ip", "rate_limit_source_ip", "disable_account", "reset_password",
        } and not self.requires_human_approval:
            raise ValueError("Potentially high-impact recommendations require human approval.")
        return self


class ResponsePlanningOutput(ContractModel):
    recommendations: list[ResponsePlanRecommendation] = Field(default_factory=list, max_length=10)
    actions_executed: Literal[False] = False
    limitations: list[str] = Field(default_factory=list, max_length=10)


class InvestigationCaseState(ContractModel):
    """In-memory handoff state; it is not persisted and contains no ORM objects."""

    run_id: UUID = Field(default_factory=uuid4)
    incident: IncidentRead
    events: list[SecurityEventRead] = Field(default_factory=list)
    detections: list[DetectionHistoryRead] = Field(default_factory=list)
    local_knowledge_context: list[str] = Field(default_factory=list)
    status: InvestigationStatus = "pending"
    current_agent: AgentName | None = None
    completed_agents: list[AgentName] = Field(default_factory=list)
    error_message: str | None = None
    triage: AlertTriageOutput | None = None
    correlation: EventCorrelationOutput | None = None
    investigation: InvestigationAgentOutput | None = None
    attack_reconstruction: AttackReconstructionOutput | None = None
    threat_intelligence: ThreatIntelligenceOutput | None = None
    risk_assessment: RiskAssessment | None = None
    response_plan: ResponsePlanningOutput | None = None
    verification: VerificationReportRead | None = None
    report: IncidentReportRead | None = None


class AgentContract(Protocol, Generic[OutputT_co]):
    agent_name: AgentName

    async def run(self, state: InvestigationCaseState) -> OutputT_co: ...


class AlertTriageAgent(AgentContract[AlertTriageOutput], Protocol):
    agent_name: Literal["alert_triage"]


class EventCorrelationAgent(AgentContract[EventCorrelationOutput], Protocol):
    agent_name: Literal["event_correlation"]


class InvestigationAgent(AgentContract[InvestigationAgentOutput], Protocol):
    agent_name: Literal["investigation"]


class AttackReconstructionAgent(AgentContract[AttackReconstructionOutput], Protocol):
    agent_name: Literal["attack_reconstruction"]


class ThreatIntelligenceAgent(AgentContract[ThreatIntelligenceOutput], Protocol):
    agent_name: Literal["threat_intelligence"]


class RiskAssessmentAgent(AgentContract[RiskAssessment], Protocol):
    agent_name: Literal["risk_assessment"]


class ResponsePlanningAgent(AgentContract[ResponsePlanningOutput], Protocol):
    agent_name: Literal["response_planning"]


class VerificationAgent(AgentContract[VerificationReportRead], Protocol):
    agent_name: Literal["verification"]


class IncidentReportGenerationAgent(AgentContract[IncidentReportRead], Protocol):
    agent_name: Literal["incident_report_generation"]


class CentralOrchestratorContract(Protocol):
    async def run(self, state: InvestigationCaseState) -> InvestigationCaseState: ...
