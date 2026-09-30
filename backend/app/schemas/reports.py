from datetime import datetime

from pydantic import BaseModel

from app.models.enums import IncidentSeverity, IncidentStatus
from app.schemas.verification import VerificationReportRead
from app.schemas.investigation import InvestigationRunRead


class ReportIncidentRead(BaseModel):
    id: int
    title: str
    status: IncidentStatus
    severity: IncidentSeverity
    summary: str | None
    created_at: datetime


class ReportEventRead(BaseModel):
    id: int
    timestamp: datetime | None
    event_type: str
    source_ip: str | None
    username: str | None
    description: str
    raw_log: str | None


class ReportDetectionRead(BaseModel):
    rule_id: str
    rule_name: str
    severity: IncidentSeverity
    description: str
    event_ids: list[int]
    detected_at: datetime


class AttackMappingRead(BaseModel):
    technique_id: str
    name: str
    description: str
    source_url: str
    qualification: str


class ReportFindingRead(BaseModel):
    id: int
    agent_name: str
    findings: str
    confidence: float | None
    created_at: datetime
    verification: str


class IncidentReportRead(BaseModel):
    incident: ReportIncidentRead
    timeline: list[ReportEventRead]
    source_ips: list[str]
    affected_accounts: list[str]
    detections: list[ReportDetectionRead]
    attack_mappings: list[AttackMappingRead]
    investigation_findings: list[ReportFindingRead]
    ai_investigations: list[InvestigationRunRead]
    response_recommendations: list[dict[str, str]]
    verification: VerificationReportRead
    limitations: list[str]
