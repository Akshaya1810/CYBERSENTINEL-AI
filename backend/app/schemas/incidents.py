from datetime import datetime
import json

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator

from app.models.enums import IncidentSeverity, IncidentStatus


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    source_ip: str | None = Field(default=None, max_length=45)


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    severity: IncidentSeverity | None = None

    @model_validator(mode="after")
    def require_update_field(self) -> "IncidentUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one of status or severity must be provided.")
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("Status and severity cannot be null.")
        return self


class SecurityEventCreate(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1)
    source_ip: str | None = Field(default=None, max_length=45)
    timestamp: datetime | None = None
    raw_log: str | None = None
    username: str | None = Field(default=None, max_length=150)
    hostname: str | None = Field(default=None, max_length=255)


class InvestigationResultCreate(BaseModel):
    agent_name: str = Field(min_length=1, max_length=100)
    findings: str = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0, le=1)


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: str | None
    severity: IncidentSeverity
    status: IncidentStatus
    source_ip: str | None
    created_at: datetime
    updated_at: datetime


class SecurityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int | None
    event_type: str
    description: str
    source_ip: str | None
    timestamp: datetime | None
    raw_log: str | None
    username: str | None
    hostname: str | None


class InvestigationResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    agent_name: str
    findings: str
    confidence: float | None
    created_at: datetime

    @field_serializer("findings")
    def serialize_structured_local_investigation(self, value: str) -> str:
        """Keep the existing string API while avoiding a raw JSON blob in legacy UI consumers."""
        try:
            analysis = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return value
        if (not isinstance(analysis, dict) or not isinstance(analysis.get("triage"), dict)
                or not isinstance(analysis.get("findings", []), list)):
            return value
        lines = [f"Triage: {analysis['triage'].get('summary', 'Unavailable')}"]
        if analysis.get("summary"):
            ids = ", ".join(str(event_id) for event_id in analysis.get("summary_event_ids", [])) or "none"
            lines.append(f"Model interpretation: {analysis['summary']} (event IDs: {ids})")
        for finding in analysis.get("findings", []):
            ids = ", ".join(str(event_id) for event_id in finding.get("event_ids", [])) or "none"
            lines.append(f"[{finding.get('classification', 'unverified')}] {finding.get('text', '')} (event IDs: {ids})")
        risk = analysis.get("risk_assessment", {})
        if risk:
            lines.append(f"Risk assessment ({risk.get('level', 'unknown')}): {risk.get('rationale', '')}")
        return "\n".join(lines)


class IncidentDetail(IncidentRead):
    security_events: list[SecurityEventRead]
    investigation_results: list[InvestigationResultRead]
