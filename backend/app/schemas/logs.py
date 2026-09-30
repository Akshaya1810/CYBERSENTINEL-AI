from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import IncidentSeverity


class DetectionRuleRead(BaseModel):
    rule_id: str
    name: str
    severity: IncidentSeverity
    threshold: int
    window_seconds: int
    description: str


class DetectionResultRead(BaseModel):
    id: int | None = None
    rule_id: str
    rule_name: str
    severity: IncidentSeverity
    source_ip: str
    description: str
    incident_id: int
    detected_at: datetime | None = None
    event_ids: list[int]
    triggering_event_ids: list[int] = Field(default_factory=list)


class DetectionHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    rule_name: str
    severity: IncidentSeverity
    description: str
    source_ip: str
    incident_id: int
    detected_at: datetime
    event_ids: list[int]


class MalformedRecordRead(BaseModel):
    record_number: int
    reason: str


class LogUploadRead(BaseModel):
    filename: str
    file_format: str
    processed_records: int
    rejected_records: int
    malformed_records: list[MalformedRecordRead]
    warning_count: int
    warnings: list[str]
    detections: list[DetectionResultRead]
