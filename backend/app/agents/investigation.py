import asyncio
from datetime import datetime
from typing import Literal

from pydantic import ConfigDict

from app.agents.contracts import InvestigationAgentOutput, InvestigationCaseState
from app.models import DetectionRecord, Incident, SecurityEvent
from app.schemas.detections import DetectionHistoryRead
from app.schemas.incidents import IncidentRead, SecurityEventRead
from app.schemas.investigation import (
    InvestigationAnalysis,
    PipelineModuleStatus,
    NarrativeSection,
)
from app.schemas.verification import VerificationReportRead
from app.security.investigation_pipeline import run_investigation, verification_passes
from app.security.ollama import OllamaClient


class InvestigationAgentExecution(InvestigationAgentOutput):
    model_config = ConfigDict(extra="forbid")

    analysis: InvestigationAnalysis
    verification: VerificationReportRead
    modules: list[PipelineModuleStatus]
    generated_at: datetime
    status: Literal["completed", "failed"]
    error_message: str | None = None


def build_investigation_case_state(
    incident: Incident,
    detections: list[DetectionRecord],
) -> InvestigationCaseState:
    """Create the shared, ORM-free state from the incident rows already loaded by the API."""
    incident_read = IncidentRead.model_validate(incident)
    event_reads = [SecurityEventRead.model_validate(event) for event in incident.security_events]
    detection_reads = [
        DetectionHistoryRead(
            id=detection.id,
            rule_id=detection.rule_id,
            rule_name=detection.rule_name,
            severity=detection.severity,
            description=detection.description,
            source_ip=detection.source_ip,
            incident_id=detection.incident_id,
            detected_at=detection.detected_at,
            event_ids=[event.id for event in detection.events],
        )
        for detection in detections
    ]
    return InvestigationCaseState(
        incident=incident_read,
        events=event_reads,
        detections=detection_reads,
    )


def materialize_investigation_case(
    state: InvestigationCaseState,
) -> tuple[Incident, list[DetectionRecord]]:
    incident_read = state.incident
    if any(event.incident_id != incident_read.id for event in state.events):
        raise ValueError("Investigation state contains evidence from a different incident.")
    if any(detection.incident_id != incident_read.id for detection in state.detections):
        raise ValueError("Investigation state contains detections from a different incident.")

    events_by_id: dict[int, SecurityEvent] = {}
    for item in state.events:
        if item.id in events_by_id:
            raise ValueError("Investigation state contains duplicate event IDs.")
        events_by_id[item.id] = SecurityEvent(
            id=item.id,
            incident_id=item.incident_id,
            event_type=item.event_type,
            description=item.description,
            source_ip=item.source_ip,
            timestamp=item.timestamp,
            raw_log=item.raw_log,
            username=item.username,
            hostname=item.hostname,
        )

    incident = Incident(
        id=incident_read.id,
        title=incident_read.title,
        description=incident_read.description,
        severity=incident_read.severity,
        status=incident_read.status,
        source_ip=incident_read.source_ip,
        created_at=incident_read.created_at,
        updated_at=incident_read.updated_at,
    )
    incident.security_events = list(events_by_id.values())
    detections = []
    for item in state.detections:
        detection = DetectionRecord(
            id=item.id,
            rule_id=item.rule_id,
            rule_name=item.rule_name,
            severity=item.severity,
            description=item.description,
            source_ip=item.source_ip,
            incident_id=item.incident_id,
            detected_at=item.detected_at,
        )
        detection.events = [events_by_id[event_id] for event_id in item.event_ids if event_id in events_by_id]
        detections.append(detection)
    return incident, detections


class LocalInvestigationAgent:
    agent_name: Literal["investigation"] = "investigation"

    def __init__(self, client: OllamaClient):
        self._client = client

    async def run(self, state: InvestigationCaseState) -> InvestigationAgentExecution:
        incident, detections = materialize_investigation_case(state)
        # Knowledge context is intentionally excluded; the existing pipeline only builds
        # model context from incident rows and deterministic detections.
        analysis, verification, modules, generated_at = await asyncio.to_thread(
            run_investigation, incident, detections, self._client,
        )
        summary = NarrativeSection(
            summary=(analysis.summary or analysis.triage.summary)[:300],
            event_ids=analysis.summary_event_ids or analysis.triage.event_ids,
            uncertainty="Model-generated interpretation; independent verification is reported separately.",
        )
        passed = verification_passes(verification)
        return InvestigationAgentExecution(
            summary=summary,
            findings=analysis.findings,
            analysis=analysis,
            verification=verification,
            modules=modules,
            generated_at=generated_at,
            status="completed" if passed else "failed",
            error_message=None if passed else "Investigation output did not pass independent evidence verification.",
        )
