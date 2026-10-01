import json
from pathlib import Path
from pydantic import ValidationError

from app.models.detection_record import DetectionRecord
from app.models.incident import Incident
from app.schemas.reports import (
    AttackMappingRead, IncidentReportRead, ReportDetectionRead, ReportEventRead,
    ReportFindingRead, ReportIncidentRead,
)
from app.schemas.investigation import InvestigationAnalysis, InvestigationRunRead
from app.schemas.verification import InvestigationClaimInput, VerificationReportRead, VerificationRequest
from app.security.verification import verify_investigation

KNOWLEDGE_PATH = Path(__file__).with_name("mitre_attack_ssh.json")


def lookup_attack_mappings(incident: Incident, detections: list[DetectionRecord]) -> list[AttackMappingRead]:
    rule_ids = {item.rule_id for item in detections}
    event_types = {event.event_type for event in incident.security_events}
    knowledge = json.loads(KNOWLEDGE_PATH.read_text(encoding="utf-8"))
    return [AttackMappingRead(**{key: item[key] for key in (
        "technique_id", "name", "description", "source_url", "qualification"
    )}) for item in knowledge if rule_ids.intersection(item["rule_ids"]) and event_types.intersection(item["event_types"])]


def build_incident_report(incident: Incident, detections: list[DetectionRecord], request: VerificationRequest | None = None) -> IncidentReportRead:
    events = sorted(incident.security_events, key=lambda event: (event.timestamp is None, event.timestamp, event.id))
    event_ids = {event.id for event in events}
    report_detections = [ReportDetectionRead(
        rule_id=item.rule_id, rule_name=item.rule_name, severity=item.severity,
        description=item.description,
        event_ids=sorted(event.id for event in item.events if event.id in event_ids),
        detected_at=item.detected_at,
    ) for item in detections]
    mappings = lookup_attack_mappings(incident, detections)

    if request is None:
        claims = [InvestigationClaimInput(
            text=f"Recorded {event.event_type} event #{event.id}.", event_ids=[event.id],
            source_ip=event.source_ip, username=event.username, timestamp=event.timestamp,
            hostname=event.hostname,
            successful_login=(event.event_type == "ssh_authentication_succeeded")
                if event.event_type.startswith("ssh_authentication_") else None,
        ) for event in events]
        request = VerificationRequest(claims=claims)
    verification = verify_investigation(events, request.claims, request.recommendations)
    from app.security.investigation_pipeline import pipeline_modules, verify_analysis

    findings = []
    ai_runs: list[InvestigationRunRead] = []
    ai_verifications = []
    invalid_stored_ai_result = False
    for item in incident.investigation_results:
        if item.agent_name.startswith("Local Ollama ("):
            try:
                analysis = InvestigationAnalysis.model_validate_json(item.findings)
            except (ValueError, ValidationError):
                invalid_stored_ai_result = True
                findings.append(ReportFindingRead(
                    id=item.id, agent_name=item.agent_name, findings="Stored local investigation could not be parsed.",
                    confidence=item.confidence, created_at=item.created_at,
                    verification="unverified: stored output failed schema validation",
                ))
                continue
            run_verification = verify_analysis(events, analysis)
            ai_verifications.append(run_verification)
            model_name = item.agent_name.removeprefix("Local Ollama (").rstrip(")")
            ai_runs.append(InvestigationRunRead(
                status="completed", model=model_name, inference_used=True,
                investigation_result_id=item.id, generated_at=item.created_at,
                analysis=analysis, verification=run_verification, modules=pipeline_modules(),
            ))
            rendered_findings = "\n".join([analysis.triage.summary] + [
                f"[{statement.classification}] {statement.text} (event IDs: {', '.join(map(str, statement.event_ids)) or 'none'})"
                for statement in analysis.findings
            ])
            findings.append(ReportFindingRead(
                id=item.id, agent_name=item.agent_name, findings=rendered_findings,
                confidence=item.confidence, created_at=item.created_at,
                verification=f"independent verifier: {run_verification.status}",
            ))
        else:
            findings.append(ReportFindingRead(
                id=item.id, agent_name=item.agent_name, findings=item.findings,
                confidence=item.confidence, created_at=item.created_at,
                verification="unverified: saved free-text finding has no structured evidence references",
            ))
    limitations = [
        "This report reflects stored records and deterministic checks; it is not an AI-generated investigation.",
        "ATT&CK entries are possible behavior mappings, not confirmation of attack or compromise.",
    ]
    if not events:
        limitations.append("No security-event evidence is available for this incident.")
    if not detections:
        limitations.append("No persisted deterministic detection record is associated with this incident.")
    if not incident.description:
        limitations.append("Incident summary unavailable: no description was recorded.")
    if not ai_runs:
        limitations.append("No successful local Ollama investigation is stored for this incident.")
    if invalid_stored_ai_result:
        limitations.append("At least one stored local investigation failed schema validation and is not treated as verified.")
    # Re-run checks against current database evidence; stored model output never supplies its own verification.
    all_verifications = [verification, *ai_verifications]
    supported_claims = [claim for result in all_verifications for claim in result.supported_claims]
    unsupported_claims = [claim for result in all_verifications for claim in result.unsupported_claims]
    contradictions = [claim for result in all_verifications for claim in result.contradictions]
    report_verification_status = (
        "contradicted" if contradictions else "unverified" if not supported_claims
        else "partially_verified" if unsupported_claims or any(result.status != "verified" for result in ai_verifications)
        else "verified"
    )
    aggregate_verification = VerificationReportRead(
        status=report_verification_status,
        supported_claims=supported_claims,
        unsupported_claims=unsupported_claims,
        warnings=[warning for result in all_verifications for warning in result.warnings],
        contradictions=contradictions,
        missing_evidence=[item for result in all_verifications for item in result.missing_evidence],
        recommendations=[item for result in all_verifications for item in result.recommendations],
    )
    report_recommendations = [
        {"text": recommendation.text, "action_type": recommendation.action_type,
         "approval_status": "pending", "event_ids": ",".join(map(str, recommendation.event_ids))}
        for run in ai_runs for recommendation in run.analysis.response_recommendations
    ]
    report_recommendations.extend(
        {"text": item.text, "action_type": item.action_type, "approval_status": item.approval_status,
         "event_ids": ",".join(map(str, item.event_ids))}
        for item in request.recommendations
    )
    return IncidentReportRead(
        incident=ReportIncidentRead(id=incident.id, title=incident.title, status=incident.status,
            severity=incident.severity, summary=incident.description, created_at=incident.created_at),
        timeline=[ReportEventRead(id=event.id, timestamp=event.timestamp, event_type=event.event_type,
            source_ip=event.source_ip, username=event.username, description=event.description,
            raw_log=event.raw_log) for event in events],
        source_ips=sorted({event.source_ip for event in events if event.source_ip}),
        affected_accounts=sorted({event.username for event in events if event.username}),
        detections=report_detections, attack_mappings=mappings, investigation_findings=findings,
        ai_investigations=ai_runs,
        response_recommendations=report_recommendations,
        verification=aggregate_verification,
        limitations=limitations,
    )


def render_markdown(report: IncidentReportRead) -> str:
    incident = report.incident
    lines = [f"# Incident report: {incident.title}", "", f"- ID: {incident.id}",
        f"- Status: {incident.status.value}", f"- Severity: {incident.severity.value}",
        f"- Created: {incident.created_at.isoformat()}", "", "## Summary",
        incident.summary or "Unknown: no incident summary recorded.", "", "## Timeline"]
    lines.extend([f"- {(event.timestamp.isoformat() if event.timestamp else 'Timestamp unknown')} — #{event.id} {event.event_type}: {event.description}"
                  for event in report.timeline] or ["- No event evidence recorded."])
    lines.extend(["", "## Detection rules"])
    lines.extend([f"- {item.rule_id} {item.rule_name} ({item.severity.value}); event IDs: {', '.join(map(str, item.event_ids)) or 'none'}"
                  for item in report.detections] or ["- No persisted detection record."])
    lines.extend(["", "## Local Ollama investigations"])
    if report.ai_investigations:
        for run in report.ai_investigations:
            analysis = run.analysis
            lines.append(f"- Inference used: {str(run.inference_used).lower()} · model: {run.model} · independent verification: {run.verification.status if run.verification else 'unavailable'}")
            if analysis:
                if analysis.summary:
                    lines.append(f"- Model interpretation: {analysis.summary} (event IDs: {', '.join(map(str, analysis.summary_event_ids)) or 'none'})")
                lines.append(f"- Triage: {analysis.triage.summary} (event IDs: {', '.join(map(str, analysis.triage.event_ids)) or 'none'}). Uncertainty: {analysis.triage.uncertainty}")
                lines.extend([f"- [{finding.classification}] {finding.text} (event IDs: {', '.join(map(str, finding.event_ids)) or 'none'})" for finding in analysis.findings])
                lines.append(f"- Attack reconstruction hypothesis: {analysis.attack_reconstruction.summary}; event IDs: {', '.join(map(str, analysis.attack_reconstruction.event_ids)) or 'none'}")
                lines.append(f"- Risk estimate: {analysis.risk_assessment.level}: {analysis.risk_assessment.rationale} (uncertainty: {analysis.risk_assessment.uncertainty})")
                lines.extend([f"- Advisory recommendation (approval pending): {item.text} (event IDs: {', '.join(map(str, item.event_ids)) or 'none'})" for item in analysis.response_recommendations])
    else:
        lines.append("- No successful local model investigation is stored for this incident.")
    lines.extend(["", "## MITRE ATT&CK (possible mappings)"])
    lines.extend([f"- [{item.technique_id} {item.name}]({item.source_url}): {item.qualification}"
                  for item in report.attack_mappings] or ["- No evidence-qualified mapping."])
    lines.extend(["", "## Verification", f"Status: **{report.verification.status}**"])
    lines.extend([f"- Supported: {item.text}" for item in report.verification.supported_claims] or ["- No supported claims."])
    lines.extend([f"- Unsupported/unverified ({item.status}): {item.text}"
                  for item in report.verification.unsupported_claims])
    lines.extend(["", "## Response recommendations"])
    lines.extend([f"- {item['text']} (approval: {item['approval_status']})" for item in report.response_recommendations]
                  or ["- None recorded; approval status unavailable."])
    lines.extend(["", "## Limitations", *[f"- {item}" for item in report.limitations]])
    return "\n".join(lines) + "\n"
