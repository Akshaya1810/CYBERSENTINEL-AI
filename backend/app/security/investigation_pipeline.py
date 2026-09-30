from collections import Counter
from datetime import datetime, timezone

from app.models.detection_record import DetectionRecord
from app.models.incident import Incident
from app.models.security_event import SecurityEvent
from app.schemas.investigation import (
    CompactInterpretation, EvidenceStatement, ImpactAssessment,
    InvestigationAnalysis, LLMInvestigationOutput, NarrativeSection,
    PipelineModuleStatus, RecommendationDraft, RiskAssessment,
)
from app.schemas.verification import InvestigationClaimInput, ResponseRecommendationInput, VerificationReportRead
from app.security.ollama import OllamaClient
from app.security.verification import verify_investigation

MAX_CONTEXT_EVENTS = 200


def build_evidence_context(incident: Incident, detections: list[DetectionRecord]) -> dict:
    """Build a bounded, database-derived input; all log text remains explicitly untrusted."""
    events = sorted(incident.security_events, key=lambda item: (item.timestamp is None, item.timestamp, item.id))
    return {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "source_ip": incident.source_ip,
        },
        "evidence_facts": [{
            "event_id": event.id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "username": event.username,
            "hostname": event.hostname,
        } for event in events[-MAX_CONTEXT_EVENTS:]],
        "omitted_event_count": max(0, len(events) - MAX_CONTEXT_EVENTS),
        "deterministic_detections": [{
            "rule_id": item.rule_id,
            "name": item.rule_name,
            "severity": item.severity.value,
            "description": item.description,
            "event_ids": sorted(event.id for event in item.events),
        } for item in detections],
    }


def _unique_ids(values) -> list[int]:
    return list(dict.fromkeys(values))


def _deterministic_event_ids(incident: Incident, detections: list[DetectionRecord]) -> list[int]:
    valid_ids = {event.id for event in incident.security_events}
    detected_ids = [event.id for record in detections for event in record.events if event.id in valid_ids]
    return _unique_ids(detected_ids) or sorted(valid_ids)


def _as_hypothesis(item: CompactInterpretation) -> EvidenceStatement:
    return EvidenceStatement(classification="hypothesis", text=item.text, event_ids=item.event_ids)


def _observed_event_facts(incident: Incident) -> list[EvidenceStatement]:
    """Create a few backend-owned factual anchors directly from event rows."""
    result = []
    seen_types = set()
    events = sorted(incident.security_events, key=lambda item: (item.timestamp is None, item.timestamp, item.id))
    for event in events:
        if event.event_type in seen_types:
            continue
        successful_login = (
            True if event.event_type == "ssh_authentication_succeeded"
            else False if event.event_type == "ssh_authentication_failed"
            else None
        )
        if not any((event.source_ip, event.username, event.hostname, event.timestamp, successful_login is not None)):
            continue
        facts = []
        if event.source_ip:
            facts.append(f"source IP {event.source_ip}")
        if event.username:
            facts.append(f"account {event.username}")
        text = f"Event {event.id} records {event.event_type}"
        if facts:
            text += " for " + " and ".join(facts)
        text += "."
        result.append(EvidenceStatement(
            classification="observed_fact", text=text, event_ids=[event.id],
            source_ip=event.source_ip, username=event.username, hostname=event.hostname,
            timestamp=event.timestamp, successful_login=successful_login,
        ))
        seen_types.add(event.event_type)
        if len(result) == 2:
            break
    return result


def build_analysis(
    incident: Incident,
    detections: list[DetectionRecord],
    llm_output: LLMInvestigationOutput,
) -> InvestigationAnalysis:
    """Join concise model interpretations with deterministic evidence-owned fields."""
    events = sorted(incident.security_events, key=lambda item: (item.timestamp is None, item.timestamp, item.id))
    detection_ids = _deterministic_event_ids(incident, detections)
    triage_ids = detection_ids[:5]
    counts = Counter(event.event_type for event in events)
    count_text = ", ".join(f"{name}: {count}" for name, count in sorted(counts.items()))
    triage_summary = (
        f"Recorded {len(events)} security events" + (f" ({count_text})." if count_text else ".")
        if events else "No security-event evidence is recorded."
    )
    rule_names = ", ".join(dict.fromkeys(item.rule_name for item in detections))
    risk_basis = f" from deterministic rule(s): {rule_names}" if rule_names else " from the persisted incident severity"
    risk = RiskAssessment(
        level=incident.severity.value.lower(),
        rationale=f"Risk level follows {incident.severity.value}{risk_basis}; this is not confirmation of compromise."[:240],
        event_ids=detection_ids[:5],
        uncertainty="Rule-based severity estimate; compromise is not established.",
    )

    attack_texts = [item.text for item in llm_output.attack_reconstruction]
    attack_ids = _unique_ids(event_id for item in llm_output.attack_reconstruction for event_id in item.event_ids)
    attack_summary = " ".join(attack_texts)[:500] or "No additional attack reconstruction interpretation was returned."
    if not attack_ids:
        attack_ids = triage_ids

    recommendations = []
    events_by_id = {event.id: event for event in events}
    for item in llm_output.response_recommendations:
        cited_events = [events_by_id[event_id] for event_id in item.event_ids if event_id in events_by_id]
        source_ip = next((event.source_ip for event in cited_events if event.source_ip), None) if item.action_type in {"block_source_ip", "rate_limit_source_ip"} else None
        username = next((event.username for event in cited_events if event.username), None) if item.action_type in {"disable_account", "reset_password"} else None
        recommendations.append(RecommendationDraft(
            text=item.text, action_type=item.action_type, event_ids=item.event_ids,
            source_ip=source_ip, username=username,
        ))

    return InvestigationAnalysis(
        summary=llm_output.summary.text,
        summary_event_ids=llm_output.summary.event_ids,
        triage=NarrativeSection(
            summary=triage_summary[:500], event_ids=triage_ids,
            uncertainty="Deterministic event counts; intent and compromise are not established.",
        ),
        findings=[_as_hypothesis(item) for item in llm_output.findings],
        attack_reconstruction=NarrativeSection(
            summary=attack_summary, event_ids=attack_ids[:10],
            uncertainty="Model interpretation only; not confirmation of an attack or compromise.",
        ),
        impact_assessment=ImpactAssessment(
            observed=_observed_event_facts(incident),
            potential=[_as_hypothesis(item) for item in llm_output.impact_assessment],
        ),
        risk_assessment=risk,
        response_recommendations=recommendations,
    )


def _statement_claim(statement: EvidenceStatement) -> InvestigationClaimInput:
    return InvestigationClaimInput(
        text=statement.text,
        claim_type="fact" if statement.classification == "observed_fact" else "hypothesis",
        event_ids=statement.event_ids,
        source_ip=statement.source_ip,
        username=statement.username,
        hostname=statement.hostname,
        timestamp=statement.timestamp,
        successful_login=statement.successful_login,
    )


def verify_analysis(evidence: list[SecurityEvent], analysis: InvestigationAnalysis) -> VerificationReportRead:
    claims = []
    if analysis.summary:
        claims.append(InvestigationClaimInput(
            text=f"Investigation summary: {analysis.summary}", claim_type="hypothesis",
            event_ids=analysis.summary_event_ids,
        ))
    claims.append(InvestigationClaimInput(
        text=f"Deterministic triage: {analysis.triage.summary}", claim_type="hypothesis", event_ids=analysis.triage.event_ids,
    ))
    claims.extend(_statement_claim(statement) for statement in analysis.findings)
    claims.append(InvestigationClaimInput(
        text=f"Attack reconstruction: {analysis.attack_reconstruction.summary}",
        claim_type="hypothesis", event_ids=analysis.attack_reconstruction.event_ids,
    ))
    claims.extend(_statement_claim(statement) for statement in analysis.impact_assessment.observed)
    claims.extend(_statement_claim(statement) for statement in analysis.impact_assessment.potential)
    claims.append(InvestigationClaimInput(
        text=f"Risk assessment: {analysis.risk_assessment.level}. {analysis.risk_assessment.rationale}",
        claim_type="hypothesis", event_ids=analysis.risk_assessment.event_ids,
    ))
    recommendations = [ResponseRecommendationInput(
        text=item.text,
        action_type=item.action_type,
        event_ids=item.event_ids,
        source_ip=item.source_ip,
        username=item.username,
        approval_status="pending",  # Server-owned; the model cannot approve its own actions.
    ) for item in analysis.response_recommendations]
    return verify_investigation(evidence, claims, recommendations)


def verification_passes(report: VerificationReportRead) -> bool:
    """Accept qualified hypotheses, but block unsupported facts, bad IDs, contradictions, or unsafe recommendations."""
    claims = report.supported_claims + report.unsupported_claims
    return (
        bool(report.supported_claims)
        and not report.contradictions
        and not report.missing_evidence
        and all(claim.status == "unverified" and claim.claim_type == "hypothesis"
                for claim in report.unsupported_claims)
        and all(item.consistency == "consistent" for item in report.recommendations)
        and all(claim.status in {"supported", "unverified"} for claim in claims)
    )


def pipeline_modules(ollama_status: str = "completed", verification_status: str = "completed"):
    return [
        PipelineModuleStatus(module="triage", responsibility="Event counts and deterministic rule correlation", method="deterministic", status="completed"),
        PipelineModuleStatus(module="event_correlation", responsibility="Database events and deterministic detection record correlation", method="deterministic", status="completed"),
        PipelineModuleStatus(module="investigation", responsibility="Structured findings with event references", method="ollama", status=ollama_status),
        PipelineModuleStatus(module="attack_reconstruction", responsibility="Cautious evidence-linked behavioral hypothesis", method="ollama", status=ollama_status),
        PipelineModuleStatus(module="threat_intelligence", responsibility="Local ATT&CK catalog only; no IP reputation or live intelligence", method="deterministic", status="completed"),
        PipelineModuleStatus(module="risk_assessment", responsibility="Persisted deterministic incident severity", method="deterministic", status="completed"),
        PipelineModuleStatus(module="response_planning", responsibility="Advisory recommendations requiring human approval", method="ollama", status=ollama_status),
        PipelineModuleStatus(module="independent_verification", responsibility="Validate event IDs and structured claims against database evidence", method="independent_deterministic", status=verification_status),
    ]


def run_investigation(incident: Incident, detections: list[DetectionRecord], client: OllamaClient):
    context = build_evidence_context(incident, detections)
    raw_analysis = client.generate(context)
    llm_output = LLMInvestigationOutput.model_validate(raw_analysis)
    analysis = build_analysis(incident, detections, llm_output)
    verification = verify_analysis(incident.security_events, analysis)
    return analysis, verification, pipeline_modules(), datetime.now(timezone.utc)
