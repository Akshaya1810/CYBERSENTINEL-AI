from collections.abc import Sequence
from datetime import datetime, timezone
import re

from app.models.security_event import SecurityEvent
from app.schemas.verification import (
    ClaimCheckRead, InvestigationClaimInput, RecommendationCheckRead,
    ResponseRecommendationInput, VerificationReportRead,
)
from app.security.parser import SSH_SUCCEEDED

IPV4_TEXT_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def verify_investigation(
    evidence: Sequence[SecurityEvent],
    claims: Sequence[InvestigationClaimInput],
    recommendations: Sequence[ResponseRecommendationInput] = (),
) -> VerificationReportRead:
    """Deterministically validate structured claims against actual incident event rows."""
    by_id = {event.id: event for event in evidence}
    supported, unsupported, warnings, contradictions, missing = [], [], [], [], []
    for claim in claims:
        selected = [by_id[event_id] for event_id in claim.event_ids if event_id in by_id]
        invalid_ids = sorted(set(claim.event_ids) - by_id.keys())
        reasons: list[str] = []
        if invalid_ids:
            reasons.append(f"Event IDs not present in this incident: {', '.join(map(str, invalid_ids))}.")
            missing.append(f"{claim.text}: referenced incident evidence is missing.")
        if not claim.event_ids:
            reasons.append("No incident evidence IDs were supplied.")
            missing.append(f"{claim.text}: no supporting evidence IDs supplied.")
        checks = passed = structured_checks = 0
        for field, expected in (("source_ip", claim.source_ip), ("username", claim.username), ("hostname", claim.hostname)):
            if expected is not None:
                checks += 1
                structured_checks += 1
                if any(getattr(event, field) == expected for event in selected):
                    passed += 1
                    reasons.append(f"Claimed {field} is present on referenced evidence.")
                else:
                    reasons.append(f"Claimed {field} is not present on referenced evidence.")
        textual_ips = set(IPV4_TEXT_PATTERN.findall(claim.text))
        selected_ips = {event.source_ip for event in selected if event.source_ip}
        if textual_ips - selected_ips:
            checks += 1
            reasons.append(f"Text includes IP addresses not present on its referenced evidence: {', '.join(sorted(textual_ips - selected_ips))}.")
        elif textual_ips:
            checks += 1
            passed += 1
            reasons.append("IP addresses stated in the text match referenced event evidence.")
        if claim.timestamp is not None:
            checks += 1
            structured_checks += 1
            if any(_utc(event.timestamp) == _utc(claim.timestamp) for event in selected):
                passed += 1
                reasons.append("Timestamp matches a referenced event.")
            else:
                reasons.append("Claimed timestamp does not match a referenced event.")
        contradicted = False
        if claim.successful_login is not None:
            checks += 1
            structured_checks += 1
            has_success = any(event.event_type == SSH_SUCCEEDED for event in selected)
            if has_success == claim.successful_login:
                passed += 1
                reasons.append("Successful-login assertion matches referenced event types.")
            else:
                contradicted = not claim.successful_login and has_success
                reasons.append("Successful-login assertion conflicts with referenced event types." if contradicted else "No referenced successful-login event supports this assertion.")
        if contradicted:
            state = "contradicted"
            contradictions.append(claim.text)
        elif invalid_ids or (checks > 0 and passed < checks):
            state = "unsupported"
        elif claim.claim_type == "hypothesis":
            reasons.append("Hypotheses are not promoted to facts by evidence-reference checks.")
            state = "unverified"
        elif structured_checks == 0:
            reasons.append("Free-text meaning cannot be verified by this deterministic module.")
            state = "unverified"
        elif selected and passed == checks:
            state = "supported"
        else:
            state = "unsupported"
        result = ClaimCheckRead(text=claim.text, claim_type=claim.claim_type, status=state,
                                event_ids=claim.event_ids, reasons=reasons)
        if state == "supported":
            supported.append(result)
        else:
            unsupported.append(result)
            warnings.append(f"Claim marked {state}: {claim.text}")

    checked_recommendations = []
    for item in recommendations:
        selected = [by_id[event_id] for event_id in item.event_ids if event_id in by_id]
        invalid_ids = sorted(set(item.event_ids) - by_id.keys())
        reasons: list[str] = []
        consistent = not invalid_ids and bool(item.event_ids)
        if invalid_ids:
            reasons.append(f"Evidence IDs are not part of this incident: {', '.join(map(str, invalid_ids))}.")
            missing.append(f"Recommendation lacks valid incident evidence: {item.text}")
        for field, expected in (("source_ip", item.source_ip), ("username", item.username)):
            if expected is not None:
                if any(getattr(event, field) == expected for event in selected):
                    reasons.append(f"Referenced {field} is present in incident evidence.")
                else:
                    consistent = False
                    reasons.append(f"Referenced {field} is not supported by selected event IDs.")
        textual_ips = set(IPV4_TEXT_PATTERN.findall(item.text))
        selected_ips = {event.source_ip for event in selected if event.source_ip}
        if textual_ips - selected_ips:
            consistent = False
            reasons.append(f"Text includes IP addresses not present on its referenced evidence: {', '.join(sorted(textual_ips - selected_ips))}.")
        target_field = {
            "block_source_ip": "source_ip",
            "rate_limit_source_ip": "source_ip",
            "disable_account": "username",
            "reset_password": "username",
        }.get(item.action_type)
        if item.action_type == "review_logs":
            reasons.append("Review action is linked to existing incident event IDs.")
        elif target_field is None:
            consistent = False
            reasons.append("Action type is unspecified; consistency cannot be established from text alone.")
        elif not getattr(item, target_field):
            consistent = False
            reasons.append(f"{item.action_type} requires a structured {target_field} target.")
        elif not any(getattr(event, target_field) == getattr(item, target_field) for event in selected):
            consistent = False
            reasons.append(f"Action target {target_field} is not present in the referenced evidence.")
        else:
            reasons.append(f"Action target {target_field} is supported by referenced evidence; approval remains {item.approval_status}.")
        if not item.event_ids:
            consistent = False
            reasons.append("No event IDs supplied; recommendation consistency is unverified.")
            warnings.append(f"Recommendation consistency is unverified: {item.text}")
        state = "consistent" if consistent else ("unverified" if not item.event_ids and not invalid_ids or item.action_type == "other" else "unsupported")
        checked_recommendations.append(RecommendationCheckRead(
            text=item.text, action_type=item.action_type, consistency=state, approval_status=item.approval_status,
            event_ids=item.event_ids, reasons=reasons,
        ))

    recommendation_issues = any(item.consistency != "consistent" for item in checked_recommendations)
    status = "contradicted" if contradictions else "unverified" if not supported else "partially_verified" if unsupported or recommendation_issues else "verified"
    return VerificationReportRead(
        status=status, supported_claims=supported, unsupported_claims=unsupported,
        warnings=warnings, contradictions=contradictions, missing_evidence=missing,
        recommendations=checked_recommendations,
    )
