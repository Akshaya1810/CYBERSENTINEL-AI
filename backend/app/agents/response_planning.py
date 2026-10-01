"""Deterministic advisory response planning; this module never executes actions."""

from typing import Literal

from app.agents.contracts import (
    InvestigationCaseState,
    ResponsePlanRecommendation,
    ResponsePlanningOutput,
)


class DeterministicResponsePlanningAgent:
    agent_name: Literal["response_planning"] = "response_planning"

    async def run(self, state: InvestigationCaseState) -> ResponsePlanningOutput:
        valid_events = {event.id: event for event in state.events}
        recommendations = []
        limitations = []

        if not valid_events:
            limitations.append(
                "No stored incident events are available to support a response recommendation."
            )
            return ResponsePlanningOutput(
                recommendations=[],
                actions_executed=False,
                limitations=limitations,
            )

        risk = state.risk_assessment
        priority = risk.level if risk and risk.level in {"low", "medium", "high", "critical"} else "medium"
        event_ids = sorted(valid_events)[:5]
        recommendations.append(ResponsePlanRecommendation(
            text="Review the referenced incident events and authentication timeline.",
            action_type="review_logs",
            event_ids=event_ids,
            priority=priority,
            requires_human_approval=False,
            approval_status="pending",
            uncertainty=(
                "This is a review recommendation only; stored events do not establish intent or compromise."
            ),
            actions_executed=False,
        ))

        if priority in {"high", "critical"}:
            target_ip = state.incident.source_ip
            matching_ids = [
                event.id for event in state.events
                if target_ip and event.source_ip == target_ip
            ][:5]
            if target_ip and matching_ids:
                recommendations.append(ResponsePlanRecommendation(
                    text=f"Consider whether limiting traffic from recorded source IP {target_ip} is appropriate after analyst review.",
                    action_type="rate_limit_source_ip",
                    event_ids=matching_ids,
                    source_ip=target_ip,
                    priority=priority,
                    requires_human_approval=True,
                    approval_status="pending",
                    uncertainty=(
                        "The source address appears in stored events, but malicious intent is not established; "
                        "no network change has been made."
                    ),
                    actions_executed=False,
                ))
            else:
                limitations.append(
                    "High persisted severity has no matching recorded source IP; no source-limiting recommendation was generated."
                )

        if state.investigation is None:
            limitations.append(
                "No investigation output is available; recommendations rely only on persisted events and severity."
            )
        if state.attack_reconstruction is None:
            limitations.append(
                "No attack reconstruction is available; no attack sequence is assumed."
            )
        if state.threat_intelligence is not None:
            limitations.append(
                "Local knowledge and ATT&CK references are contextual only and were not used as incident evidence."
            )

        return ResponsePlanningOutput(
            recommendations=recommendations,
            actions_executed=False,
            limitations=limitations,
        )
