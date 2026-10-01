"""Evidence-led, deterministic reconstruction of an incident's recorded sequence."""

from typing import Literal

from app.agents.contracts import (
    AttackReconstructionOutput,
    AttackReconstructionStep,
    AttackReconstructionAgent as AttackReconstructionAgentContract,
    InvestigationCaseState,
)
from app.agents.investigation import materialize_investigation_case
from app.agents.tools import IncidentDetectionsInput, run_attack_lookup_tool
from app.security.parser import SSH_FAILED, SSH_INVALID_USER, SSH_SUCCEEDED


class DeterministicAttackReconstructionAgent(AttackReconstructionAgentContract):
    agent_name: Literal["attack_reconstruction"] = "attack_reconstruction"

    async def run(self, state: InvestigationCaseState) -> AttackReconstructionOutput:
        incident, detections = materialize_investigation_case(state)
        ordered_events = sorted(
            state.events,
            key=lambda event: (event.timestamp is None, event.timestamp, event.id),
        )
        valid_event_ids = {event.id for event in ordered_events}
        steps = []

        for event in ordered_events:
            success = (
                True if event.event_type == SSH_SUCCEEDED
                else False if event.event_type in {SSH_FAILED, SSH_INVALID_USER}
                else None
            )
            steps.append(AttackReconstructionStep(
                order=len(steps) + 1,
                classification="observed",
                description=f"Recorded {event.event_type}: {event.description}"[:500],
                event_ids=[event.id],
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                username=event.username,
                hostname=event.hostname,
                successful_login=success,
                confidence="high",
                uncertainty="The stored event is observed; its presence alone does not establish malicious intent or compromise.",
            ))

        if state.investigation is not None:
            for finding in state.investigation.findings:
                if not finding.event_ids or not set(finding.event_ids).issubset(valid_event_ids):
                    raise ValueError(
                        "Investigation hypothesis references missing or invalid incident event IDs."
                    )
                steps.append(AttackReconstructionStep(
                    order=len(steps) + 1,
                    classification="hypothesized",
                    description=f"Investigation hypothesis: {finding.text}"[:500],
                    event_ids=list(finding.event_ids),
                    confidence="low",
                    uncertainty="This interpretation is a hypothesis and is not an observed attack step.",
                ))

        contextual_references = run_attack_lookup_tool(
            IncidentDetectionsInput(incident=incident, detections=detections)
        ).attack_mappings
        if steps:
            summary = (
                f"Ordered {len(ordered_events)} stored event record(s); "
                f"{sum(step.classification == 'hypothesized' for step in steps)} "
                "investigation hypothesis/hypotheses are kept separate."
            )
        else:
            summary = "No stored incident events are available to reconstruct an attack sequence."

        return AttackReconstructionOutput(
            reconstruction={
                "summary": summary,
                "event_ids": [event.id for event in ordered_events[:10]],
                "uncertainty": "Recorded activity does not establish a complete attack chain.",
            },
            steps=steps,
            contextual_attack_references=contextual_references,
        )
