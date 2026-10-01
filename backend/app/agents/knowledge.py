"""Agent adapter for the bundled local cybersecurity reference catalog."""

from typing import Literal

from app.agents.contracts import InvestigationCaseState, ThreatIntelligenceOutput
from app.agents.investigation import materialize_investigation_case
from app.agents.tools import (
    IncidentDetectionsInput,
    LocalKnowledgeToolInput,
    run_attack_lookup_tool,
    run_local_rag_tool,
)


class LocalThreatIntelligenceAgent:
    agent_name: Literal["threat_intelligence"] = "threat_intelligence"

    async def run(self, state: InvestigationCaseState) -> ThreatIntelligenceOutput:
        incident, detections = materialize_investigation_case(state)
        query_terms = [
            incident.title,
            incident.description or "",
            *(event.event_type for event in incident.security_events),
            *(detection.rule_id for detection in detections),
            *(detection.rule_name for detection in detections),
        ]
        query = " ".join(term.strip() for term in query_terms if term and term.strip())[:500]
        knowledge = run_local_rag_tool(LocalKnowledgeToolInput(query=query or "cybersecurity"))
        mappings = run_attack_lookup_tool(
            IncidentDetectionsInput(incident=incident, detections=detections)
        )
        return ThreatIntelligenceOutput(
            attack_mappings=mappings.attack_mappings,
            knowledge_query=knowledge.query,
            retrieved_context=knowledge.retrieved_context,
        )
