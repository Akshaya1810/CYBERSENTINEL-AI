import asyncio
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.request import urlopen

from app.agents.contracts import InvestigationCaseState, ThreatIntelligenceOutput
from app.agents.investigation import materialize_investigation_case
from app.agents.knowledge import LocalThreatIntelligenceAgent
from app.agents.risk import DeterministicRiskAssessmentAgent
from app.agents.tools import LocalKnowledgeToolOutput, run_risk_assessment_tool
from app.models import DetectionRecord, Incident, IncidentSeverity, IncidentStatus, SecurityEvent
from app.schemas.detections import DetectionHistoryRead
from app.schemas.incidents import IncidentRead, SecurityEventRead
from app.schemas.investigation import RiskAssessment
from app.schemas.verification import VerificationReportRead
from app.security.investigation_pipeline import build_deterministic_risk_assessment


class KnowledgeAndRiskAgentTests(unittest.TestCase):
    def setUp(self):
        self.timestamp = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
        self.incident = Incident(
            id=44,
            title="SSH brute force authentication",
            description="Repeated SSH password failures.",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.OPEN,
            source_ip="203.0.113.44",
            created_at=self.timestamp,
            updated_at=self.timestamp,
        )
        self.event = SecurityEvent(
            id=401,
            incident_id=44,
            event_type="ssh_authentication_failed",
            description="Failed password for analyst.",
            source_ip="203.0.113.44",
            username="analyst",
            timestamp=self.timestamp,
            raw_log="synthetic test event",
        )
        self.incident.security_events = [self.event]
        self.detection = DetectionRecord(
            id=51,
            rule_id="SSH-AUTH-001",
            rule_name="SSH brute-force attempt",
            severity=IncidentSeverity.HIGH,
            description="Repeated failed SSH attempts.",
            source_ip="203.0.113.44",
            incident_id=44,
            detected_at=self.timestamp,
            events=[self.event],
        )
        self.state = InvestigationCaseState(
            incident=IncidentRead.model_validate(self.incident),
            events=[SecurityEventRead.model_validate(self.event)],
            detections=[DetectionHistoryRead(
                id=self.detection.id,
                rule_id=self.detection.rule_id,
                rule_name=self.detection.rule_name,
                severity=self.detection.severity,
                description=self.detection.description,
                source_ip=self.detection.source_ip,
                incident_id=self.detection.incident_id,
                detected_at=self.detection.detected_at,
                event_ids=[self.event.id],
            )],
        )

    def test_local_rag_returns_relevant_context(self):
        output = asyncio.run(LocalThreatIntelligenceAgent().run(self.state))

        self.assertTrue(output.retrieved_context)
        self.assertTrue(any(
            entry.id == "T1110" or "brute force" in entry.title.casefold()
            for entry in output.retrieved_context
        ))

    def test_knowledge_is_stored_separately_from_event_evidence(self):
        output = asyncio.run(LocalThreatIntelligenceAgent().run(self.state))
        self.state.threat_intelligence = output

        self.assertEqual([event.id for event in self.state.events], [self.event.id])
        self.assertIs(self.state.threat_intelligence, output)
        self.assertTrue(output.retrieved_context)
        self.assertTrue(all(not hasattr(entry, "event_ids") for entry in output.retrieved_context))

    def test_attack_and_knowledge_context_cannot_be_event_evidence_ids(self):
        output = asyncio.run(LocalThreatIntelligenceAgent().run(self.state))
        evidence_ids = {event.id for event in self.state.events}

        self.assertTrue(output.attack_mappings)
        self.assertTrue(output.retrieved_context)
        for entry in output.retrieved_context:
            self.assertNotIn("event_ids", entry.model_dump())
            self.assertNotIn("event_id", entry.model_dump())
        for mapping in output.attack_mappings:
            self.assertNotIn("event_ids", mapping.model_dump())
        self.assertEqual(evidence_ids, {self.event.id})

    def test_empty_rag_result_is_safe(self):
        empty_context = LocalKnowledgeToolOutput(query="no match", retrieved_context=[])
        no_mappings = ThreatIntelligenceOutput(knowledge_query="no match")
        with patch(
            "app.agents.knowledge.run_local_rag_tool",
            return_value=empty_context,
        ):
            with patch(
                "app.agents.knowledge.run_attack_lookup_tool",
                return_value=no_mappings,
            ):
                output = asyncio.run(LocalThreatIntelligenceAgent().run(self.state))
        self.assertEqual(output.retrieved_context, [])
        self.assertEqual(output.attack_mappings, [])
        self.assertEqual(output.knowledge_query, "no match")

    def test_local_knowledge_agent_does_not_call_external_network(self):
        with patch("urllib.request.urlopen", wraps=urlopen) as external_request:
            output = asyncio.run(LocalThreatIntelligenceAgent().run(self.state))

        external_request.assert_not_called()
        self.assertIsInstance(output, ThreatIntelligenceOutput)

    def test_risk_agent_reuses_deterministic_assessment(self):
        incident, detections = materialize_investigation_case(self.state)
        expected = build_deterministic_risk_assessment(incident, detections)
        with patch(
            "app.agents.risk.run_risk_assessment_tool",
            wraps=run_risk_assessment_tool,
        ) as existing_tool:
            actual = asyncio.run(DeterministicRiskAssessmentAgent().run(self.state))

        self.assertEqual(existing_tool.call_count, 1)
        self.assertEqual(actual, expected)

    def test_risk_output_is_structured_and_only_uses_stored_inputs(self):
        output = asyncio.run(DeterministicRiskAssessmentAgent().run(self.state))

        self.assertIsInstance(output, RiskAssessment)
        self.assertEqual(output.level, "high")
        self.assertIn("High", output.rationale)
        self.assertIn("SSH brute-force attempt", output.rationale)
        self.assertEqual(output.event_ids, [self.event.id])
        self.assertIn("not confirmation of compromise", output.rationale)
        self.assertNotIn("asset criticality", output.rationale.casefold())

    def test_missing_optional_information_does_not_invent_business_impact(self):
        self.state.events = []
        self.state.detections = []
        output = asyncio.run(DeterministicRiskAssessmentAgent().run(self.state))

        self.assertEqual(output.level, "high")
        self.assertEqual(output.event_ids, [])
        self.assertIn("persisted incident severity", output.rationale)
        self.assertNotIn("financial", output.rationale.casefold())
        self.assertNotIn("business impact", output.rationale.casefold())

    def test_risk_does_not_change_investigation_or_verification(self):
        prior_verification = VerificationReportRead(
            status="contradicted",
            supported_claims=[],
            unsupported_claims=[],
            warnings=[],
            contradictions=["Existing verifier result."],
            missing_evidence=[],
            recommendations=[],
        )
        self.state.verification = prior_verification
        result = asyncio.run(DeterministicRiskAssessmentAgent().run(self.state))

        self.assertEqual(result.level, "high")
        self.assertIs(self.state.verification, prior_verification)
        self.assertIsNone(self.state.investigation)


if __name__ == "__main__":
    unittest.main()
