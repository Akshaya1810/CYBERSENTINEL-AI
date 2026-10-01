import asyncio
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from app.agents.investigation import LocalInvestigationAgent, build_investigation_case_state
from app.models import DetectionRecord, Incident, IncidentSeverity, IncidentStatus, SecurityEvent
from app.schemas.investigation import InvestigationAnalysis
from app.security.ollama import OllamaUnavailable
from app.security.verification import verify_investigation


def model_output(event_id: int) -> dict:
    return {
        "summary": {"text": "Authentication activity needs review.", "event_ids": [event_id]},
        "findings": [{"text": "The pattern may be password guessing.", "event_ids": [event_id]}],
        "attack_reconstruction": [],
        "impact_assessment": [],
        "response_recommendations": [],
    }


class InvestigationAgentTests(unittest.TestCase):
    def setUp(self):
        self.timestamp = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
        self.incident = Incident(
            id=11,
            title="Synthetic SSH investigation",
            description="Synthetic evidence for agent tests.",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.OPEN,
            source_ip="203.0.113.44",
            created_at=self.timestamp,
            updated_at=self.timestamp,
        )
        self.event = SecurityEvent(
            id=101,
            incident_id=11,
            event_type="ssh_authentication_failed",
            description="Failed SSH password",
            source_ip="203.0.113.44",
            username="analyst",
            timestamp=self.timestamp,
            raw_log="synthetic failed password",
        )
        self.incident.security_events = [self.event]
        self.detection = DetectionRecord(
            id=5,
            rule_id="SSH-AUTH-001",
            rule_name="SSH brute-force attempt",
            severity=IncidentSeverity.HIGH,
            description="Repeated SSH failures.",
            source_ip="203.0.113.44",
            incident_id=11,
            detected_at=self.timestamp,
            events=[self.event],
        )
        self.state = build_investigation_case_state(self.incident, [self.detection])
        self.state.local_knowledge_context = ["knowledge context is not evidence"]

    def make_agent(self, response=None, error=None):
        client = Mock()
        client.model = "qwen2.5:3b"
        if error is not None:
            client.generate.side_effect = error
        else:
            client.generate.return_value = response if response is not None else model_output(101)
        return LocalInvestigationAgent(client), client

    def test_construction_satisfies_stage_one_agent_contract(self):
        agent, _ = self.make_agent()

        self.assertEqual(agent.agent_name, "investigation")
        self.assertTrue(callable(agent.run))

    def test_valid_case_state_produces_existing_structured_analysis(self):
        agent, client = self.make_agent()
        result = asyncio.run(agent.run(self.state))

        self.assertEqual(result.status, "completed")
        self.assertIsInstance(result.analysis, InvestigationAnalysis)
        self.assertEqual(result.analysis.summary, "Authentication activity needs review.")
        self.assertEqual(result.findings[0].classification, "hypothesis")
        context = client.generate.call_args.args[0]
        self.assertEqual(
            [item["event_id"] for item in context["evidence_facts"]],
            [self.event.id],
        )
        self.assertNotIn("knowledge context is not evidence", str(context))

    def test_successful_output_event_ids_are_from_case_evidence(self):
        agent, _ = self.make_agent()
        result = asyncio.run(agent.run(self.state))
        evidence_ids = {event.id for event in self.state.events}

        referenced_ids = set(result.analysis.summary_event_ids)
        for finding in result.analysis.findings:
            referenced_ids.update(finding.event_ids)
        self.assertTrue(referenced_ids)
        self.assertTrue(referenced_ids <= evidence_ids)

    def test_verification_is_called_independently_after_model_output(self):
        agent, _ = self.make_agent()
        with patch(
            "app.security.investigation_pipeline.verify_investigation",
            wraps=verify_investigation,
        ) as verifier:
            result = asyncio.run(agent.run(self.state))

        self.assertEqual(verifier.call_count, 1)
        self.assertTrue(result.verification.supported_claims)
        self.assertEqual(result.status, "completed")

    def test_invalid_event_ids_fail_independent_verification(self):
        agent, _ = self.make_agent(model_output(999))
        result = asyncio.run(agent.run(self.state))

        self.assertEqual(result.status, "failed")
        self.assertTrue(result.verification.missing_evidence)

    def test_ollama_failure_propagates_for_existing_route_handling(self):
        agent, _ = self.make_agent(error=OllamaUnavailable("offline"))

        with self.assertRaises(OllamaUnavailable):
            asyncio.run(agent.run(self.state))


if __name__ == "__main__":
    unittest.main()
