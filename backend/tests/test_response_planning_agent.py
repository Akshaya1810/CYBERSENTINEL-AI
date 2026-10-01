import asyncio
import inspect
import unittest
from datetime import datetime, timezone

from app.agents.contracts import (
    InvestigationCaseState,
    ResponsePlanRecommendation,
    ResponsePlanningOutput,
)
from app.agents.response_planning import DeterministicResponsePlanningAgent
from app.models import IncidentSeverity, IncidentStatus
from app.schemas.detections import DetectionHistoryRead
from app.schemas.incidents import IncidentRead, SecurityEventRead
from app.schemas.investigation import EvidenceStatement, NarrativeSection, RiskAssessment


class ResponsePlanningAgentTests(unittest.TestCase):
    def setUp(self):
        self.timestamp = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
        self.state = InvestigationCaseState(
            incident=IncidentRead(
                id=70,
                title="SSH activity",
                description="Recorded SSH authentication failures.",
                severity=IncidentSeverity.HIGH,
                status=IncidentStatus.OPEN,
                source_ip="203.0.113.70",
                created_at=self.timestamp,
                updated_at=self.timestamp,
            ),
            events=[
                SecurityEventRead(
                    id=701 + offset,
                    incident_id=70,
                    event_type="ssh_authentication_failed",
                    description="Failed password.",
                    source_ip="203.0.113.70",
                    timestamp=self.timestamp,
                    raw_log="synthetic event",
                    username="analyst",
                    hostname="host-a",
                )
                for offset in range(2)
            ],
            detections=[DetectionHistoryRead(
                id=80,
                rule_id="SSH-AUTH-001",
                rule_name="SSH brute-force attempt",
                severity=IncidentSeverity.HIGH,
                description="Repeated SSH failures.",
                source_ip="203.0.113.70",
                incident_id=70,
                detected_at=self.timestamp,
                event_ids=[701, 702],
            )],
            risk_assessment=RiskAssessment(
                level="high",
                rationale="Persisted severity and detection record.",
                event_ids=[701, 702],
                uncertainty="Deterministic assessment.",
            ),
            investigation={
                "summary": {
                    "summary": "Repeated authentication failures.",
                    "event_ids": [701],
                    "uncertainty": "Not a compromise finding.",
                },
                "findings": [{
                    "classification": "hypothesis",
                    "text": "This may be password guessing.",
                    "event_ids": [701, 702],
                }],
            },
        )

    def test_construction_and_state_contract(self):
        agent = DeterministicResponsePlanningAgent()

        self.assertEqual(agent.agent_name, "response_planning")
        self.assertTrue(inspect.iscoroutinefunction(agent.run))
        self.assertIsInstance(self.state, InvestigationCaseState)

    def test_valid_state_produces_structured_recommendations(self):
        output = asyncio.run(DeterministicResponsePlanningAgent().run(self.state))

        self.assertIsInstance(output, ResponsePlanningOutput)
        self.assertTrue(output.recommendations)
        self.assertTrue(all(
            isinstance(item, ResponsePlanRecommendation)
            for item in output.recommendations
        ))

    def test_recommendations_never_execute_actions(self):
        output = asyncio.run(DeterministicResponsePlanningAgent().run(self.state))

        self.assertFalse(output.actions_executed)
        self.assertTrue(all(not item.actions_executed for item in output.recommendations))

    def test_high_impact_recommendations_require_pending_human_approval(self):
        output = asyncio.run(DeterministicResponsePlanningAgent().run(self.state))
        high_impact = [
            item for item in output.recommendations
            if item.action_type in {
                "block_source_ip", "rate_limit_source_ip", "disable_account", "reset_password",
            }
        ]

        self.assertTrue(high_impact)
        self.assertTrue(all(item.requires_human_approval for item in high_impact))
        self.assertTrue(all(item.approval_status == "pending" for item in high_impact))
        self.assertTrue(all(item.priority == "high" for item in high_impact))

    def test_recommendation_event_ids_are_from_the_case(self):
        output = asyncio.run(DeterministicResponsePlanningAgent().run(self.state))
        valid_ids = {event.id for event in self.state.events}

        for recommendation in output.recommendations:
            self.assertTrue(recommendation.event_ids)
            self.assertTrue(set(recommendation.event_ids) <= valid_ids)

    def test_insufficient_evidence_returns_limitations_without_actions(self):
        self.state.events = []
        self.state.detections = []
        output = asyncio.run(DeterministicResponsePlanningAgent().run(self.state))

        self.assertEqual(output.recommendations, [])
        self.assertTrue(output.limitations)
        self.assertFalse(output.actions_executed)

    def test_planning_consumes_existing_risk_and_investigation_without_overriding(self):
        prior_risk = self.state.risk_assessment
        prior_investigation = self.state.investigation
        output = asyncio.run(DeterministicResponsePlanningAgent().run(self.state))

        self.assertEqual(output.recommendations[0].priority, prior_risk.level)
        self.assertIn("stored events", output.recommendations[0].uncertainty)
        self.assertIs(self.state.risk_assessment, prior_risk)
        self.assertIs(self.state.investigation, prior_investigation)

    def test_approval_state_is_representable_but_agent_defaults_to_pending(self):
        approved = ResponsePlanRecommendation(
            text="Block the recorded source.",
            action_type="block_source_ip",
            event_ids=[701],
            source_ip="203.0.113.70",
            priority="high",
            requires_human_approval=True,
            approval_status="approved",
            uncertainty="Test only.",
        )
        output = asyncio.run(DeterministicResponsePlanningAgent().run(self.state))

        self.assertEqual(approved.approval_status, "approved")
        self.assertTrue(all(
            item.approval_status == "pending"
            for item in output.recommendations
        ))


if __name__ == "__main__":
    unittest.main()
