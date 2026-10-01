import asyncio
import inspect
import unittest
from datetime import datetime, timezone

from app.agents.attack_reconstruction import DeterministicAttackReconstructionAgent
from app.agents.contracts import (
    AttackReconstructionOutput,
    InvestigationAgentOutput,
    InvestigationCaseState,
)
from app.models import IncidentSeverity, IncidentStatus
from app.schemas.detections import DetectionHistoryRead
from app.schemas.incidents import IncidentRead, SecurityEventRead
from app.schemas.investigation import EvidenceStatement, NarrativeSection


class AttackReconstructionAgentTests(unittest.TestCase):
    def setUp(self):
        self.timestamp = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
        self.state = InvestigationCaseState(
            incident=IncidentRead(
                id=10,
                title="SSH incident",
                description="Test incident",
                severity=IncidentSeverity.HIGH,
                status=IncidentStatus.OPEN,
                source_ip="203.0.113.8",
                created_at=self.timestamp,
                updated_at=self.timestamp,
            ),
            events=[
                SecurityEventRead(
                    id=201,
                    incident_id=10,
                    event_type="ssh_authentication_failed",
                    description="Failed password for analyst.",
                    source_ip="203.0.113.8",
                    timestamp=self.timestamp,
                    raw_log="synthetic failed password",
                    username="analyst",
                    hostname="host-a",
                ),
                SecurityEventRead(
                    id=202,
                    incident_id=10,
                    event_type="ssh_authentication_succeeded",
                    description="Accepted password for analyst.",
                    source_ip="203.0.113.8",
                    timestamp=self.timestamp.replace(minute=1),
                    raw_log="synthetic accepted password",
                    username="analyst",
                    hostname="host-a",
                ),
            ],
            detections=[DetectionHistoryRead(
                id=30,
                rule_id="SSH-AUTH-002",
                rule_name="Successful SSH login following repeated failures",
                severity=IncidentSeverity.CRITICAL,
                description="A successful login followed failures.",
                source_ip="203.0.113.8",
                incident_id=10,
                detected_at=self.timestamp,
                event_ids=[201, 202],
            )],
            local_knowledge_context=["knowledge says an attack can involve persistence"],
        )

    def test_construction_satisfies_agent_contract(self):
        agent = DeterministicAttackReconstructionAgent()

        self.assertEqual(agent.agent_name, "attack_reconstruction")
        self.assertTrue(inspect.iscoroutinefunction(agent.run))
        self.assertEqual(list(inspect.signature(agent.run).parameters), ["state"])
        self.assertIs(inspect.signature(agent.run).return_annotation, AttackReconstructionOutput)

    def test_valid_state_reconstructs_ordered_stored_event_records(self):
        output = asyncio.run(DeterministicAttackReconstructionAgent().run(self.state))

        self.assertIsInstance(output, AttackReconstructionOutput)
        self.assertEqual(
            [step.event_ids for step in output.steps if step.classification == "observed"],
            [[201], [202]],
        )
        self.assertEqual([step.order for step in output.steps], [1, 2])
        self.assertEqual(output.steps[0].description, "Recorded ssh_authentication_failed: Failed password for analyst.")
        self.assertEqual(output.steps[0].successful_login, False)
        self.assertEqual(output.steps[1].successful_login, True)
        self.assertTrue(all(step.confidence == "high" for step in output.steps))

    def test_each_observed_step_has_valid_event_ids(self):
        output = asyncio.run(DeterministicAttackReconstructionAgent().run(self.state))
        valid_ids = {event.id for event in self.state.events}

        self.assertTrue(output.steps)
        for step in output.steps:
            if step.classification == "observed":
                self.assertTrue(step.event_ids)
                self.assertTrue(set(step.event_ids) <= valid_ids)

    def test_investigation_findings_remain_low_confidence_hypotheses(self):
        self.state.investigation = InvestigationAgentOutput(
            summary=NarrativeSection(
                summary="Authentication activity.",
                event_ids=[201],
                uncertainty="Interpretation only.",
            ),
            findings=[EvidenceStatement(
                classification="hypothesis",
                text="The sequence may be password guessing.",
                event_ids=[201, 202],
            )],
        )
        output = asyncio.run(DeterministicAttackReconstructionAgent().run(self.state))
        hypothesis, = [step for step in output.steps if step.classification == "hypothesized"]

        self.assertEqual(hypothesis.event_ids, [201, 202])
        self.assertEqual(hypothesis.confidence, "low")
        self.assertIn("hypothesis", hypothesis.uncertainty)

    def test_insufficient_evidence_produces_no_fabricated_attack_steps(self):
        self.state.events = []
        self.state.detections = []
        output = asyncio.run(DeterministicAttackReconstructionAgent().run(self.state))

        self.assertEqual(output.steps, [])
        self.assertIn("No stored incident events", output.reconstruction.summary)
        self.assertEqual(output.reconstruction.event_ids, [])

    def test_attack_references_are_context_only_not_event_evidence(self):
        output = asyncio.run(DeterministicAttackReconstructionAgent().run(self.state))

        self.assertTrue(output.contextual_attack_references)
        self.assertEqual(output.contextual_attack_references[0].technique_id, "T1110")
        self.assertIn("not evidence", output.reference_note)
        event_ids = {event.id for event in self.state.events}
        self.assertTrue(all(
            set(step.event_ids) <= event_ids
            for step in output.steps if step.classification == "observed"
        ))
        self.assertFalse(hasattr(output.contextual_attack_references[0], "event_ids"))

    def test_knowledge_context_does_not_create_steps(self):
        baseline = asyncio.run(DeterministicAttackReconstructionAgent().run(self.state))
        self.state.local_knowledge_context = [
            "knowledge says an attack can involve persistence",
            "T1059 command execution",
        ]
        with_knowledge = asyncio.run(DeterministicAttackReconstructionAgent().run(self.state))

        self.assertEqual(with_knowledge.steps, baseline.steps)
        self.assertEqual(with_knowledge.reconstruction, baseline.reconstruction)

    def test_invalid_investigation_event_reference_fails_safely(self):
        self.state.investigation = InvestigationAgentOutput(
            summary=NarrativeSection(
                summary="Unrelated finding.",
                event_ids=[999],
                uncertainty="Unverified.",
            ),
            findings=[EvidenceStatement(
                classification="hypothesis",
                text="Unsupported activity.",
                event_ids=[999],
            )],
        )

        with self.assertRaisesRegex(ValueError, "missing or invalid incident event IDs"):
            asyncio.run(DeterministicAttackReconstructionAgent().run(self.state))


if __name__ == "__main__":
    unittest.main()
