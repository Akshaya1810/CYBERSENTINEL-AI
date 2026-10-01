import asyncio
import inspect
import unittest
from datetime import datetime, timezone

from app.agents.contracts import (
    AlertTriageOutput,
    KnowledgeContextEntry,
    InvestigationCaseState,
    ResponsePlanningOutput,
    ThreatIntelligenceOutput,
)
from app.agents.investigation import InvestigationAgentExecution
from app.agents.orchestrator import (
    CentralOrchestrator,
    run_event_correlation_stage,
)
from app.agents.attack_reconstruction import DeterministicAttackReconstructionAgent
from app.agents.response_planning import DeterministicResponsePlanningAgent
from app.agents.tools import (
    EvidenceVerificationInput,
    EventCorrelationToolOutput,
    IncidentDetectionsInput,
    run_alert_triage_tool,
    run_event_correlation_tool,
    run_evidence_verification_tool,
)
from app.models import IncidentSeverity, IncidentStatus
from app.schemas.detections import DetectionHistoryRead
from app.schemas.incidents import IncidentRead, SecurityEventRead
from app.schemas.investigation import (
    EvidenceStatement,
    ImpactAssessment,
    InvestigationAnalysis,
    NarrativeSection,
    PipelineModuleStatus,
    RiskAssessment,
)
from app.schemas.verification import VerificationReportRead
from app.security.investigation_pipeline import verify_analysis


class FakeInvestigationAgent:
    agent_name = "investigation"

    def __init__(self, events, order):
        self._events = events
        self.order = order
        self.received_state = None

    async def run(self, state: InvestigationCaseState) -> InvestigationAgentExecution:
        self.order.append("investigation")
        self.received_state = state.model_copy(deep=True)
        event_id = self._events[0].id
        observed = EvidenceStatement(
            classification="observed_fact",
            text="The event records this source address.",
            event_ids=[event_id],
            source_ip=self._events[0].source_ip,
        )
        analysis = InvestigationAnalysis(
            summary="Authentication activity needs review.",
            summary_event_ids=[event_id],
            triage=NarrativeSection(
                summary="One deterministic detection is linked.",
                event_ids=[event_id],
                uncertainty="Deterministic triage only.",
            ),
            findings=[EvidenceStatement(
                classification="hypothesis",
                text="The activity may represent password guessing.",
                event_ids=[event_id],
            )],
            attack_reconstruction=NarrativeSection(
                summary="An interpretation for testing.",
                event_ids=[event_id],
                uncertainty="Hypothesis only.",
            ),
            impact_assessment=ImpactAssessment(observed=[observed]),
            risk_assessment=RiskAssessment(
                level="high",
                rationale="Stored severity is high.",
                event_ids=[event_id],
                uncertainty="Deterministic severity only.",
            ),
            response_recommendations=[],
        )
        verification = verify_analysis(self._events, analysis)
        return InvestigationAgentExecution(
            summary=NarrativeSection(
                summary=analysis.summary,
                event_ids=[event_id],
                uncertainty="Model interpretation.",
            ),
            findings=analysis.findings,
            analysis=analysis,
            verification=verification,
            modules=[PipelineModuleStatus(
                module="investigation",
                responsibility="Test agent",
                method="ollama",
                status="completed",
            )],
            generated_at=datetime.now(timezone.utc),
            status="completed",
        )


class CentralOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.timestamp = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
        self.state = InvestigationCaseState(
            incident=IncidentRead(
                id=5,
                title="SSH investigation",
                description="Synthetic test incident.",
                severity=IncidentSeverity.HIGH,
                status=IncidentStatus.OPEN,
                source_ip="203.0.113.10",
                created_at=self.timestamp,
                updated_at=self.timestamp,
            ),
            events=[
                SecurityEventRead(
                    id=101 + offset,
                    incident_id=5,
                    event_type="ssh_authentication_failed",
                    description="Synthetic SSH failure.",
                    source_ip="203.0.113.10",
                    timestamp=self.timestamp,
                    raw_log="synthetic only",
                    username="analyst",
                    hostname="host-a",
                )
                for offset in range(2)
            ],
            detections=[DetectionHistoryRead(
                id=20,
                rule_id="SSH-AUTH-001",
                rule_name="SSH brute-force attempt",
                severity=IncidentSeverity.HIGH,
                description="Two related SSH failures.",
                source_ip="203.0.113.10",
                incident_id=5,
                detected_at=self.timestamp,
                event_ids=[101, 102],
            )],
        )

    def make_orchestrator(
        self,
        *,
        triage_tool=run_alert_triage_tool,
        correlation_tool=run_event_correlation_stage,
        verification_tool=run_evidence_verification_tool,
        agent_error=None,
        reconstruction_agent=None,
        threat_intelligence_agent=None,
        risk_assessment_agent=None,
        response_planning_agent=None,
    ):
        order = []
        investigation_agent = FakeInvestigationAgent(self.state.events, order)
        if agent_error is not None:
            async def failed_agent_run(_state):
                order.append("investigation")
                raise agent_error
            investigation_agent.run = failed_agent_run
        orchestrator = CentralOrchestrator(
            investigation_agent,
            triage_tool=triage_tool,
            correlation_tool=correlation_tool,
            verification_tool=verification_tool,
            attack_reconstruction_agent=reconstruction_agent,
            threat_intelligence_agent=threat_intelligence_agent,
            risk_assessment_agent=risk_assessment_agent,
            response_planning_agent=response_planning_agent,
        )
        return orchestrator, investigation_agent, order

    def test_successful_workflow_runs_sequentially_and_completes_state(self):
        order = []

        def triage(inputs: IncidentDetectionsInput) -> AlertTriageOutput:
            order.append("triage")
            return run_alert_triage_tool(inputs)

        def correlation(state: InvestigationCaseState, inputs: IncidentDetectionsInput) -> EventCorrelationToolOutput:
            self.assertIsNotNone(state.triage)
            order.append("correlation")
            return run_event_correlation_tool(inputs)

        def verification(inputs: EvidenceVerificationInput) -> VerificationReportRead:
            order.append("verification")
            return run_evidence_verification_tool(inputs)

        class RecordingReconstructionAgent:
            agent_name = "attack_reconstruction"

            async def run(inner_self, state):
                order.append("attack_reconstruction")
                return await DeterministicAttackReconstructionAgent().run(state)

        class RecordingThreatAgent:
            agent_name = "threat_intelligence"

            async def run(inner_self, state):
                order.append("threat_intelligence")
                return ThreatIntelligenceOutput(
                    knowledge_query="local test query",
                    retrieved_context=[KnowledgeContextEntry(
                        id="local-test",
                        title="Local test reference",
                        description="Context only.",
                        guidance="Not evidence.",
                        relevance_score=1.0,
                    )],
                )

        class RecordingRiskAgent:
            agent_name = "risk_assessment"

            async def run(inner_self, state):
                order.append("risk_assessment")
                self.assertIsNotNone(state.threat_intelligence)
                return RiskAssessment(
                    level="high",
                    rationale="Persisted High severity.",
                    event_ids=[101, 102],
                    uncertainty="Deterministic severity only.",
                )

        class RecordingResponseAgent:
            agent_name = "response_planning"

            async def run(inner_self, state):
                order.append("response_planning")
                self.assertIsNotNone(state.risk_assessment)
                return ResponsePlanningOutput()

        agent = FakeInvestigationAgent(self.state.events, order)
        orchestrator = CentralOrchestrator(
            agent, triage, correlation, verification,
            attack_reconstruction_agent=RecordingReconstructionAgent(),
            threat_intelligence_agent=RecordingThreatAgent(),
            risk_assessment_agent=RecordingRiskAgent(),
            response_planning_agent=RecordingResponseAgent(),
        )
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(order, [
            "triage", "correlation", "investigation", "attack_reconstruction",
            "threat_intelligence", "risk_assessment", "response_planning",
            "verification",
        ])
        self.assertEqual(result.status, "completed")
        self.assertIsNone(result.current_agent)
        self.assertEqual(
            result.completed_agents,
            [
                "alert_triage", "event_correlation", "investigation",
                "attack_reconstruction", "threat_intelligence",
                "risk_assessment", "response_planning", "verification",
                "incident_report_generation",
            ],
        )
        self.assertIsNotNone(result.triage)
        self.assertIsNotNone(result.correlation)
        self.assertIsNotNone(result.investigation)
        self.assertIsNotNone(result.attack_reconstruction)
        self.assertIsNotNone(result.threat_intelligence)
        self.assertIsNotNone(result.risk_assessment)
        self.assertIsNotNone(result.response_plan)
        self.assertIsNotNone(result.report)
        self.assertEqual(result.verification.status, "partially_verified")

    def test_triage_and_correlation_outputs_reach_investigation_stage(self):
        orchestrator, agent, _ = self.make_orchestrator()
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(agent.received_state.triage, result.triage)
        self.assertEqual(agent.received_state.correlation, result.correlation)
        self.assertEqual(len(agent.received_state.correlation.groups), 1)
        self.assertEqual(agent.received_state.correlation.groups[0].event_ids, [101, 102])

    def test_investigation_output_is_used_as_verification_input(self):
        received = []

        def verification(inputs: EvidenceVerificationInput) -> VerificationReportRead:
            received.append(inputs)
            return run_evidence_verification_tool(inputs)

        orchestrator, _, _ = self.make_orchestrator(verification_tool=verification)
        result = asyncio.run(orchestrator.run(self.state))

        self.assertTrue(received)
        self.assertEqual(
            {item.text for item in received[0].claims},
            {item.text for item in result.investigation.findings}
            | {
                "Recorded ssh_authentication_failed: Synthetic SSH failure.",
                "Investigation hypothesis: The activity may represent password guessing.",
                "The event records this source address.",
                "Investigation summary: Authentication activity needs review.",
                "Deterministic triage: One deterministic detection is linked.",
                "Attack reconstruction: An interpretation for testing.",
                "Risk assessment: high. Stored severity is high.",
                "Deterministic risk assessment: high. Risk level follows High from deterministic rule(s): SSH brute-force attempt; this is not confirmation of compromise.",
            },
        )
        self.assertEqual([event.id for event in received[0].evidence], [101, 102])

    def test_threat_intelligence_receives_updated_case_state(self):
        received = []

        class RecordingThreatAgent:
            agent_name = "threat_intelligence"

            async def run(inner_self, state):
                received.append(state.model_copy(deep=True))
                return ThreatIntelligenceOutput(knowledge_query="SSH")

        orchestrator, _, _ = self.make_orchestrator(
            threat_intelligence_agent=RecordingThreatAgent(),
        )
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(len(received), 1)
        self.assertIsNotNone(received[0].attack_reconstruction)
        self.assertTrue(received[0].investigation.findings)
        self.assertIsNotNone(result.threat_intelligence)

    def test_risk_assessment_receives_updated_knowledge_and_reconstruction(self):
        received = []

        class RecordingThreatAgent:
            agent_name = "threat_intelligence"

            async def run(inner_self, _state):
                return ThreatIntelligenceOutput(knowledge_query="SSH")

        class RecordingRiskAgent:
            agent_name = "risk_assessment"

            async def run(inner_self, state):
                received.append(state.model_copy(deep=True))
                return RiskAssessment(
                    level="high",
                    rationale="Persisted High severity.",
                    event_ids=[101],
                    uncertainty="Deterministic estimate only.",
                )

        orchestrator, _, _ = self.make_orchestrator(
            threat_intelligence_agent=RecordingThreatAgent(),
            risk_assessment_agent=RecordingRiskAgent(),
        )
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(len(received), 1)
        self.assertIsNotNone(received[0].threat_intelligence)
        self.assertIsNotNone(received[0].attack_reconstruction)
        self.assertIsNotNone(result.risk_assessment)
        self.assertLess(
            result.completed_agents.index("risk_assessment"),
            result.completed_agents.index("response_planning"),
        )
        self.assertLess(
            result.completed_agents.index("response_planning"),
            result.completed_agents.index("verification"),
        )
        self.assertLess(
            result.completed_agents.index("verification"),
            result.completed_agents.index("incident_report_generation"),
        )

    def test_threat_or_risk_stage_failure_stops_without_later_outputs(self):
        class FailedStageAgent:
            def __init__(self, name):
                self.agent_name = name

            async def run(self, _state):
                raise RuntimeError(f"{self.agent_name} failed")

        class SuccessfulThreatAgent:
            agent_name = "threat_intelligence"

            async def run(self, _state):
                return ThreatIntelligenceOutput(knowledge_query="local context")

        for stage_name, options, expected_prior in (
            ("threat_intelligence", {"threat_intelligence_agent": FailedStageAgent("threat_intelligence")}, "attack_reconstruction"),
            ("risk_assessment", {
                "threat_intelligence_agent": SuccessfulThreatAgent(),
                "risk_assessment_agent": FailedStageAgent("risk_assessment"),
            }, "threat_intelligence"),
        ):
            with self.subTest(stage=stage_name):
                orchestrator, _, _ = self.make_orchestrator(**options)
                result = asyncio.run(orchestrator.run(self.state.model_copy(deep=True)))

                self.assertEqual(result.status, "failed")
                self.assertEqual(result.current_agent, stage_name)
                self.assertIn(expected_prior, result.completed_agents)
                self.assertIsNone(result.verification)
                if stage_name == "threat_intelligence":
                    self.assertIsNone(result.threat_intelligence)
                    self.assertIsNone(result.risk_assessment)
                else:
                    self.assertIsNotNone(result.threat_intelligence)
                    self.assertIsNone(result.risk_assessment)
                self.assertIn(f"{stage_name} failed", result.error_message)

    def test_response_planning_failure_stops_before_verification_and_report(self):
        class FailedResponseAgent:
            agent_name = "response_planning"

            async def run(self, _state):
                raise RuntimeError("response planning failed")

        orchestrator, _, _ = self.make_orchestrator(
            response_planning_agent=FailedResponseAgent(),
        )
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.current_agent, "response_planning")
        self.assertIsNone(result.response_plan)
        self.assertIsNone(result.verification)
        self.assertIsNone(result.report)
        self.assertIn("response planning failed", result.error_message)

    def test_response_planning_receives_updated_case_state(self):
        received = []

        class RecordingResponseAgent:
            agent_name = "response_planning"

            async def run(inner_self, state):
                received.append(state.model_copy(deep=True))
                return await DeterministicResponsePlanningAgent().run(state)

        orchestrator, _, _ = self.make_orchestrator(
            response_planning_agent=RecordingResponseAgent(),
        )
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(len(received), 1)
        self.assertIsNotNone(received[0].investigation)
        self.assertIsNotNone(received[0].attack_reconstruction)
        self.assertIsNotNone(received[0].threat_intelligence)
        self.assertIsNotNone(received[0].risk_assessment)
        self.assertIsNotNone(result.response_plan)
        self.assertLess(
            result.completed_agents.index("risk_assessment"),
            result.completed_agents.index("response_planning"),
        )
        self.assertLess(
            result.completed_agents.index("response_planning"),
            result.completed_agents.index("verification"),
        )

    def test_verification_rejection_preserves_report_and_never_executes_response(self):
        rejected = VerificationReportRead(
            status="contradicted",
            supported_claims=[],
            unsupported_claims=[],
            warnings=["Recommendation target was not supported."],
            contradictions=["Recommendation rejected."],
            missing_evidence=[],
            recommendations=[],
        )
        orchestrator, _, _ = self.make_orchestrator(
            verification_tool=lambda _inputs: rejected,
        )
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.verification, rejected)
        self.assertIsNotNone(result.report)
        self.assertEqual(result.report.verification, rejected)
        self.assertFalse(result.response_plan.actions_executed)
        self.assertTrue(all(
            item.approval_status == "pending"
            for item in result.response_plan.recommendations
        ))
        self.assertTrue(any(
            "no actions were executed" in item
            for item in result.report.limitations
        ))

    def test_final_report_handoff_preserves_risk_findings_and_advisory_recommendations(self):
        result = asyncio.run(CentralOrchestrator(FakeInvestigationAgent(
            self.state.events, [],
        )).run(self.state))

        self.assertIsNotNone(result.report)
        self.assertEqual(result.report.verification, result.verification)
        self.assertTrue(result.report.ai_investigations)
        report_analysis = result.report.ai_investigations[-1].analysis
        self.assertEqual(report_analysis.risk_assessment, result.risk_assessment)
        self.assertTrue(report_analysis.findings)
        self.assertTrue(result.report.response_recommendations)
        self.assertTrue(all(
            recommendation["approval_status"] == "pending"
            for recommendation in result.report.response_recommendations
        ))
        self.assertTrue(all(
            recommendation["actions_executed"] == "false"
            for recommendation in result.report.response_recommendations
        ))
        self.assertTrue(any(
            recommendation["requires_human_approval"] == "true"
            for recommendation in result.report.response_recommendations
        ))
        self.assertTrue(any(
            "no actions were executed" in item
            for item in result.report.limitations
        ))

    def test_verification_failure_is_recorded_as_failed_state(self):
        invalid_verification = VerificationReportRead(
            status="contradicted",
            supported_claims=[],
            unsupported_claims=[],
            warnings=["Contradictory test result."],
            contradictions=["Claim contradicted."],
            missing_evidence=[],
            recommendations=[],
        )
        orchestrator, _, _ = self.make_orchestrator(
            verification_tool=lambda _inputs: invalid_verification,
        )
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.verification.status, "contradicted")
        self.assertIn("independent evidence verification", result.error_message)
        self.assertIn("verification", result.completed_agents)

    def test_stage_failure_stops_without_fabricating_later_outputs(self):
        def failed_correlation(_state, _inputs):
            raise RuntimeError("correlation service failed")

        orchestrator, _, _ = self.make_orchestrator(correlation_tool=failed_correlation)
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.current_agent, "event_correlation")
        self.assertIsNotNone(result.triage)
        self.assertIsNone(result.correlation)
        self.assertIsNone(result.investigation)
        self.assertIsNone(result.verification)
        self.assertIn("correlation service failed", result.error_message)

    def test_investigation_failure_stops_before_verification(self):
        orchestrator, _, order = self.make_orchestrator(
            agent_error=RuntimeError("investigation unavailable"),
        )
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(result.status, "failed")
        self.assertEqual(order, ["investigation"])
        self.assertIsNotNone(result.triage)
        self.assertIsNotNone(result.correlation)
        self.assertIsNone(result.investigation)
        self.assertIsNone(result.verification)
        self.assertIn("investigation unavailable", result.error_message)

    def test_reconstruction_failure_is_recorded_without_verification(self):
        class FailingReconstructionAgent:
            agent_name = "attack_reconstruction"

            async def run(self, _state):
                raise RuntimeError("reconstruction failed")

        orchestrator, _, _ = self.make_orchestrator(
            reconstruction_agent=FailingReconstructionAgent(),
        )
        result = asyncio.run(orchestrator.run(self.state))

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.current_agent, "attack_reconstruction")
        self.assertIsNotNone(result.investigation)
        self.assertIsNone(result.attack_reconstruction)
        self.assertIsNone(result.verification)
        self.assertIn("reconstruction failed", result.error_message)

    def test_orchestrator_satisfies_stage_one_contract(self):
        orchestrator, _, _ = self.make_orchestrator()

        self.assertTrue(inspect.iscoroutinefunction(orchestrator.run))
        self.assertEqual(list(inspect.signature(orchestrator.run).parameters), ["state"])
        self.assertIs(inspect.signature(orchestrator.run).return_annotation, InvestigationCaseState)
        self.assertIsInstance(self.state, InvestigationCaseState)


if __name__ == "__main__":
    unittest.main()
