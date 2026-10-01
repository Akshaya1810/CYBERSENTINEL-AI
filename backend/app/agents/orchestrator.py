"""Sequential internal workflow for the initial investigation agent stages."""

from typing import Callable

from app.agents.contracts import (
    AlertTriageOutput,
    AttackReconstructionAgent as AttackReconstructionAgentContract,
    CentralOrchestratorContract,
    CorrelationGroup,
    EventCorrelationOutput,
    InvestigationCaseState,
    RiskAssessmentAgent as RiskAssessmentAgentContract,
    ResponsePlanningAgent as ResponsePlanningAgentContract,
    ThreatIntelligenceAgent as ThreatIntelligenceAgentContract,
)
from app.agents.attack_reconstruction import DeterministicAttackReconstructionAgent
from app.agents.investigation import (
    LocalInvestigationAgent,
    materialize_investigation_case,
)
from app.agents.knowledge import LocalThreatIntelligenceAgent
from app.agents.risk import DeterministicRiskAssessmentAgent
from app.agents.response_planning import DeterministicResponsePlanningAgent
from app.agents.tools import (
    EventCorrelationToolOutput,
    EvidenceVerificationInput,
    IncidentReportInput,
    IncidentDetectionsInput,
    run_alert_triage_tool,
    run_event_correlation_tool,
    run_evidence_verification_tool,
    run_incident_report_tool,
)
from app.schemas.investigation import InvestigationRunRead
from app.schemas.verification import ResponseRecommendationInput, VerificationRequest
from app.schemas.verification import VerificationReportRead
from app.schemas.verification import InvestigationClaimInput
from app.security.investigation_pipeline import analysis_verification_inputs, verification_passes

TriageTool = Callable[[IncidentDetectionsInput], AlertTriageOutput]
VerificationTool = Callable[[EvidenceVerificationInput], VerificationReportRead]
CorrelationStage = Callable[
    [InvestigationCaseState, IncidentDetectionsInput],
    EventCorrelationToolOutput,
]


def run_event_correlation_stage(
    state: InvestigationCaseState,
    inputs: IncidentDetectionsInput,
) -> EventCorrelationToolOutput:
    if state.triage is None:
        raise RuntimeError("Triage output is not available to the correlation stage.")
    return run_event_correlation_tool(inputs)


class CentralOrchestrator(CentralOrchestratorContract):
    agent_name = "central_orchestrator"

    def __init__(
        self,
        investigation_agent: LocalInvestigationAgent,
        triage_tool: TriageTool = run_alert_triage_tool,
        correlation_tool: CorrelationStage = run_event_correlation_stage,
        verification_tool: VerificationTool = run_evidence_verification_tool,
        attack_reconstruction_agent: AttackReconstructionAgentContract | None = None,
        threat_intelligence_agent: ThreatIntelligenceAgentContract | None = None,
        risk_assessment_agent: RiskAssessmentAgentContract | None = None,
        response_planning_agent: ResponsePlanningAgentContract | None = None,
    ):
        self._investigation_agent = investigation_agent
        self._attack_reconstruction_agent = (
            attack_reconstruction_agent or DeterministicAttackReconstructionAgent()
        )
        self._threat_intelligence_agent = (
            threat_intelligence_agent or LocalThreatIntelligenceAgent()
        )
        self._risk_assessment_agent = (
            risk_assessment_agent or DeterministicRiskAssessmentAgent()
        )
        self._response_planning_agent = (
            response_planning_agent or DeterministicResponsePlanningAgent()
        )
        self._triage_tool = triage_tool
        self._correlation_tool = correlation_tool
        self._verification_tool = verification_tool

    async def run(self, state: InvestigationCaseState) -> InvestigationCaseState:
        state.status = "running"
        state.error_message = None
        state.completed_agents = []
        state.triage = None
        state.correlation = None
        state.investigation = None
        state.attack_reconstruction = None
        state.threat_intelligence = None
        state.risk_assessment = None
        state.response_plan = None
        state.verification = None
        state.report = None

        try:
            state.current_agent = "alert_triage"
            incident, detections = materialize_investigation_case(state)
            inputs = IncidentDetectionsInput(incident=incident, detections=detections)
            triage = self._triage_tool(inputs)
            state.triage = triage
            state.completed_agents.append("alert_triage")

            state.current_agent = "event_correlation"
            correlated = self._correlation_tool(state, inputs)
            state.correlation = EventCorrelationOutput(
                groups=[
                    CorrelationGroup(
                        event_ids=item.event_ids,
                        rationale=item.description,
                    )
                    for item in correlated.correlations
                    if len(item.event_ids) >= 2
                ]
            )
            state.completed_agents.append("event_correlation")

            state.current_agent = "investigation"
            execution = await self._investigation_agent.run(state)
            state.investigation = execution
            state.completed_agents.append("investigation")

            state.current_agent = "attack_reconstruction"
            state.attack_reconstruction = await self._attack_reconstruction_agent.run(state)
            state.completed_agents.append("attack_reconstruction")

            state.current_agent = "threat_intelligence"
            state.threat_intelligence = await self._threat_intelligence_agent.run(state)
            state.completed_agents.append("threat_intelligence")

            state.current_agent = "risk_assessment"
            state.risk_assessment = await self._risk_assessment_agent.run(state)
            state.completed_agents.append("risk_assessment")

            state.current_agent = "response_planning"
            state.response_plan = await self._response_planning_agent.run(state)
            state.completed_agents.append("response_planning")

            state.current_agent = "verification"
            claims, recommendations = analysis_verification_inputs(execution.analysis)
            claims.extend(
                InvestigationClaimInput(
                    text=step.description,
                    claim_type=(
                        "fact"
                        if step.classification == "observed"
                        and any((step.source_ip, step.username, step.hostname, step.timestamp, step.successful_login is not None))
                        else "hypothesis"
                    ),
                    event_ids=step.event_ids,
                    source_ip=step.source_ip,
                    username=step.username,
                    hostname=step.hostname,
                    timestamp=step.timestamp,
                    successful_login=step.successful_login,
                )
                for step in state.attack_reconstruction.steps
            )
            risk = state.risk_assessment
            if risk is not None and risk.event_ids:
                claims.append(InvestigationClaimInput(
                    text=f"Deterministic risk assessment: {risk.level}. {risk.rationale}",
                    claim_type="hypothesis",
                    event_ids=risk.event_ids,
                ))
            response_recommendations = [
                ResponseRecommendationInput(
                    text=item.text,
                    action_type=item.action_type,
                    event_ids=item.event_ids,
                    source_ip=item.source_ip,
                    username=item.username,
                    approval_status=item.approval_status,
                )
                for item in state.response_plan.recommendations
            ]
            recommendations.extend(response_recommendations)
            request = VerificationRequest(claims=claims, recommendations=recommendations)
            state.verification = self._verification_tool(EvidenceVerificationInput(
                evidence=incident.security_events,
                claims=claims,
                recommendations=recommendations,
            ))
            state.completed_agents.append("verification")

            if execution.status != "completed" or not verification_passes(state.verification):
                state.status = "failed"
                state.error_message = execution.error_message or (
                    "Investigation or response recommendations did not pass independent evidence verification."
                )
            else:
                state.status = "completed"

            state.current_agent = "incident_report_generation"
            report = run_incident_report_tool(IncidentReportInput(
                incident=incident,
                detections=detections,
                verification_request=request,
            ))
            report_run = InvestigationRunRead(
                status="completed",
                model="Local Ollama",
                inference_used=True,
                generated_at=execution.generated_at,
                analysis=execution.analysis.model_copy(
                    update={"risk_assessment": state.risk_assessment}
                ),
                verification=state.verification,
                modules=execution.modules,
            )
            response_by_key = {
                (item.text, item.action_type): item
                for item in state.response_plan.recommendations
            }
            report_recommendations = []
            for recommendation in report.response_recommendations:
                plan = response_by_key.get((
                    recommendation.get("text", ""),
                    recommendation.get("action_type", ""),
                ))
                if plan is None:
                    report_recommendations.append(recommendation)
                    continue
                report_recommendations.append({
                    **recommendation,
                    "priority": plan.priority,
                    "requires_human_approval": str(plan.requires_human_approval).lower(),
                    "uncertainty": plan.uncertainty,
                    "actions_executed": str(plan.actions_executed).lower(),
                })
            state.report = report.model_copy(update={
                "verification": state.verification,
                "ai_investigations": [*report.ai_investigations, report_run],
                "response_recommendations": report_recommendations,
                "limitations": [
                    *report.limitations,
                    *state.response_plan.limitations,
                    "The current orchestrated investigation is attached to this in-memory report and is not newly persisted.",
                    "Response recommendations are advisory only; no actions were executed.",
                ],
            })
            state.completed_agents.append("incident_report_generation")
            state.current_agent = None
            return state
        except Exception as error:
            state.status = "failed"
            state.error_message = f"{state.current_agent or 'workflow'} stage failed: {type(error).__name__}: {error}"
            return state
