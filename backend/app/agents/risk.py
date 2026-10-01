"""Deterministic risk assessment agent backed by persisted case severity."""

from typing import Literal

from app.agents.contracts import InvestigationCaseState
from app.agents.investigation import materialize_investigation_case
from app.agents.tools import IncidentDetectionsInput, run_risk_assessment_tool
from app.schemas.investigation import RiskAssessment


class DeterministicRiskAssessmentAgent:
    agent_name: Literal["risk_assessment"] = "risk_assessment"

    async def run(self, state: InvestigationCaseState) -> RiskAssessment:
        incident, detections = materialize_investigation_case(state)
        return run_risk_assessment_tool(
            IncidentDetectionsInput(incident=incident, detections=detections)
        )
