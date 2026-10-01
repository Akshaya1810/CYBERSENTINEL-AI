from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.agents.investigation import LocalInvestigationAgent, build_investigation_case_state
from app.core.config import get_settings
from app.db.dependencies import get_db
from app.models import DetectionRecord, Incident, InvestigationResult
from app.schemas.investigation import InvestigationRunRead, PipelineModuleStatus
from app.security.investigation_pipeline import pipeline_modules
from app.security.ollama import (
    OllamaConfigurationError, OllamaInvalidResponse, OllamaTimedOut,
    OllamaUnavailable, OllamaClient,
)

router = APIRouter(prefix="/api/incidents", tags=["local-investigation"])


@router.post("/{incident_id}/investigate", response_model=InvestigationRunRead)
async def investigate_incident(incident_id: int, db: Session = Depends(get_db)) -> InvestigationRunRead:
    statement = select(Incident).where(Incident.id == incident_id).options(
        selectinload(Incident.security_events), selectinload(Incident.investigation_results),
    )
    incident = db.scalar(statement)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    detections = list(db.scalars(select(DetectionRecord).where(DetectionRecord.incident_id == incident_id)
        .options(selectinload(DetectionRecord.events))).all())
    settings = get_settings()
    client = OllamaClient(settings)
    agent = LocalInvestigationAgent(client)
    try:
        case_state = build_investigation_case_state(incident, detections)
        execution = await agent.run(case_state)
        analysis = execution.analysis
        verification = execution.verification
        if execution.status != "completed":
            return InvestigationRunRead(
                status="failed", model=settings.ollama_model, inference_used=True,
                error_message=execution.error_message,
                analysis=analysis, verification=verification,
                modules=[
                    PipelineModuleStatus(
                        module=item.module,
                        responsibility=item.responsibility,
                        method=item.method,
                        status="failed" if item.module == "independent_verification" else item.status,
                    )
                    for item in execution.modules
                ],
            )
        modules = execution.modules
        generated_at = execution.generated_at
    except (OllamaUnavailable, OllamaConfigurationError):
        return InvestigationRunRead(status="unavailable", model=settings.ollama_model,
            inference_used=False, error_message="Local Ollama is unavailable. Start Ollama and confirm the configured model is installed.",
            modules=pipeline_modules("unavailable", "failed"))
    except OllamaTimedOut:
        return InvestigationRunRead(status="failed", model=settings.ollama_model,
            inference_used=False, error_message="Local Ollama did not respond before the configured timeout.",
            modules=pipeline_modules("failed", "failed"))
    except (OllamaInvalidResponse, ValidationError):
        return InvestigationRunRead(status="failed", model=settings.ollama_model,
            inference_used=True, error_message="Local Ollama returned output that did not match the required investigation schema.",
            modules=pipeline_modules("failed", "failed"))

    result = InvestigationResult(
        incident_id=incident.id,
        agent_name=f"Local Ollama ({settings.ollama_model})",
        findings=analysis.model_dump_json(),
        confidence=None,
    )
    db.add(result)
    db.commit()
    db.refresh(result)
    return InvestigationRunRead(
        status="completed", model=settings.ollama_model, inference_used=True,
        investigation_result_id=result.id, generated_at=generated_at,
        analysis=analysis, verification=verification, modules=modules,
    )
