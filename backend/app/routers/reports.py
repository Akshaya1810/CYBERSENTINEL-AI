from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.dependencies import get_db
from app.models import DetectionRecord, Incident
from app.schemas.reports import IncidentReportRead
from app.schemas.verification import VerificationReportRead, VerificationRequest
from app.security.reporting import build_incident_report, render_markdown
from app.security.verification import verify_investigation

router = APIRouter(prefix="/api/incidents", tags=["incident-reports-and-verification"])


def _load_report_data(db: Session, incident_id: int):
    incident = db.scalar(select(Incident).where(Incident.id == incident_id).options(
        selectinload(Incident.security_events), selectinload(Incident.investigation_results)))
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    detections = db.scalars(select(DetectionRecord).where(DetectionRecord.incident_id == incident_id)
        .options(selectinload(DetectionRecord.events)).order_by(DetectionRecord.detected_at)).all()
    return incident, list(detections)


@router.get("/{incident_id}/report", response_model=IncidentReportRead)
def incident_report(incident_id: int, db: Session = Depends(get_db)) -> IncidentReportRead:
    incident, detections = _load_report_data(db, incident_id)
    return build_incident_report(incident, detections)


@router.get("/{incident_id}/report.md", response_class=Response)
def download_incident_report(incident_id: int, db: Session = Depends(get_db)) -> Response:
    incident, detections = _load_report_data(db, incident_id)
    return Response(content=render_markdown(build_incident_report(incident, detections)),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}-report.md"'})


@router.post("/{incident_id}/verify", response_model=VerificationReportRead)
def verify_incident_submission(incident_id: int, payload: VerificationRequest,
                               db: Session = Depends(get_db)) -> VerificationReportRead:
    incident, _ = _load_report_data(db, incident_id)
    return verify_investigation(incident.security_events, payload.claims, payload.recommendations)
