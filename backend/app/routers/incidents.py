from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.dependencies import get_db
from app.models import Incident, IncidentSeverity, IncidentStatus, InvestigationResult, SecurityEvent
from app.schemas.incidents import (
    IncidentCreate,
    IncidentDetail,
    IncidentRead,
    IncidentUpdate,
    InvestigationResultCreate,
    InvestigationResultRead,
    SecurityEventCreate,
    SecurityEventRead,
)

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def get_incident_or_404(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    return incident


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db)) -> Incident:
    incident = Incident(**payload.model_dump())
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.get("", response_model=list[IncidentRead])
def list_incidents(db: Session = Depends(get_db)) -> list[Incident]:
    statement = select(Incident).order_by(Incident.created_at.desc(), Incident.id.desc())
    return list(db.scalars(statement).all())


@router.get("/{incident_id}", response_model=IncidentDetail)
def read_incident(incident_id: int, db: Session = Depends(get_db)) -> Incident:
    statement = (
        select(Incident)
        .where(Incident.id == incident_id)
        .options(selectinload(Incident.security_events), selectinload(Incident.investigation_results))
    )
    incident = db.scalar(statement)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    return incident


@router.patch("/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: int, payload: IncidentUpdate, db: Session = Depends(get_db)
) -> Incident:
    incident = get_incident_or_404(db, incident_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)
    db.commit()
    db.refresh(incident)
    return incident


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(incident_id: int, db: Session = Depends(get_db)) -> None:
    incident = get_incident_or_404(db, incident_id)
    db.delete(incident)
    db.commit()


@router.post(
    "/{incident_id}/events",
    response_model=SecurityEventRead,
    status_code=status.HTTP_201_CREATED,
)
def create_security_event(
    incident_id: int, payload: SecurityEventCreate, db: Session = Depends(get_db)
) -> SecurityEvent:
    get_incident_or_404(db, incident_id)
    event_data = payload.model_dump(exclude={"timestamp"})
    event = SecurityEvent(
        incident_id=incident_id,
        timestamp=payload.timestamp or datetime.now(timezone.utc),
        **event_data,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


@router.get("/{incident_id}/events", response_model=list[SecurityEventRead])
def list_security_events(incident_id: int, db: Session = Depends(get_db)) -> list[SecurityEvent]:
    get_incident_or_404(db, incident_id)
    statement = (
        select(SecurityEvent)
        .where(SecurityEvent.incident_id == incident_id)
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
    )
    return list(db.scalars(statement).all())


@router.post(
    "/{incident_id}/investigation-results",
    response_model=InvestigationResultRead,
    status_code=status.HTTP_201_CREATED,
)
def create_investigation_result(
    incident_id: int, payload: InvestigationResultCreate, db: Session = Depends(get_db)
) -> InvestigationResult:
    get_incident_or_404(db, incident_id)
    result = InvestigationResult(incident_id=incident_id, **payload.model_dump())
    db.add(result)
    db.commit()
    db.refresh(result)
    return result