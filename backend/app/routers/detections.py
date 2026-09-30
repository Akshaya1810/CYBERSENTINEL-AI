from pathlib import PurePath

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.db.dependencies import get_db
from app.models import DetectionRecord
from app.schemas.detections import (
    DetectionHistoryRead,
    DetectionResultRead,
    DetectionRuleRead,
    LogUploadRead,
    MalformedRecordRead,
)
from app.security.detection import active_rules
from app.security.ingestion import ingest_records
from app.security.parser import LogParseError, RecordLimitExceeded, parse_csv_text, parse_ssh_text

router = APIRouter(tags=["logs-and-detections"])
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_RECORDS = 10_000
MAX_RETURNED_ISSUES = 100
MAX_RETURNED_WARNINGS = 50


@router.post("/api/logs/upload", response_model=LogUploadRead, status_code=status.HTTP_200_OK)
async def upload_security_log(
    file: UploadFile = File(...), db: Session = Depends(get_db)
) -> LogUploadRead:
    filename = PurePath(file.filename or "").name
    extension = PurePath(filename).suffix.lower()
    if extension not in {".log", ".txt", ".csv"}:
        raise HTTPException(status_code=415, detail="Upload a .log, .txt, or .csv file.")
    contents = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Log upload exceeds the 5 MiB size limit.")
    try:
        text = contents.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=400, detail="Log files must use UTF-8 text encoding.") from error

    try:
        parsed = parse_csv_text(text, MAX_RECORDS) if extension == ".csv" else parse_ssh_text(text, MAX_RECORDS)
    except RecordLimitExceeded as error:
        raise HTTPException(status_code=413, detail=str(error)) from error
    except LogParseError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    stored_detections = ingest_records(parsed.records, db, get_settings())
    detections = [
        DetectionResultRead(
            id=item.record.id,
            rule_id=item.match.rule_id,
            rule_name=item.match.name,
            severity=item.match.severity,
            source_ip=item.match.source_ip,
            description=item.match.description,
            incident_id=item.incident_id,
            detected_at=item.record.detected_at,
            event_ids=list(item.match.event_ids),
            triggering_event_ids=list(item.match.triggering_event_ids),
        )
        for item in stored_detections
    ]
    return LogUploadRead(
        filename=filename,
        file_format="csv" if extension == ".csv" else "ssh",
        processed_records=len(parsed.records),
        rejected_records=len(parsed.malformed),
        malformed_records=[
            MalformedRecordRead(record_number=issue.record_number, reason=issue.reason)
            for issue in parsed.malformed[:MAX_RETURNED_ISSUES]
        ],
        warning_count=len(parsed.warnings),
        warnings=parsed.warnings[:MAX_RETURNED_WARNINGS],
        detections=detections,
    )


@router.get("/api/detections/rules", response_model=list[DetectionRuleRead])
def list_detection_rules() -> list[DetectionRuleRead]:
    settings = get_settings()
    return [DetectionRuleRead(**rule.__dict__) for rule in active_rules(settings)]


@router.get("/api/detections/history", response_model=list[DetectionHistoryRead])
def list_detection_history(db: Session = Depends(get_db)) -> list[DetectionHistoryRead]:
    records = db.scalars(
        select(DetectionRecord)
        .options(selectinload(DetectionRecord.events))
        .order_by(DetectionRecord.detected_at.desc(), DetectionRecord.id.desc())
        .limit(100)
    ).all()
    return [
        DetectionHistoryRead(
            id=record.id,
            rule_id=record.rule_id,
            rule_name=record.rule_name,
            severity=record.severity,
            description=record.description,
            source_ip=record.source_ip,
            incident_id=record.incident_id,
            detected_at=record.detected_at,
            event_ids=[event.id for event in record.events],
        )
        for record in records
    ]
