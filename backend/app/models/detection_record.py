from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.enums import IncidentSeverity

detection_event_links = Table(
    "detection_event_links",
    Base.metadata,
    Column("detection_id", ForeignKey("detection_records.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", ForeignKey("security_events.id", ondelete="CASCADE"), primary_key=True),
)


class DetectionRecord(Base):
    __tablename__ = "detection_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(160), nullable=False)
    severity: Mapped[IncidentSeverity] = mapped_column(
        SAEnum(
            IncidentSeverity,
            name="detection_severity",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    incident: Mapped["Incident"] = relationship()
    events: Mapped[list["SecurityEvent"]] = relationship(secondary=detection_event_links)
