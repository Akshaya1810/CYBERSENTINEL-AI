import unittest
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import DetectionRecord, Incident, IncidentSeverity, IncidentStatus, SecurityEvent
from app.schemas.verification import InvestigationClaimInput, ResponseRecommendationInput
from app.security.reporting import build_incident_report
from app.security.verification import verify_investigation


class IncidentVerificationAndReportTests(unittest.TestCase):
    def test_real_database_event_ids_attack_mapping_and_unsupported_claim(self):
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
        stamp = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
        with Session(engine) as db:
            incident = Incident(title="SSH authentication investigation", description="Five failed SSH password attempts.",
                severity=IncidentSeverity.HIGH, status=IncidentStatus.OPEN, source_ip="203.0.113.70")
            incident.security_events = [SecurityEvent(event_type="ssh_authentication_failed",
                description=f"Failed SSH password attempt {index}.", source_ip="203.0.113.70",
                username=f"user{index}", timestamp=stamp, raw_log=f"synthetic ssh evidence {index}")
                for index in range(5)]
            db.add(incident)
            db.flush()
            detection = DetectionRecord(rule_id="SSH-AUTH-001", rule_name="SSH brute-force attempt",
                severity=IncidentSeverity.HIGH, description="Five failed attempts within five minutes.",
                source_ip="203.0.113.70", incident_id=incident.id, events=list(incident.security_events))
            db.add(detection)
            db.commit()

            stored_incident = db.scalar(select(Incident).where(Incident.id == incident.id))
            stored_detection = db.scalar(select(DetectionRecord).where(DetectionRecord.incident_id == incident.id))
            evidence_ids = {event.id for event in db.scalars(select(SecurityEvent).where(SecurityEvent.incident_id == incident.id))}
            report = build_incident_report(stored_incident, [stored_detection])
            self.assertEqual({event.id for event in report.timeline}, evidence_ids)
            self.assertEqual(set(report.detections[0].event_ids), evidence_ids)
            self.assertEqual({mapping.technique_id for mapping in report.attack_mappings}, {"T1110", "T1110.001"})
            self.assertTrue(all("Possible" in mapping.qualification for mapping in report.attack_mappings))

            verification = verify_investigation(stored_incident.security_events, [
                InvestigationClaimInput(text="Evidence supports source IP", event_ids=[min(evidence_ids)], source_ip="203.0.113.70"),
                InvestigationClaimInput(text="Unsupported account claim", event_ids=[999999], username="root"),
                InvestigationClaimInput(text="Unreferenced free text conclusion"),
            ])
            self.assertEqual(len(verification.supported_claims), 1)
            self.assertEqual(len(verification.unsupported_claims), 2)
            self.assertTrue(verification.missing_evidence)
            self.assertIn(verification.status, {"partially_verified", "unverified"})
        engine.dispose()

    def test_successful_login_contradiction_is_reported(self):
        event = SecurityEvent(id=4, incident_id=8, event_type="ssh_authentication_succeeded",
            description="Successful SSH login", source_ip="203.0.113.71", username="analyst",
            timestamp=datetime(2026, 9, 29, 10, 1, tzinfo=timezone.utc), raw_log="synthetic accepted password")
        result = verify_investigation([event], [InvestigationClaimInput(
            text="No successful authentication occurred", event_ids=[4], successful_login=False)])
        self.assertEqual(result.status, "contradicted")
        self.assertEqual(result.contradictions, ["No successful authentication occurred"])

    def test_recommendation_target_must_match_evidence_and_action_must_be_structured(self):
        event = SecurityEvent(id=7, incident_id=8, event_type="ssh_authentication_failed",
            description="Failed password", source_ip="203.0.113.72", username="analyst",
            timestamp=datetime(2026, 9, 29, 10, 1, tzinfo=timezone.utc), raw_log="synthetic failed password")
        result = verify_investigation([event], [], [
            ResponseRecommendationInput(text="Block unrelated IP", action_type="block_source_ip",
                event_ids=[7], source_ip="198.51.100.10"),
            ResponseRecommendationInput(text="Investigate the referenced records", action_type="review_logs", event_ids=[7]),
            ResponseRecommendationInput(text="Take action", action_type="other", event_ids=[7]),
        ])
        self.assertEqual([item.consistency for item in result.recommendations], ["unsupported", "consistent", "unverified"])


if __name__ == "__main__":
    unittest.main()
