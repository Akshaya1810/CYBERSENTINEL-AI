import unittest
from datetime import datetime, timezone

from app.agents.tools import (
    EvidenceVerificationInput,
    IncidentDetectionsInput,
    IncidentReportInput,
    LocalKnowledgeToolInput,
    run_alert_triage_tool,
    run_attack_lookup_tool,
    run_event_correlation_tool,
    run_evidence_verification_tool,
    run_incident_report_tool,
    run_local_rag_tool,
    run_risk_assessment_tool,
)
from app.models import DetectionRecord, Incident, IncidentSeverity, IncidentStatus, SecurityEvent
from app.schemas.verification import InvestigationClaimInput


class AgentToolTests(unittest.TestCase):
    def setUp(self):
        timestamp = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
        self.incident = Incident(
            id=12,
            title="SSH authentication investigation",
            description="Repeated failed SSH password attempts.",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.OPEN,
            source_ip="203.0.113.70",
            created_at=timestamp,
            updated_at=timestamp,
        )
        self.incident.security_events = [
            SecurityEvent(
                id=event_id,
                incident_id=self.incident.id,
                event_type="ssh_authentication_failed",
                description="Failed SSH password attempt.",
                source_ip="203.0.113.70",
                username="analyst",
                hostname="host-a",
                timestamp=timestamp,
                raw_log="synthetic failed SSH login",
            )
            for event_id in range(101, 106)
        ]
        self.detection = DetectionRecord(
            id=22,
            rule_id="SSH-AUTH-001",
            rule_name="SSH brute-force attempt",
            severity=IncidentSeverity.HIGH,
            description="Repeated failed SSH password authentications.",
            source_ip="203.0.113.70",
            incident_id=self.incident.id,
            detected_at=timestamp,
            events=list(self.incident.security_events),
        )
        self.inputs = IncidentDetectionsInput(self.incident, [self.detection])

    def test_triage_and_risk_tools_reuse_deterministic_results(self):
        triage = run_alert_triage_tool(self.inputs)
        risk = run_risk_assessment_tool(self.inputs)

        self.assertEqual(triage.severity, IncidentSeverity.HIGH)
        self.assertIn("Recorded 5 security events", triage.summary.summary)
        self.assertEqual(triage.summary.event_ids, [101, 102, 103, 104, 105])
        self.assertEqual(risk.level, "high")
        self.assertIn("SSH brute-force attempt", risk.rationale)

    def test_event_correlation_exposes_detection_event_links(self):
        result = run_event_correlation_tool(self.inputs)

        self.assertEqual(result.incident_id, self.incident.id)
        self.assertEqual(len(result.correlations), 1)
        self.assertEqual(result.correlations[0].rule_id, "SSH-AUTH-001")
        self.assertEqual(result.correlations[0].event_ids, [101, 102, 103, 104, 105])

    def test_attack_lookup_uses_local_evidence_qualified_catalog(self):
        result = run_attack_lookup_tool(self.inputs)

        self.assertEqual(
            {item.technique_id for item in result.attack_mappings},
            {"T1110", "T1110.001"},
        )
        self.assertTrue(all("Possible" in item.qualification for item in result.attack_mappings))

    def test_local_rag_output_remains_separate_from_evidence(self):
        result = run_local_rag_tool(LocalKnowledgeToolInput(query="T1110"))

        self.assertTrue(result.retrieved_context)
        self.assertEqual(result.retrieved_context[0].id, "T1110")
        self.assertFalse(hasattr(result.retrieved_context[0], "event_ids"))
        self.assertFalse(hasattr(result.retrieved_context[0], "source_ip"))

    def test_verification_tool_delegates_to_authoritative_verifier(self):
        result = run_evidence_verification_tool(EvidenceVerificationInput(
            evidence=self.incident.security_events,
            claims=[InvestigationClaimInput(
                text="Source address is recorded",
                event_ids=[101],
                source_ip="203.0.113.70",
            )],
        ))

        self.assertEqual(result.status, "verified")
        self.assertEqual(len(result.supported_claims), 1)

    def test_report_tool_builds_existing_incident_report(self):
        result = run_incident_report_tool(IncidentReportInput(
            incident=self.incident,
            detections=[self.detection],
        ))

        self.assertEqual(result.incident.id, self.incident.id)
        self.assertEqual(len(result.timeline), 5)
        self.assertEqual(
            {item.technique_id for item in result.attack_mappings},
            {"T1110", "T1110.001"},
        )
        self.assertEqual(result.verification.status, "verified")


if __name__ == "__main__":
    unittest.main()
