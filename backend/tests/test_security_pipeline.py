import unittest
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.session import Base
from app.models import DetectionRecord, Incident, IncidentSeverity, IncidentStatus, SecurityEvent
from app.security.detection import (
    BRUTE_FORCE_RULE_ID,
    INVALID_USER_RULE_ID,
    SUCCESS_AFTER_FAILURES_RULE_ID,
    DetectionEvent,
    active_rules,
    detect,
)
from app.security.parser import (
    SSH_FAILED,
    SSH_INVALID_USER,
    SSH_SUCCEEDED,
    parse_csv_text,
    parse_ssh_text,
    ParsedLogRecord,
)
from app.security.ingestion import ingest_records


class LogParserTests(unittest.TestCase):
    def test_parses_supported_ssh_authentication_types_and_evidence(self):
        log = "\n".join([
            "2026-09-29T10:00:00Z edge-1 sshd[100]: Failed password for alice from 203.0.113.8 port 2200 ssh2",
            "2026-09-29T10:00:01Z edge-1 sshd[101]: Accepted password for alice from 203.0.113.8 port 2200 ssh2",
            "2026-09-29T10:00:02Z edge-1 sshd[102]: Invalid user guest from 203.0.113.8 port 2200",
        ])
        parsed = parse_ssh_text(log)
        self.assertEqual([item.event_type for item in parsed.records], [SSH_FAILED, SSH_SUCCEEDED, SSH_INVALID_USER])
        self.assertEqual(parsed.records[0].username, "alice")
        self.assertEqual(parsed.records[0].hostname, "edge-1")
        self.assertEqual(parsed.records[0].source_ip, "203.0.113.8")
        self.assertIn("Failed password", parsed.records[0].raw_log)
        self.assertFalse(parsed.malformed)

    def test_malformed_ssh_ip_is_reported_and_unknown_line_is_not_threat(self):
        parsed = parse_ssh_text("Failed password for user from not-an-ip port 22 ssh2\nsshd: Server listening on 0.0.0.0 port 22")
        self.assertEqual(len(parsed.malformed), 1)
        self.assertEqual(parsed.records[0].event_type, "ssh_unclassified")

    def test_csv_header_case_variations_and_missing_timestamp(self):
        parsed = parse_csv_text(
            "Event Type,Source IP,User,Host,Description,Raw Log\n"
            'FAILED PASSWORD,203.0.113.9,alice,edge-2,auth failed,"line 1, evidence"\n'
        )
        self.assertEqual(len(parsed.records), 1)
        self.assertEqual(parsed.records[0].event_type, SSH_FAILED)
        self.assertEqual(parsed.records[0].timestamp, None)
        self.assertEqual(parsed.records[0].username, "alice")
        self.assertEqual(parsed.records[0].hostname, "edge-2")
        self.assertIn("line 1, evidence", parsed.records[0].raw_log)

    def test_csv_preserves_original_row_when_no_raw_log_column(self):
        parsed = parse_csv_text('event_type,source_ip,description\nlogin,203.0.113.3,"text, with comma"\n')
        self.assertIn('"text, with comma"', parsed.records[0].raw_log)

    def test_oversized_csv_field_is_reported_as_malformed(self):
        parsed = parse_csv_text("event_type,description\nlogin," + ("x" * 140_000))
        self.assertEqual(len(parsed.records), 0)
        self.assertEqual(len(parsed.malformed), 1)


class DeterministicRuleTests(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(_env_file=None)
        self.start = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)

    def event(self, event_id, event_type, seconds, username="analyst", ip="203.0.113.25"):
        return DetectionEvent(event_id, event_type, self.start + timedelta(seconds=seconds), ip, username, "synthetic test evidence")

    def test_brute_force_threshold_and_window(self):
        three = [self.event(i, SSH_FAILED, i) for i in range(1, 4)]
        self.assertEqual(detect(three, {3}, self.settings), [])
        four = three + [self.event(4, SSH_FAILED, 4)]
        matches = detect(four, {4}, self.settings)
        self.assertEqual([match.rule_id for match in matches], [BRUTE_FORCE_RULE_ID])
        self.assertEqual(len(matches[0].event_ids), 4)
        outside = [self.event(i, SSH_FAILED, i * 101) for i in range(1, 5)]
        self.assertEqual(detect(outside, {4}, self.settings), [])

    def test_bruteforce_username_allowlist_requires_every_window_event_to_match(self):
        settings = Settings(_env_file=None, ssh_bruteforce_exempt_usernames="Automation, deploy")
        trusted = [
            self.event(i, SSH_FAILED, i, username="automation")
            for i in range(1, 5)
        ]
        self.assertEqual(detect(trusted, {4}, settings), [])

        mixed = trusted[:-1] + [self.event(4, SSH_FAILED, 4, username="admin")]
        self.assertIn(
            BRUTE_FORCE_RULE_ID,
            [match.rule_id for match in detect(mixed, {4}, settings)],
        )

    def test_allowlist_does_not_suppress_success_after_failures(self):
        settings = Settings(_env_file=None, ssh_bruteforce_exempt_usernames="automation")
        failures = [
            self.event(i, SSH_FAILED, i * 10, username="automation")
            for i in range(1, 6)
        ]
        success = self.event(6, SSH_SUCCEEDED, 60, username="automation")
        rules = [match.rule_id for match in detect(failures + [success], {6}, settings)]
        self.assertIn(SUCCESS_AFTER_FAILURES_RULE_ID, rules)
        self.assertNotIn(BRUTE_FORCE_RULE_ID, rules)

    def test_success_after_repeated_failures_requires_preceding_window(self):
        failures = [self.event(i, SSH_FAILED, i * 20) for i in range(1, 6)]
        success = self.event(6, SSH_SUCCEEDED, 110)
        matches = detect(failures + [success], {6}, self.settings)
        self.assertIn(SUCCESS_AFTER_FAILURES_RULE_ID, [match.rule_id for match in matches])
        too_old = [self.event(i, SSH_FAILED, i * 150) for i in range(1, 6)] + [self.event(6, SSH_SUCCEEDED, 1000)]
        self.assertNotIn(SUCCESS_AFTER_FAILURES_RULE_ID, [m.rule_id for m in detect(too_old, {6}, self.settings)])

    def test_invalid_user_threshold_and_rule_configuration(self):
        attempts = [self.event(i, SSH_INVALID_USER, i, username=f"missing{i}") for i in range(1, 4)]
        matches = detect(attempts, {3}, self.settings)
        self.assertIn(INVALID_USER_RULE_ID, [match.rule_id for match in matches])
        rules = {rule.rule_id: rule for rule in active_rules(self.settings)}
        self.assertEqual(rules[BRUTE_FORCE_RULE_ID].threshold, 4)
        self.assertEqual(rules[BRUTE_FORCE_RULE_ID].window_seconds, 300)


class IngestionPersistenceTests(unittest.TestCase):
    def test_detection_creates_one_incident_and_groups_repeat_uploads(self):
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
        settings = Settings(_env_file=None)
        start = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
        first_batch = [
            ParsedLogRecord(
                event_type=SSH_FAILED,
                description=f"Failed SSH login attempt {number}.",
                timestamp=start + timedelta(seconds=number),
                source_ip="203.0.113.80",
                username=f"user{number}",
                hostname="test-host",
                raw_log=f"synthetic log line {number}",
                source_line=number,
            )
            for number in range(1, 6)
        ]
        with Session(engine, autoflush=False, expire_on_commit=False) as db:
            first = ingest_records(first_batch, db, settings)
            self.assertEqual(len(first), 1)
            self.assertEqual(first[0].match.rule_id, BRUTE_FORCE_RULE_ID)
            self.assertEqual(first[0].record.incident_id, first[0].incident_id)
            self.assertEqual(db.scalar(select(func.count()).select_from(Incident)), 1)
            self.assertEqual(db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.incident_id == first[0].incident_id)), 5)
            self.assertEqual(db.scalar(select(func.count()).select_from(DetectionRecord)), 1)
            db.commit()

            repeat = ParsedLogRecord(
                event_type=SSH_FAILED,
                description="Failed SSH login attempt six.",
                timestamp=start + timedelta(seconds=6),
                source_ip="203.0.113.80",
                username="user6",
                hostname="test-host",
                raw_log="synthetic log line six",
                source_line=6,
            )
            second = ingest_records([repeat], db, settings)
            self.assertEqual(len(second), 1)
            self.assertEqual(second[0].incident_id, first[0].incident_id)
            self.assertEqual(db.scalar(select(func.count()).select_from(Incident)), 1)
            self.assertEqual(db.scalar(select(func.count()).select_from(DetectionRecord)), 1)
            self.assertEqual(db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.incident_id == first[0].incident_id)), 6)
            incident = db.get(Incident, first[0].incident_id)
            self.assertEqual(incident.status, IncidentStatus.OPEN)
            self.assertEqual(incident.severity, IncidentSeverity.HIGH)
            unknown_time = ParsedLogRecord(
                event_type="csv_event",
                description="Timestamp intentionally omitted.",
                timestamp=None,
                source_ip="203.0.113.81",
                username=None,
                hostname=None,
                raw_log="csv row without timestamp",
                source_line=1,
            )
            db.commit()
            self.assertEqual(ingest_records([unknown_time], db, settings), [])
            stored_unknown_time = db.scalar(select(SecurityEvent).where(SecurityEvent.raw_log == unknown_time.raw_log))
            self.assertIsNone(stored_unknown_time.timestamp)
            self.assertIsNone(stored_unknown_time.incident_id)
        engine.dispose()


if __name__ == "__main__":
    unittest.main()
