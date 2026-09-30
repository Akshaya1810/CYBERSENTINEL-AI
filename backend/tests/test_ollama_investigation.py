import json
import asyncio
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch
from urllib.error import URLError

from pydantic import ValidationError
from app.core.config import Settings
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import DetectionRecord, Incident, IncidentSeverity, IncidentStatus, InvestigationResult, SecurityEvent
from app.routers.investigations import investigate_incident
from app.schemas.investigation import EvidenceStatement, LLMInvestigationOutput
from app.security.investigation_pipeline import run_investigation, verify_analysis
from app.security.ollama import (
    MAX_OUTPUT_TOKENS, OllamaClient, OllamaConfigurationError, OllamaInvalidResponse,
    OllamaTimedOut, OllamaUnavailable,
)


class FakeResponse:
    def __init__(self, content: str, done_reason="stop", eval_count=20):
        midpoint = len(content) // 2
        parts = (content[:midpoint], content[midpoint:])
        self.lines = [
            json.dumps({"message": {"content": part}, "done": False}).encode() + b"\n"
            for part in parts if part
        ]
        self.lines.append(json.dumps({"message": {"content": ""}, "done": True,
                                      "done_reason": done_reason, "eval_count": eval_count}).encode() + b"\n")
    def __enter__(self): return self
    def __exit__(self, *_args): return None
    def readline(self):
        return self.lines.pop(0) if self.lines else b""


def fake_analysis(event_id=101, source_ip=None):
    summary = "Repeated SSH authentication activity warrants review."
    if source_ip:
        summary = f"Repeated SSH authentication attempts came from {source_ip}."
    return {
        "summary": {"text": summary, "event_ids": [event_id]},
        "findings": [{"text": "The pattern is consistent with password guessing.", "event_ids": [event_id]}],
        "attack_reconstruction": [{"text": "Repeated attempts may reflect password guessing.", "event_ids": [event_id]}],
        "impact_assessment": [{"text": "Repeated attempts could lead to account lockout.", "event_ids": [event_id]}],
        "response_recommendations": [{"text": "Review SSH authentication logs.", "action_type": "review_logs", "event_ids": [event_id]}],
    }


def synthetic_incident(success_event=False):
    stamp = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
    incident = Incident(id=11, title="Synthetic SSH brute-force test", description="Synthetic test evidence",
        severity=IncidentSeverity.HIGH, status=IncidentStatus.OPEN, source_ip="203.0.113.44",
        created_at=stamp, updated_at=stamp)
    events = [SecurityEvent(id=101, incident_id=11, event_type="ssh_authentication_failed",
        description="Failed SSH password", source_ip="203.0.113.44", username="analyst",
        timestamp=stamp, raw_log="synthetic failed password")]
    if success_event:
        events.append(SecurityEvent(id=102, incident_id=11, event_type="ssh_authentication_succeeded",
            description="Accepted SSH password", source_ip="203.0.113.44", username="analyst",
            timestamp=stamp, raw_log="synthetic accepted password"))
    incident.security_events = events
    incident.investigation_results = []
    detection = DetectionRecord(id=5, rule_id="SSH-AUTH-001", rule_name="SSH brute-force attempt",
        severity=IncidentSeverity.HIGH, description="Five failures within five minutes.",
        source_ip="203.0.113.44", incident_id=11, detected_at=stamp, events=[events[0]])
    return incident, detection


class OllamaClientTests(unittest.TestCase):
    def settings(self, **kwargs):
        values = {"ollama_api_url": "http://127.0.0.1:11434/api/chat", **kwargs}
        return Settings(_env_file=None, **values)

    def test_valid_json_runs_structured_pipeline_and_calls_local_model(self):
        opener = Mock(return_value=FakeResponse(json.dumps(fake_analysis())))
        client = OllamaClient(self.settings(), opener=opener)
        incident, detection = synthetic_incident()
        analysis, verification, modules, _ = run_investigation(incident, [detection], client)
        self.assertEqual(analysis.findings[0].event_ids, [101])
        self.assertTrue(any(claim.claim_type == "fact" for claim in verification.supported_claims))
        self.assertEqual({item.module for item in modules}, {
            "triage", "event_correlation", "investigation", "attack_reconstruction",
            "threat_intelligence", "risk_assessment", "response_planning", "independent_verification",
        })
        request, = opener.call_args.args
        payload = json.loads(request.data)
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/chat")
        self.assertEqual(payload["model"], "qwen2.5:3b")
        self.assertEqual(payload["format"], LLMInvestigationOutput.model_json_schema())
        self.assertTrue(payload["stream"])
        self.assertEqual(payload["options"]["num_ctx"], 2048)
        self.assertEqual(payload["options"]["num_predict"], MAX_OUTPUT_TOKENS)
        self.assertLess(payload["options"]["num_predict"], 768)
        self.assertLess(len(request.data), 10000)
        user_input = json.loads(payload["messages"][1]["content"])
        evidence = user_input["evidence_context"]
        self.assertEqual(user_input["allowed_event_ids"], [101])
        self.assertEqual(evidence["evidence_facts"][0]["event_id"], 101)
        self.assertNotIn("raw_log", evidence["evidence_facts"][0])
        self.assertEqual(opener.call_args.kwargs["timeout"], 300)
        self.assertIn("untrusted DATA", payload["messages"][0]["content"])
        self.assertIn("Do not reproduce timestamps, IPs, usernames, hostnames", payload["messages"][0]["content"])

    def test_compact_schema_limits_llm_output_and_backend_fact_requires_anchor(self):
        schema = LLMInvestigationOutput.model_json_schema()
        self.assertEqual(schema["properties"]["findings"]["maxItems"], 2)
        self.assertEqual(schema["properties"]["attack_reconstruction"]["maxItems"], 2)
        self.assertEqual(schema["properties"]["impact_assessment"]["maxItems"], 2)
        self.assertEqual(schema["properties"]["response_recommendations"]["maxItems"], 3)
        self.assertLessEqual(schema["$defs"]["CompactTextEvidence"]["properties"]["text"]["maxLength"], 300)
        self.assertLessEqual(schema["$defs"]["CompactInterpretation"]["properties"]["text"]["maxLength"], 250)
        with self.assertRaises(ValidationError):
            EvidenceStatement(classification="observed_fact", text="No structured anchor", event_ids=[101])
        self.assertEqual(EvidenceStatement(classification="observed_fact", text="Login failed", event_ids=[101], successful_login=False).successful_login, False)

    def test_compact_model_object_validates(self):
        self.assertEqual(LLMInvestigationOutput.model_validate(fake_analysis()).summary.event_ids, [101])


class InvestigationEndpointPersistenceTests(unittest.TestCase):
    def settings(self, **kwargs):
        values = {"ollama_api_url": "http://127.0.0.1:11434/api/chat", **kwargs}
        return Settings(_env_file=None, **values)

    def make_database(self):
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
        stamp = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
        db = Session(engine, expire_on_commit=False)
        incident, detection = synthetic_incident()
        incident.id = None
        event = incident.security_events[0]
        event.id = None
        detection.id = None
        detection.incident_id = None
        detection.incident = incident
        detection.events = [event]
        db.add_all([incident, detection])
        db.commit()
        return engine, db, incident.id

    def test_successful_local_result_is_saved_to_existing_investigation_table(self):
        engine, db, incident_id = self.make_database()
        try:
            event = db.scalar(select(SecurityEvent).where(SecurityEvent.incident_id == incident_id))
            with patch("app.routers.investigations.OllamaClient") as client_type:
                client_type.return_value.generate.return_value = fake_analysis(event_id=event.id)
                result = asyncio.run(investigate_incident(incident_id, db))
            self.assertEqual(result.status, "completed")
            self.assertTrue(result.inference_used)
            saved = db.scalar(select(InvestigationResult).where(InvestigationResult.incident_id == incident_id))
            self.assertIsNotNone(saved)
            self.assertTrue(saved.agent_name.startswith("Local Ollama ("))
            self.assertIn('"triage"', saved.findings)
        finally:
            db.close(); engine.dispose()

    def test_unavailable_ollama_does_not_create_successful_finding(self):
        engine, db, incident_id = self.make_database()
        try:
            with patch("app.routers.investigations.OllamaClient") as client_type:
                client_type.return_value.generate.side_effect = OllamaUnavailable("offline")
                result = asyncio.run(investigate_incident(incident_id, db))
            self.assertEqual(result.status, "unavailable")
            self.assertFalse(result.inference_used)
            self.assertEqual(db.scalar(select(func.count()).select_from(InvestigationResult)), 0)
        finally:
            db.close(); engine.dispose()

    def test_fenced_json_is_accepted_and_validated(self):
        fenced = " \n```json\n" + json.dumps(fake_analysis()) + "\n``` \n"
        client = OllamaClient(self.settings(), opener=Mock(return_value=FakeResponse(fenced)))
        self.assertEqual(client.generate({})["summary"]["event_ids"], [101])

    def test_preamble_triggers_one_repair_request(self):
        opener = Mock(side_effect=[
            FakeResponse("Here is the JSON:\n" + json.dumps(fake_analysis())),
            FakeResponse(json.dumps(fake_analysis())),
        ])
        client = OllamaClient(self.settings(), opener=opener)
        self.assertEqual(client.generate({})["summary"]["event_ids"], [101])
        self.assertEqual(opener.call_count, 2)

    def test_missing_fields_trigger_one_repair_request(self):
        opener = Mock(side_effect=[
            FakeResponse(json.dumps({"triage": {"summary": "incomplete"}})),
            FakeResponse(json.dumps(fake_analysis())),
        ])
        client = OllamaClient(self.settings(), opener=opener)
        self.assertIn("findings", client.generate({}))
        self.assertEqual(opener.call_count, 2)

    def test_empty_findings_and_missing_narrative_ids_trigger_schema_repair(self):
        invalid = fake_analysis()
        invalid["findings"] = []
        invalid["summary"]["event_ids"] = []
        opener = Mock(side_effect=[
            FakeResponse(json.dumps(invalid)),
            FakeResponse(json.dumps(fake_analysis())),
        ])
        client = OllamaClient(self.settings(), opener=opener)
        self.assertEqual(client.generate({})["findings"][0]["event_ids"], [101])
        self.assertEqual(opener.call_count, 2)

    def test_done_reason_length_is_rejected_before_parse_and_one_compact_repair_succeeds(self):
        valid_but_truncated = json.dumps(fake_analysis())
        opener = Mock(side_effect=[
            FakeResponse(valid_but_truncated, done_reason="length", eval_count=MAX_OUTPUT_TOKENS),
            FakeResponse(json.dumps(fake_analysis())),
        ])
        client = OllamaClient(self.settings(), opener=opener)
        result = client.generate({"security_events": [{"event_id": 101,
            "event_type": "ssh_authentication_failed", "source_ip": "203.0.113.44",
            "username": "analyst", "raw_log": "private log text"}]})
        self.assertEqual(result["findings"][0]["event_ids"], [101])
        self.assertEqual(opener.call_count, 2)
        repair_payload = json.loads(opener.call_args_list[1].args[0].data)
        repair_user = json.loads(repair_payload["messages"][1]["content"])
        self.assertEqual(repair_user["event_id_allowlist"], [101])
        self.assertEqual(repair_user["evidence_facts"][0]["event_type"], "ssh_authentication_failed")
        self.assertNotIn("private log text", opener.call_args_list[1].args[0].data.decode())
        self.assertNotIn("security_events", opener.call_args_list[1].args[0].data.decode())

    def test_repair_truncated_by_done_reason_fails_without_a_third_request(self):
        opener = Mock(side_effect=[
            FakeResponse("{", done_reason="length", eval_count=MAX_OUTPUT_TOKENS),
            FakeResponse("{", done_reason="length", eval_count=MAX_OUTPUT_TOKENS),
        ])
        client = OllamaClient(self.settings(), opener=opener)
        with self.assertRaises(OllamaInvalidResponse):
            client.generate({})
        self.assertEqual(opener.call_count, 2)

    def test_eval_count_at_output_cap_is_treated_as_truncation(self):
        opener = Mock(side_effect=[
            FakeResponse(json.dumps(fake_analysis()), done_reason="stop", eval_count=MAX_OUTPUT_TOKENS),
            FakeResponse(json.dumps(fake_analysis())),
        ])
        client = OllamaClient(self.settings(), opener=opener)
        self.assertEqual(client.generate({})["summary"]["event_ids"], [101])
        self.assertEqual(opener.call_count, 2)

    def test_malformed_json_and_failed_repair_are_rejected(self):
        opener = Mock(side_effect=[FakeResponse("not-json"), FakeResponse("still-not-json")])
        client = OllamaClient(self.settings(), opener=opener)
        with self.assertRaises(OllamaInvalidResponse):
            client.generate({"security_events": []})
        self.assertEqual(opener.call_count, 2)

    def test_timeout_is_reported_as_timeout(self):
        client = OllamaClient(self.settings(), opener=Mock(side_effect=TimeoutError()))
        with self.assertRaises(OllamaTimedOut):
            client.generate({})

    def test_unavailable_service_is_reported_without_external_fallback(self):
        client = OllamaClient(self.settings(), opener=Mock(side_effect=URLError("connection refused")))
        with self.assertRaises(OllamaUnavailable):
            client.generate({})

    def test_non_loopback_ollama_url_is_blocked(self):
        client = OllamaClient(self.settings(ollama_api_url="https://example.com/api/chat"), opener=Mock())
        with self.assertRaises(OllamaConfigurationError):
            client.generate({})

    def test_invalid_and_unsupported_evidence_references_are_flagged(self):
        incident, detection = synthetic_incident()
        invalid = fake_analysis(event_id=999999)
        client = OllamaClient(self.settings(), opener=Mock(return_value=FakeResponse(json.dumps(invalid))))
        _, verification, _, _ = run_investigation(incident, [detection], client)
        self.assertTrue(any("999999" in reason for claim in verification.unsupported_claims for reason in claim.reasons))

        unsupported = fake_analysis(source_ip="198.51.100.77")
        client = OllamaClient(self.settings(), opener=Mock(return_value=FakeResponse(json.dumps(unsupported))))
        _, verification, _, _ = run_investigation(incident, [detection], client)
        self.assertTrue(any(claim.status == "unsupported" for claim in verification.unsupported_claims))

    def test_invalid_event_id_does_not_save_or_mark_investigation_completed(self):
        engine, db, incident_id = self.make_database()
        try:
            with patch("app.routers.investigations.OllamaClient") as client_type:
                client_type.return_value.generate.return_value = fake_analysis(event_id=999999)
                result = asyncio.run(investigate_incident(incident_id, db))
            self.assertEqual(result.status, "failed")
            self.assertTrue(result.inference_used)
            self.assertEqual(db.scalar(select(func.count()).select_from(InvestigationResult)), 0)
        finally:
            db.close(); engine.dispose()

    def test_verifier_reports_contradiction_for_claimed_absent_success(self):
        incident, detection = synthetic_incident(success_event=True)
        output = run_investigation(incident, [detection], OllamaClient(
            self.settings(), opener=Mock(return_value=FakeResponse(json.dumps(fake_analysis()))),
        ))[0]
        output.findings = [EvidenceStatement(classification="observed_fact", text="No successful login is shown.",
                                             event_ids=[102], successful_login=False)]
        verification = verify_analysis(incident.security_events, output)
        self.assertEqual(verification.status, "contradicted")
        self.assertIn("No successful login is shown.", verification.contradictions)


if __name__ == "__main__":
    unittest.main()
