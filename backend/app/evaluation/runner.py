"""Run reproducible synthetic cases against existing local CyberSentinel services."""

import argparse
import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from app.agents.contracts import InvestigationCaseState
from app.agents.investigation import LocalInvestigationAgent, materialize_investigation_case
from app.agents.orchestrator import CentralOrchestrator
from app.agents.response_planning import DeterministicResponsePlanningAgent
from app.agents.tools import (
    EvidenceVerificationInput,
    IncidentDetectionsInput,
    run_alert_triage_tool,
    run_attack_lookup_tool,
    run_evidence_verification_tool,
    run_event_correlation_tool,
    run_risk_assessment_tool,
)
from app.core.config import Settings, get_settings
from app.evaluation.models import (
    SyntheticEvaluationCase,
    SyntheticEvaluationDataset,
    VerificationProbe,
)
from app.models import IncidentSeverity, IncidentStatus
from app.models.detection_record import DetectionRecord
from app.schemas.detections import DetectionHistoryRead
from app.schemas.incidents import IncidentRead, SecurityEventRead
from app.schemas.verification import (
    InvestigationClaimInput,
    ResponseRecommendationInput,
)
from app.security.detection import DetectionEvent, detect
from app.security.investigation_pipeline import verification_passes
from app.security.ollama import OllamaClient

DEFAULT_DATASET = Path(__file__).resolve().parents[2] / "evaluation" / "synthetic_cases.json"
DEFAULT_RESULTS = Path(__file__).resolve().parents[2] / "evaluation" / "results"
REFERENCE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
HIGH_IMPACT_ACTIONS = {
    "block_source_ip",
    "rate_limit_source_ip",
    "disable_account",
    "reset_password",
}
COUNT_ONLY_METRICS = {
    "detection_rule_exact_case_accuracy",
    "related_event_group_exact_accuracy",
    "expected_evidence_coverage",
    "detection_evidence_id_validity",
    "verification_supported_claim_rate",
    "verification_probe_exact_status_accuracy",
    "response_recommendation_safety_compliance",
}


def _evaluation_settings() -> Settings:
    return Settings(
        _env_file=None,
        ssh_bruteforce_threshold=4,
        ssh_bruteforce_window_seconds=300,
        ssh_bruteforce_exempt_usernames="automation1,automation2",
        ssh_success_failure_threshold=5,
        ssh_success_failure_window_seconds=600,
        ssh_invalid_user_threshold=3,
        ssh_invalid_user_window_seconds=300,
    )


def load_dataset(path: Path = DEFAULT_DATASET) -> SyntheticEvaluationDataset:
    with path.open("r", encoding="utf-8") as source:
        return SyntheticEvaluationDataset.model_validate(json.load(source))


def binary_detection_metrics(
    expected_positive: list[bool],
    predicted_positive: list[bool],
) -> dict[str, dict[str, Any]]:
    if len(expected_positive) != len(predicted_positive):
        raise ValueError("Expected and predicted detection labels must have equal lengths.")
    tp = sum(expected and predicted for expected, predicted in zip(expected_positive, predicted_positive))
    fp = sum(not expected and predicted for expected, predicted in zip(expected_positive, predicted_positive))
    fn = sum(expected and not predicted for expected, predicted in zip(expected_positive, predicted_positive))
    tn = sum(not expected and not predicted for expected, predicted in zip(expected_positive, predicted_positive))

    def metric(numerator: int, denominator: int, reason: str) -> dict[str, Any]:
        return {
            "value": numerator / denominator if denominator else None,
            "numerator": numerator,
            "denominator": denominator,
            "unavailable_reason": None if denominator else reason,
        }

    precision = metric(tp, tp + fp, "No cases were predicted positive.")
    recall = metric(tp, tp + fn, "The dataset contains no positive cases.")
    f1_denominator = 2 * tp + fp + fn
    f1 = metric(2 * tp, f1_denominator, "Neither expected nor predicted positive cases exist.")
    f1["value"] = (2 * tp / f1_denominator) if f1_denominator else None
    false_positive_rate = metric(fp, fp + tn, "The dataset contains no negative cases.")
    return {
        "detection_precision": precision,
        "detection_recall": recall,
        "detection_f1": f1,
        "false_positive_rate": false_positive_rate,
        "confusion_counts": {"true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn},
    }


def _build_state(case: SyntheticEvaluationCase) -> InvestigationCaseState:
    incident_id = 1
    events = [
        SecurityEventRead(
            id=item.id,
            incident_id=incident_id,
            event_type=item.event_type,
            description=item.description,
            source_ip=item.source_ip,
            timestamp=REFERENCE_TIME + timedelta(seconds=item.offset_seconds),
            raw_log=f"Synthetic evaluation event {item.id}",
            username=item.username,
            hostname=item.hostname,
        )
        for item in case.events
    ]
    incident = IncidentRead(
        id=incident_id,
        title=case.case_id.replace("-", " ").title(),
        description=case.description,
        severity=IncidentSeverity(case.incident_severity),
        status=IncidentStatus.OPEN,
        source_ip=case.source_ip,
        created_at=REFERENCE_TIME,
        updated_at=REFERENCE_TIME,
    )
    settings = _evaluation_settings()
    matches = detect(
        [
            DetectionEvent(
                id=event.id,
                event_type=event.event_type,
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                username=event.username,
                raw_log=event.raw_log,
            )
            for event in events
        ],
        {event.id for event in events},
        settings,
    )
    detections = [
        DetectionHistoryRead(
            id=index,
            rule_id=match.rule_id,
            rule_name=match.name,
            severity=match.severity,
            description=match.description,
            source_ip=match.source_ip,
            incident_id=incident_id,
            detected_at=max(
                event.timestamp for event in events
                if event.id in match.event_ids and event.timestamp is not None
            ),
            event_ids=list(match.event_ids),
        )
        for index, match in enumerate(matches, start=1)
    ]
    return InvestigationCaseState(incident=incident, events=events, detections=detections)


def _probe_claim(probe: VerificationProbe) -> InvestigationClaimInput:
    return InvestigationClaimInput(
        text=probe.text,
        claim_type=probe.claim_type,
        event_ids=probe.event_ids,
        source_ip=probe.source_ip,
        username=probe.username,
        hostname=probe.hostname,
        successful_login=probe.successful_login,
    )


def _response_input(item) -> ResponseRecommendationInput:
    return ResponseRecommendationInput(
        text=item.text,
        action_type=item.action_type,
        event_ids=item.event_ids,
        source_ip=item.source_ip,
        username=item.username,
        approval_status=item.approval_status,
    )


def _recommendation_output(item) -> dict[str, Any]:
    return item.model_dump(mode="json")


def _deterministic_case_output(case: SyntheticEvaluationCase, state: InvestigationCaseState) -> dict[str, Any]:
    incident, detections = materialize_investigation_case(state)
    tool_input = IncidentDetectionsInput(incident=incident, detections=detections)
    triage = run_alert_triage_tool(tool_input)
    correlation = run_event_correlation_tool(tool_input)
    attack = run_attack_lookup_tool(tool_input)
    risk = run_risk_assessment_tool(tool_input)
    state.risk_assessment = risk
    response = asyncio.run(DeterministicResponsePlanningAgent().run(state))
    evidence = list(incident.security_events)
    probe_results = run_evidence_verification_tool(EvidenceVerificationInput(
        evidence=evidence,
        claims=[_probe_claim(probe) for probe in case.verification_probes],
    ))
    probe_status_by_text = {
        item.text: item.status
        for item in probe_results.supported_claims + probe_results.unsupported_claims
    }
    response_checks = run_evidence_verification_tool(EvidenceVerificationInput(
        evidence=evidence,
        claims=[],
        recommendations=[_response_input(item) for item in response.recommendations],
    ))
    return {
        "workflow_status": "completed",
        "security_incident_detected": bool(state.detections),
        "detection_rules": [
            {"rule_id": item.rule_id, "event_ids": item.event_ids}
            for item in state.detections
        ],
        "triage_severity": triage.severity.value.lower(),
        "correlated_event_groups": [
            sorted(item.event_ids) for item in correlation.correlations
        ],
        "attack_mapping_ids": sorted(item.technique_id for item in attack.attack_mappings),
        "risk_category": risk.level.lower(),
        "detection_evidence_ids": sorted({
            event_id for detection in state.detections for event_id in detection.event_ids
        }),
        "probe_verification": [
            {
                "probe_id": probe.probe_id,
                "actual_status": probe_status_by_text[probe.text],
            }
            for probe in case.verification_probes
        ],
        "response_plan": {
            "actions_executed": response.actions_executed,
            "recommendations": [_recommendation_output(item) for item in response.recommendations],
            "verification_consistency": [
                item.consistency for item in response_checks.recommendations
            ],
        },
    }


def _complete_pipeline(case: SyntheticEvaluationCase, state: InvestigationCaseState) -> InvestigationCaseState:
    settings = get_settings()
    orchestrator = CentralOrchestrator(LocalInvestigationAgent(OllamaClient(settings)))
    return asyncio.run(orchestrator.run(state))


def _full_pipeline_output(
    case: SyntheticEvaluationCase,
    state: InvestigationCaseState,
) -> dict[str, Any]:
    evidence_ids = {event.id for event in state.events}
    output = {
        "workflow_status": state.status,
        "security_incident_detected": bool(state.detections),
        "workflow_error": state.error_message,
        "completed_agents": state.completed_agents,
        "detection_rules": [
            {"rule_id": item.rule_id, "event_ids": item.event_ids}
            for item in state.detections
        ],
        "correlated_event_groups": (
            [sorted(group.event_ids) for group in state.correlation.groups]
            if state.correlation is not None else None
        ),
        "attack_mapping_ids": (
            sorted(item.technique_id for item in state.threat_intelligence.attack_mappings)
            if state.threat_intelligence is not None else None
        ),
        "risk_category": state.risk_assessment.level.lower() if state.risk_assessment else None,
        "detection_evidence_ids": sorted({
            event_id for detection in state.detections for event_id in detection.event_ids
        }),
        "final_verification": state.verification.model_dump(mode="json") if state.verification else None,
        "final_verification_passes": verification_passes(state.verification) if state.verification else None,
        "response_plan": (
            {
                "actions_executed": state.response_plan.actions_executed,
                "recommendations": [_recommendation_output(item) for item in state.response_plan.recommendations],
            }
            if state.response_plan is not None else None
        ),
        "report_handoff": state.report is not None,
        "stored_event_ids": sorted(evidence_ids),
    }
    if state.response_plan is not None and state.verification is not None:
        consistency_by_text = {
            item.text: item.consistency
            for item in state.verification.recommendations
        }
        output["response_plan"]["verification_consistency"] = [
            consistency_by_text.get(item.text, "unsupported")
            for item in state.response_plan.recommendations
        ]
    return output


def _metric(value: float | None, numerator: int | float, denominator: int | float, reason: str | None = None):
    return {
        "value": value,
        "numerator": numerator,
        "denominator": denominator,
        "unavailable_reason": reason if value is None else None,
    }


def _calculate_metrics(
    cases: list[SyntheticEvaluationCase],
    results: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    expected_detections = [case.expected_security_incident for case in cases]
    predicted_detections = [
        bool(result["system_output"].get("security_incident_detected"))
        for result in results
    ]
    metrics: dict[str, Any] = binary_detection_metrics(expected_detections, predicted_detections)
    confusion = metrics["confusion_counts"]
    total_cases = sum(confusion.values())
    correct_cases = confusion["true_positive"] + confusion["true_negative"]
    metrics["detection_accuracy"] = _metric(
        correct_cases / total_cases if total_cases else None,
        correct_cases,
        total_cases,
        "The dataset contains no labeled cases.",
    )

    def categorical(name: str, expected, actual, unavailable: str):
        pairs = [(left, right) for left, right in zip(expected, actual) if right is not None]
        if not pairs:
            metrics[name] = _metric(None, 0, 0, unavailable)
        else:
            correct = sum(left == right for left, right in pairs)
            metrics[name] = _metric(correct / len(pairs), correct, len(pairs))

    categorical(
        "detection_rule_exact_case_accuracy",
        [set(case.expected_detection_rules) for case in cases],
        [
            {
                item["rule_id"]
                for item in (result["system_output"].get("detection_rules") or [])
            }
            for result in results
        ],
        "No case produced a detection-rule output.",
    )
    categorical(
        "attack_mapping_exact_case_accuracy",
        [set(case.expected_attack_mappings) for case in cases],
        [
            set(result["system_output"].get("attack_mapping_ids") or [])
            if result["system_output"].get("attack_mapping_ids") is not None else None
            for result in results
        ],
        "No case produced an ATT&CK mapping output.",
    )
    categorical(
        "severity_risk_category_accuracy",
        [case.expected_risk_category for case in cases],
        [result["system_output"].get("risk_category") for result in results],
        "No case produced a risk category.",
    )
    categorical(
        "related_event_group_exact_accuracy",
        [
            {tuple(sorted(group)) for group in case.expected_related_event_groups}
            for case in cases
        ],
        [
            {tuple(sorted(group)) for group in (result["system_output"].get("correlated_event_groups") or [])}
            if result["system_output"].get("correlated_event_groups") is not None else None
            for result in results
        ],
        "No case produced event-correlation output.",
    )

    required_ids = [
        event_id for case in cases for event_id in case.expected_evidence_ids
    ]
    observed_evidence_ids = {
        event_id
        for result in results
        for event_id in result["system_output"].get("detection_evidence_ids", [])
    }
    covered = sum(event_id in observed_evidence_ids for event_id in required_ids)
    metrics["expected_evidence_coverage"] = _metric(
        covered / len(required_ids) if required_ids else None,
        covered,
        len(required_ids),
        "The dataset defines no expected detection evidence IDs." if not required_ids else None,
    )
    evidence_refs = [
        event_id
        for result in results
        for detection in result["system_output"].get("detection_rules", [])
        for event_id in detection["event_ids"]
    ]
    stored_ids = {
        event.id for case in cases for event in case.events
    }
    valid_references = sum(event_id in stored_ids for event_id in evidence_refs)
    metrics["detection_evidence_id_validity"] = _metric(
        valid_references / len(evidence_refs) if evidence_refs else None,
        valid_references,
        len(evidence_refs),
        "No detection evidence IDs were emitted.",
    )

    probes = [
        (probe, actual)
        for result in results
        for probe, actual in zip(
            result["ground_truth"]["verification_probes"],
            result["system_output"].get("probe_verification") or [],
        )
    ]
    supported = [(probe, actual) for probe, actual in probes if probe["expected_status"] == "supported"]
    supported_correct = sum(item["actual_status"] == "supported" for _, item in supported)
    metrics["verification_supported_claim_rate"] = _metric(
        supported_correct / len(supported) if supported else None,
        supported_correct,
        len(supported),
        "The dataset contains no supported-claim probes.",
    )
    unsupported = [
        (probe, actual) for probe, actual in probes
        if probe["expected_status"] in {"unsupported", "contradicted"}
    ]
    unsupported_detected = sum(
        item["actual_status"] in {"unsupported", "contradicted"}
        for _, item in unsupported
    )
    metrics["unsupported_claim_detection_rate"] = _metric(
        unsupported_detected / len(unsupported) if unsupported else None,
        unsupported_detected,
        len(unsupported),
        "The dataset contains no unsupported or contradicted claim probes.",
    )
    exact_probe_status = sum(
        probe["expected_status"] == actual["actual_status"]
        for probe, actual in probes
    )
    metrics["verification_probe_exact_status_accuracy"] = _metric(
        exact_probe_status / len(probes) if probes else None,
        exact_probe_status,
        len(probes),
        "The dataset contains no verification probes.",
    )

    recommendations = [
        (case, result["system_output"].get("response_plan"))
        for case, result in zip(cases, results)
    ]
    recommendations = [
        (case, plan, recommendation, index)
        for case, plan in recommendations if plan is not None
        for index, recommendation in enumerate(plan["recommendations"])
    ]
    compliant = 0
    for case, plan, recommendation, index in recommendations:
        valid_case_ids = {event.id for event in case.events}
        actions_not_executed = (
            not plan["actions_executed"] and not recommendation["actions_executed"]
            if case.response_constraints.actions_must_not_execute
            else True
        )
        valid_evidence = (
            bool(recommendation["event_ids"])
            and set(recommendation["event_ids"]) <= valid_case_ids
            if case.response_constraints.evidence_ids_must_belong_to_case
            else True
        )
        approval_ok = (
            recommendation["requires_human_approval"]
            and recommendation["approval_status"] == "pending"
            if recommendation["action_type"] in HIGH_IMPACT_ACTIONS
            and case.response_constraints.high_impact_requires_pending_approval
            else True
        )
        consistency = (
            plan.get("verification_consistency", [])[index] == "consistent"
            if plan.get("verification_consistency") is not None
            and index < len(plan["verification_consistency"])
            else True
        )
        compliant += actions_not_executed and valid_evidence and approval_ok and consistency
    metrics["response_recommendation_safety_compliance"] = _metric(
        compliant / len(recommendations) if recommendations else None,
        compliant,
        len(recommendations),
        "No response recommendations were produced.",
    )
    definitions = {
        "detection_precision": "Correctly detected positive cases divided by all predicted-positive cases.",
        "detection_recall": "Correctly detected positive cases divided by all ground-truth positive cases.",
        "detection_f1": "Harmonic mean of case-level detection precision and recall.",
        "detection_accuracy": "Correctly classified cases (true positives plus true negatives) divided by all labeled cases.",
        "false_positive_rate": "False-positive cases divided by all ground-truth negative cases.",
        "detection_rule_exact_case_accuracy": "Cases whose complete deterministic rule-ID set exactly matches the ground-truth set.",
        "attack_mapping_exact_case_accuracy": "Cases whose complete ATT&CK technique-ID set exactly matches the reference set.",
        "severity_risk_category_accuracy": "Cases whose deterministic risk category matches the reference label.",
        "related_event_group_exact_accuracy": "Reference event groups exactly matched by correlation output.",
        "expected_evidence_coverage": "Expected event IDs included among detection evidence references.",
        "detection_evidence_id_validity": "Detection evidence references that point to an event in the synthetic dataset.",
        "verification_supported_claim_rate": "Supported evaluation probes returned as supported.",
        "unsupported_claim_detection_rate": "Unsupported/contradicted probes flagged as unsupported or contradicted.",
        "verification_probe_exact_status_accuracy": "Evaluation probes whose verifier status exactly matches the reference status.",
        "response_recommendation_safety_compliance": "Recommendations satisfying non-execution, event-reference, approval, and verifier-consistency constraints.",
    }
    for name, definition in definitions.items():
        metrics[name]["definition"] = definition
    return metrics


def _format_markdown(document: dict[str, Any]) -> str:
    lines = [
        "# CyberSentinel AI Synthetic Evaluation",
        "",
        f"- Dataset: `{document['dataset']['id']}` version `{document['dataset']['version']}`",
        f"- Cases: {document['dataset']['case_count']}",
        f"- Dataset SHA-256: `{document['dataset']['sha256']}`",
        "- Data: controlled synthetic cases only; no production database writes or external services.",
        "",
        "## Baselines and run status",
        "",
        "| Baseline | Status | Notes |",
        "|---|---|---|",
    ]
    for name, baseline in document["baselines"].items():
        lines.append(f"| {name} | {baseline['status']} | {baseline['notes']} |")
    for mode_name, mode in document["evaluations"].items():
        lines.extend(["", f"## {mode_name} metrics", ""])
        lines.append("| Metric | Value | Numerator / denominator | Definition | Availability note |")
        lines.append("|---|---:|---:|---|---|")
        for name, metric in mode["metrics"].items():
            if "value" not in metric:
                counts = ", ".join(f"{key}={value}" for key, value in metric.items())
                lines.append(f"| `{name}` | n/a | {counts} | Raw counts | |")
                continue
            if name in COUNT_ONLY_METRICS:
                value = "count only"
            else:
                value = "Unavailable" if metric["value"] is None else f"{metric['value']:.3f}"
            ratio = f"{metric['numerator']} / {metric['denominator']}"
            why = metric.get("unavailable_reason") or ""
            definition = metric.get("definition", "")
            lines.append(f"| `{name}` | {value} | {ratio} | {definition} | {why} |")
        lines.extend(["", "## Per-case outcomes", ""])
        lines.append("| Case | Ground truth labels | System output | Workflow / error |")
        lines.append("|---|---|---|---|")
        for result in mode["cases"]:
            gt = result["ground_truth"]
            output = result["system_output"]
            expected = ", ".join(gt["detection_rules"]) or "no detection"
            actual = ", ".join(item["rule_id"] for item in (output.get("detection_rules") or [])) or "no detection"
            expected_mappings = ", ".join(gt["attack_mapping_ids"]) or "none"
            actual_mappings = ", ".join(output.get("attack_mapping_ids") or []) or "none"
            probe_statuses = ", ".join(
                f"{item['probe_id']}={item['actual_status']}"
                for item in (output.get("probe_verification") or [])
            ) or "not run"
            plan = output.get("response_plan")
            recommendation_count = len(plan["recommendations"]) if plan else 0
            actions_executed = plan.get("actions_executed") if plan else None
            actual_status = output.get("workflow_status", "n/a")
            error = output.get("workflow_error") or ""
            ground_truth = (
                f"security_incident={gt['security_incident']}; rules={expected}; "
                f"risk={gt['risk_category']}; ATT&CK={expected_mappings}; "
                f"verification={', '.join(item['probe_id'] + ':' + item['expected_status'] for item in gt['verification_probes'])}"
            )
            system = (
                f"rules={actual}; risk={output.get('risk_category')}; "
                f"ATT&CK={actual_mappings}; probe statuses={probe_statuses}; "
                f"recommendations={recommendation_count}; actions_executed={actions_executed}"
            )
            lines.append(
                f"| `{result['case_id']}` | {ground_truth} | {system} | "
                f"{actual_status}; {error} |"
            )
        metrics = mode["metrics"]
        if "confusion_counts" in metrics:
            counts = metrics["confusion_counts"]
            lines.extend([
                "",
                "## Detection classification analysis",
                "",
                "| Outcome | Cases |",
                "|---|---:|",
                f"| True positives | {counts['true_positive']} |",
                f"| False positives | {counts['false_positive']} |",
                f"| False negatives | {counts['false_negative']} |",
                f"| True negatives | {counts['true_negative']} |",
                "",
                "Precision, recall, F1, accuracy, and false-positive rate are calculated against the authored `expected_security_incident` labels, not simply against whether a deterministic rule matched.",
                "Benign maintenance bursts that trigger a rule are labeled false positives; labeled low-and-slow attack cases below the configured threshold are labeled false negatives.",
            ])
    lines.extend([
        "",
        "## Metrics not calculated",
        "",
    ])
    for item in document["metrics_not_calculated"]:
        lines.append(f"- `{item['metric']}`: {item['reason']}")
    lines.extend([
        "",
        "## Interpretation and limitations",
        "",
        "- Ground-truth labels are authored in the synthetic dataset; they are not generated by the system.",
        "- System outputs are captured separately from ground truth. Metrics are calculated from those outputs and labels.",
        "- Verification claim rates are measured on explicit evaluation probes, not represented as LLM-generated claims.",
        "- ATT&CK accuracy is exact per-case mapping-set agreement against the bundled local SSH catalog.",
        "- Risk accuracy compares the existing deterministic severity category with the case label; it does not measure real-world impact.",
        "- Results describe only these synthetic SSH cases and do not demonstrate superiority over any baseline.",
        "- Integrity, fixture-conformance, and response-safety checks are reported as pass counts, not performance percentages. Safety constraints are safeguards to preserve, not scores to tune downward.",
        "- Single-LLM-only and multi-agent-without-verification baselines are not implemented and have no results.",
        "- The complete pipeline requires the configured local loopback Ollama service; an unrun or failed workflow is not a measured successful result.",
        "- For the complete pipeline, detection and risk inputs are precomputed by the same deterministic local services; their scores are not independent measurements of the LLM stages.",
        "- Complete-pipeline LLM claim quality, calibration, real-world response effectiveness, business impact, and asset criticality are not measured by this synthetic dataset.",
    ])
    return "\n".join(lines) + "\n"


def run_evaluation(
    dataset_path: Path = DEFAULT_DATASET,
    mode: Literal["deterministic", "complete", "both"] = "deterministic",
    result_dir: Path = DEFAULT_RESULTS,
    complete_pipeline_runner: Callable[
        [SyntheticEvaluationCase, InvestigationCaseState], InvestigationCaseState
    ] | None = None,
) -> dict[str, Any]:
    dataset = load_dataset(dataset_path)
    dataset_bytes = dataset_path.read_bytes()
    evaluations: dict[str, Any] = {}
    baseline_cases: list[dict[str, Any]] = []

    for case in dataset.cases:
        state = _build_state(case)
        ground_truth = {
            "description": case.description,
            "security_incident": case.expected_security_incident,
            "detection_rules": case.expected_detection_rules,
            "risk_category": case.expected_risk_category,
            "attack_mapping_ids": case.expected_attack_mappings,
            "expected_evidence_ids": case.expected_evidence_ids,
            "verification_probes": [
                {"probe_id": probe.probe_id, "expected_status": probe.expected_status}
                for probe in case.verification_probes
            ],
        }
        baseline_cases.append({
            "case_id": case.case_id,
            "ground_truth": ground_truth,
            "system_output": _deterministic_case_output(case, state),
        })
    if mode in {"deterministic", "both"}:
        evaluations["deterministic_baseline"] = {
            "status": "completed",
            "description": "Existing deterministic detection, local ATT&CK, risk, verification and response-planning services.",
            "cases": baseline_cases,
            "metrics": _calculate_metrics(dataset.cases, baseline_cases),
        }

    if mode in {"complete", "both"}:
        pipeline_runner = complete_pipeline_runner or _complete_pipeline
        full_cases = []
        for case, baseline_result in zip(dataset.cases, baseline_cases):
            state = _build_state(case)
            try:
                completed_state = pipeline_runner(case, state)
                output = _full_pipeline_output(case, completed_state)
            except Exception as error:
                output = {
                    "workflow_status": "error",
                    "security_incident_detected": bool(state.detections),
                    "workflow_error": f"{type(error).__name__}: {error}",
                    "detection_rules": [
                        {"rule_id": item.rule_id, "event_ids": item.event_ids}
                        for item in state.detections
                    ],
                    "correlated_event_groups": None,
                    "attack_mapping_ids": None,
                    "risk_category": None,
                    "detection_evidence_ids": baseline_result["system_output"]["detection_evidence_ids"],
                    "final_verification": None,
                    "final_verification_passes": None,
                    "response_plan": None,
                    "probe_verification": baseline_result["system_output"]["probe_verification"],
                }
            output["probe_verification"] = baseline_result["system_output"]["probe_verification"]
            full_cases.append({
                "case_id": case.case_id,
                "ground_truth": baseline_result["ground_truth"],
                "system_output": output,
            })
        evaluations["complete_pipeline"] = {
            "status": "completed" if all(
                case["system_output"]["workflow_status"] == "completed" for case in full_cases
            ) else "completed_with_failures",
            "description": "Production CentralOrchestrator with local Ollama investigation, executed in memory.",
            "cases": full_cases,
            "metrics": _calculate_metrics(dataset.cases, full_cases),
        }

    evaluation_settings = _evaluation_settings()
    document = {
        "schema_version": "1.0",
        "evaluation_parameters": {
            "ssh_bruteforce_threshold": evaluation_settings.ssh_bruteforce_threshold,
            "ssh_bruteforce_exempt_usernames": evaluation_settings.ssh_bruteforce_exempt_usernames,
            "ssh_bruteforce_window_seconds": evaluation_settings.ssh_bruteforce_window_seconds,
            "ssh_success_failure_threshold": evaluation_settings.ssh_success_failure_threshold,
            "ssh_invalid_user_threshold": evaluation_settings.ssh_invalid_user_threshold,
            "ssh_invalid_user_window_seconds": evaluation_settings.ssh_invalid_user_window_seconds,
            "ollama_execution_attempted": (
                mode in {"complete", "both"} and complete_pipeline_runner is None
            ),
            "database_writes": False,
            "external_services": False,
        },
        "dataset": {
            "id": dataset.dataset_id,
            "version": dataset.version,
            "case_count": len(dataset.cases),
            "sha256": hashlib.sha256(dataset_bytes).hexdigest(),
        },
        "baselines": {
            "A_deterministic_detection": {
                "status": "executed",
                "notes": "Existing deterministic security rules; results are in deterministic_baseline.",
            },
            "B_single_llm_investigation": {
                "status": "unavailable",
                "notes": "Not implemented as a separate evaluation baseline; no results fabricated.",
            },
            "C_multi_agent_without_verification": {
                "status": "unavailable",
                "notes": "Not implemented because it would require production workflow variants; no results fabricated.",
            },
            "D_complete_cybersentinel_pipeline": {
                "status": (
                    "executed" if "complete_pipeline" in evaluations
                    else "available_not_run"
                ),
                "notes": (
                    "Ran with production orchestrator and configured loopback Ollama."
                    if "complete_pipeline" in evaluations
                    else "Opt-in via --mode complete or --mode both; requires the configured local Ollama service."
                ),
            },
        },
        "evaluations": evaluations,
        "metrics_not_calculated": [
            {
                "metric": "single_llm_investigation_baseline_comparison",
                "reason": "A separate single-LLM baseline is not implemented.",
            },
            {
                "metric": "multi_agent_without_verification_baseline_comparison",
                "reason": "A verification-disabled production workflow variant is not implemented.",
            },
            {
                "metric": "complete_pipeline_llm_claim_quality",
                "reason": "No ground-truth labels exist for model interpretations; only explicit, separately labeled verifier probes are scored.",
            },
            {
                "metric": "local_rag_retrieval_relevance",
                "reason": "The dataset has no human relevance judgments for retrieved knowledge passages.",
            },
            {
                "metric": "real_world_detection_or_response_effectiveness",
                "reason": "The dataset contains only synthetic SSH cases and no executed response outcomes.",
            },
            {
                "metric": "business_impact_or_asset_criticality",
                "reason": "No such ground-truth fields exist in the synthetic cases or current system inputs.",
            },
        ],
    }
    result_dir.mkdir(parents=True, exist_ok=True)
    (result_dir / "evaluation.json").write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (result_dir / "evaluation.md").write_text(_format_markdown(document), encoding="utf-8")
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("deterministic", "complete", "both"),
        default="deterministic",
        help="The complete mode calls the configured local Ollama service.",
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    args = parser.parse_args()
    document = run_evaluation(args.dataset, args.mode, args.results)
    print(json.dumps(document, indent=2, ensure_ascii=False))
    print(f"\nWrote {args.results / 'evaluation.json'}")
    print(f"Wrote {args.results / 'evaluation.md'}")


if __name__ == "__main__":
    main()
