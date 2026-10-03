"""Expand the authored SSH evaluation set with reproducible challenge cases."""

import json
from pathlib import Path

DATASET_PATH = Path(__file__).with_name("synthetic_cases.json")
ATTACK_MAPPINGS = ["T1110", "T1110.001"]
EVALUATION_EXEMPT_USERNAMES = {"automation1", "automation2"}


def _make_case(
    case_id: str,
    description: str,
    expected_security_incident: bool,
    severity: str,
    expected_risk_category: str,
    source_ip: str,
    event_types: list[str],
    base_event_id: int,
    username: str,
) -> dict:
    events = [
        {
            "id": base_event_id + index,
            "event_type": event_type,
            "offset_seconds": index * 20,
            "source_ip": source_ip,
            "username": username,
            "hostname": f"synthetic-{case_id[:12]}",
            "description": "Synthetic SSH authentication event.",
        }
        for index, event_type in enumerate(event_types)
    ]
    event_ids = [event["id"] for event in events]
    has_brute_force_match = (
        sum(event_type in {"ssh_authentication_failed", "ssh_invalid_user"} for event_type in event_types) >= 4
    )
    has_invalid_user_match = event_types.count("ssh_invalid_user") >= 3
    rules = (
        (["SSH-AUTH-001"] if has_brute_force_match and username.casefold() not in EVALUATION_EXEMPT_USERNAMES else [])
        + (["SSH-AUTH-003"] if has_invalid_user_match else [])
    )
    return {
        "case_id": case_id,
        "description": description,
        "expected_security_incident": expected_security_incident,
        "incident_severity": severity,
        "source_ip": source_ip,
        "events": events,
        "expected_detection_rules": rules,
        "expected_risk_category": expected_risk_category,
        "expected_attack_mappings": (
            ATTACK_MAPPINGS
            if "SSH-AUTH-001" in rules and expected_security_incident
            else []
        ),
        "expected_evidence_ids": event_ids if rules else [],
        "expected_related_event_groups": [event_ids] if rules else [],
        "verification_probes": [],
        "response_constraints": {
            "actions_must_not_execute": True,
            "high_impact_requires_pending_approval": True,
            "evidence_ids_must_belong_to_case": True,
        },
    }


def build_challenge_cases() -> list[dict]:
    failed = "ssh_authentication_failed"
    succeeded = "ssh_authentication_succeeded"
    cases = []

    for index in range(5):
        case_id = f"confirmed-attack-burst-{index + 1}"
        cases.append(_make_case(
            case_id=case_id,
            description=(
                "Synthetic benchmark-positive attack replay with five failed logins "
                "inside the rule window. The positive label is assigned by the "
                "controlled test scenario, not inferred from these log lines."
            ),
            expected_security_incident=True,
            severity="High",
            expected_risk_category="high",
            source_ip=f"198.51.100.{101 + index}",
            event_types=[failed] * 5,
            base_event_id=2101 + index * 10,
            username=f"service{index + 1}",
        ))

    for index in range(4):
        case_id = f"benign-maintenance-burst-{index + 1}"
        cases.append(_make_case(
            case_id=case_id,
            description=(
                "Synthetic benign maintenance or credential-rotation test with five "
                "failed logins. The first two named automation identities are "
                "explicitly allowlisted in the benchmark; the remaining identities "
                "are not allowlisted and remain alertable."
            ),
            expected_security_incident=False,
            severity="High",
            expected_risk_category="low",
            source_ip=f"203.0.113.{101 + index}",
            event_types=[failed] * 5,
            base_event_id=2201 + index * 10,
            username=f"automation{index + 1}",
        ))

    for index in range(4):
        case_id = f"low-and-slow-attack-{index + 1}"
        failure_count = 3 if index == 3 else 4
        cases.append(_make_case(
            case_id=case_id,
            description=(
                f"Synthetic benchmark-positive low-and-slow attack scenario with {failure_count} "
                f"failed logins. The configured threshold is four, so this case is "
                f"{'below threshold and expected to be missed' if failure_count < 4 else 'at threshold'}. "
                "The positive label is scenario ground truth; logs alone do not prove intent."
            ),
            expected_security_incident=True,
            severity="High",
            expected_risk_category="high",
            source_ip=f"192.0.2.{101 + index}",
            event_types=[failed] * failure_count,
            base_event_id=2301 + index * 10,
            username=f"account{index + 1}",
        ))

    cases.append(_make_case(
        case_id="confirmed-invalid-user-scan",
        description=(
            "Synthetic benchmark-positive scan for nonexistent SSH accounts. Three "
            "invalid-user events trigger the dedicated invalid-user rule."
        ),
        expected_security_incident=True,
        severity="Medium",
        expected_risk_category="medium",
        source_ip="198.51.100.111",
        event_types=["ssh_invalid_user"] * 3,
        base_event_id=2501,
        username="nonexistent",
    ))

    benign_cases = [
        ("routine-successful-login", [succeeded], "Low", "Routine successful SSH login."),
        ("isolated-failed-login", [failed], "Medium", "One failed login below all configured thresholds."),
        ("routine-mixed-logins", [succeeded, failed, succeeded], "Medium", "Routine mixed SSH activity below detection thresholds."),
        ("few-invalid-user-attempts", ["ssh_invalid_user"] * 2, "Medium", "Two invalid-user attempts below the configured threshold."),
    ]
    for index, (case_id, event_types, severity, description) in enumerate(benign_cases):
        invalid_user_case = _make_case(
            case_id=case_id,
            description=f"Synthetic benign negative control. {description}",
            expected_security_incident=False,
            severity=severity,
            expected_risk_category=severity.lower(),
            source_ip=f"192.0.2.{201 + index}",
            event_types=event_types,
            base_event_id=2401 + index * 10,
            username=f"operator{index + 1}",
        )
        if case_id == "few-invalid-user-attempts":
            invalid_user_case["verification_probes"] = [
                {
                    "probe_id": "invalid-user-is-not-password-failure-1",
                    "text": "The event confirms a failed password authentication.",
                    "claim_type": "fact",
                    "event_ids": [invalid_user_case["events"][0]["id"]],
                    "successful_login": False,
                    "expected_status": "unsupported",
                },
                {
                    "probe_id": "invalid-user-is-not-password-failure-2",
                    "text": "The event confirms another failed password authentication.",
                    "claim_type": "fact",
                    "event_ids": [invalid_user_case["events"][1]["id"]],
                    "successful_login": False,
                    "expected_status": "unsupported",
                },
            ]
        if case_id == "routine-successful-login":
            invalid_user_case["verification_probes"] = [
                {
                    "probe_id": "successful-event-contradicts-failure-claim",
                    "text": "The referenced SSH password login failed.",
                    "claim_type": "fact",
                    "event_ids": [invalid_user_case["events"][0]["id"]],
                    "successful_login": False,
                    "expected_status": "contradicted",
                }
            ]
        cases.append(invalid_user_case)
    return cases


def main() -> None:
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    original_labels = {
        "ssh-brute-force": True,
        "benign-ssh-authentication": False,
        "insufficient-failed-authentication": False,
        "related-invalid-user-events": True,
        "uncertain-repeated-failures": True,
    }
    base_cases = [
        case for case in dataset["cases"]
        if case["case_id"] in original_labels
    ]
    if len(base_cases) != len(original_labels):
        raise ValueError("Expected all five base cases in the dataset.")
    for case in base_cases:
        case["expected_security_incident"] = original_labels[case["case_id"]]
    dataset["cases"] = base_cases + build_challenge_cases()
    dataset["version"] = "1.3.0"
    dataset["description"] = (
        "Controlled synthetic SSH cases with positive attacks, benign threshold-crossing "
        "activity, low-and-slow attacks, and negative controls. Labels are authored "
        "scenario ground truth, not real-world measurements."
    )
    DATASET_PATH.write_text(json.dumps(dataset, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(dataset['cases'])} labeled cases to {DATASET_PATH}")


if __name__ == "__main__":
    main()
