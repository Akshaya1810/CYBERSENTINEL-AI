# CyberSentinel AI Synthetic Evaluation

- Dataset: `cybersentinel-synthetic-ssh` version `1.3.0`
- Cases: 23
- Dataset SHA-256: `7417f30577c87b15a799fa6c23e54b43a0d0d46ed92ca31a8b2d23bd0414dc8d`
- Data: controlled synthetic cases only; no production database writes or external services.

## Baselines and run status

| Baseline | Status | Notes |
|---|---|---|
| A_deterministic_detection | executed | Existing deterministic security rules; results are in deterministic_baseline. |
| B_single_llm_investigation | unavailable | Not implemented as a separate evaluation baseline; no results fabricated. |
| C_multi_agent_without_verification | unavailable | Not implemented because it would require production workflow variants; no results fabricated. |
| D_complete_cybersentinel_pipeline | available_not_run | Opt-in via --mode complete or --mode both; requires the configured local Ollama service. |

## deterministic_baseline metrics

| Metric | Value | Numerator / denominator | Definition | Availability note |
|---|---:|---:|---|---|
| `detection_precision` | 0.857 | 12 / 14 | Correctly detected positive cases divided by all predicted-positive cases. |  |
| `detection_recall` | 0.923 | 12 / 13 | Correctly detected positive cases divided by all ground-truth positive cases. |  |
| `detection_f1` | 0.889 | 24 / 27 | Harmonic mean of case-level detection precision and recall. |  |
| `false_positive_rate` | 0.200 | 2 / 10 | False-positive cases divided by all ground-truth negative cases. |  |
| `confusion_counts` | n/a | true_positive=12, false_positive=2, false_negative=1, true_negative=8 | Raw counts | |
| `detection_accuracy` | 0.870 | 20 / 23 | Correctly classified cases (true positives plus true negatives) divided by all labeled cases. |  |
| `detection_rule_exact_case_accuracy` | count only | 23 / 23 | Cases whose complete deterministic rule-ID set exactly matches the ground-truth set. |  |
| `attack_mapping_exact_case_accuracy` | 0.913 | 21 / 23 | Cases whose complete ATT&CK technique-ID set exactly matches the reference set. |  |
| `severity_risk_category_accuracy` | 0.826 | 19 / 23 | Cases whose deterministic risk category matches the reference label. |  |
| `related_event_group_exact_accuracy` | count only | 23 / 23 | Reference event groups exactly matched by correlation output. |  |
| `expected_evidence_coverage` | count only | 63 / 63 | Expected event IDs included among detection evidence references. |  |
| `detection_evidence_id_validity` | count only | 63 / 63 | Detection evidence references that point to an event in the synthetic dataset. |  |
| `verification_supported_claim_rate` | count only | 5 / 5 | Supported evaluation probes returned as supported. |  |
| `unsupported_claim_detection_rate` | 0.600 | 3 / 5 | Unsupported/contradicted probes flagged as unsupported or contradicted. |  |
| `verification_probe_exact_status_accuracy` | count only | 11 / 13 | Evaluation probes whose verifier status exactly matches the reference status. |  |
| `response_recommendation_safety_compliance` | count only | 38 / 38 | Recommendations satisfying non-execution, event-reference, approval, and verifier-consistency constraints. |  |

## Per-case outcomes

| Case | Ground truth labels | System output | Workflow / error |
|---|---|---|---|
| `ssh-brute-force` | security_incident=True; rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification=recorded-failed-auth:supported, intent-is-hypothesis:unverified, unknown-evidence-id:unsupported | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=recorded-failed-auth=supported, intent-is-hypothesis=unverified, unknown-evidence-id=unsupported; recommendations=2; actions_executed=False | completed;  |
| `benign-ssh-authentication` | security_incident=False; rules=no detection; risk=low; ATT&CK=none; verification=recorded-success:supported, contradicted-failure:contradicted | rules=no detection; risk=low; ATT&CK=none; probe statuses=recorded-success=supported, contradicted-failure=contradicted; recommendations=1; actions_executed=False | completed;  |
| `insufficient-failed-authentication` | security_incident=False; rules=no detection; risk=medium; ATT&CK=none; verification=recorded-failure:supported, intent-remains-uncertain:unverified | rules=no detection; risk=medium; ATT&CK=none; probe statuses=recorded-failure=supported, intent-remains-uncertain=unverified; recommendations=1; actions_executed=False | completed;  |
| `related-invalid-user-events` | security_incident=True; rules=SSH-AUTH-003; risk=medium; ATT&CK=none; verification=invalid-user-record:supported | rules=SSH-AUTH-003; risk=medium; ATT&CK=none; probe statuses=invalid-user-record=supported; recommendations=1; actions_executed=False | completed;  |
| `uncertain-repeated-failures` | security_incident=True; rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification=recorded-failure:supported, compromise-not-established:unverified | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=recorded-failure=supported, compromise-not-established=unverified; recommendations=2; actions_executed=False | completed;  |
| `confirmed-attack-burst-1` | security_incident=True; rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification= | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `confirmed-attack-burst-2` | security_incident=True; rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification= | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `confirmed-attack-burst-3` | security_incident=True; rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification= | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `confirmed-attack-burst-4` | security_incident=True; rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification= | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `confirmed-attack-burst-5` | security_incident=True; rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification= | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `benign-maintenance-burst-1` | security_incident=False; rules=no detection; risk=low; ATT&CK=none; verification= | rules=no detection; risk=high; ATT&CK=none; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `benign-maintenance-burst-2` | security_incident=False; rules=no detection; risk=low; ATT&CK=none; verification= | rules=no detection; risk=high; ATT&CK=none; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `benign-maintenance-burst-3` | security_incident=False; rules=SSH-AUTH-001; risk=low; ATT&CK=none; verification= | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `benign-maintenance-burst-4` | security_incident=False; rules=SSH-AUTH-001; risk=low; ATT&CK=none; verification= | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `low-and-slow-attack-1` | security_incident=True; rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification= | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `low-and-slow-attack-2` | security_incident=True; rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification= | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `low-and-slow-attack-3` | security_incident=True; rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification= | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `low-and-slow-attack-4` | security_incident=True; rules=no detection; risk=high; ATT&CK=none; verification= | rules=no detection; risk=high; ATT&CK=none; probe statuses=not run; recommendations=2; actions_executed=False | completed;  |
| `confirmed-invalid-user-scan` | security_incident=True; rules=SSH-AUTH-003; risk=medium; ATT&CK=none; verification= | rules=SSH-AUTH-003; risk=medium; ATT&CK=none; probe statuses=not run; recommendations=1; actions_executed=False | completed;  |
| `routine-successful-login` | security_incident=False; rules=no detection; risk=low; ATT&CK=none; verification=successful-event-contradicts-failure-claim:contradicted | rules=no detection; risk=low; ATT&CK=none; probe statuses=successful-event-contradicts-failure-claim=contradicted; recommendations=1; actions_executed=False | completed;  |
| `isolated-failed-login` | security_incident=False; rules=no detection; risk=medium; ATT&CK=none; verification= | rules=no detection; risk=medium; ATT&CK=none; probe statuses=not run; recommendations=1; actions_executed=False | completed;  |
| `routine-mixed-logins` | security_incident=False; rules=no detection; risk=medium; ATT&CK=none; verification= | rules=no detection; risk=medium; ATT&CK=none; probe statuses=not run; recommendations=1; actions_executed=False | completed;  |
| `few-invalid-user-attempts` | security_incident=False; rules=no detection; risk=medium; ATT&CK=none; verification=invalid-user-is-not-password-failure-1:unsupported, invalid-user-is-not-password-failure-2:unsupported | rules=no detection; risk=medium; ATT&CK=none; probe statuses=invalid-user-is-not-password-failure-1=supported, invalid-user-is-not-password-failure-2=supported; recommendations=1; actions_executed=False | completed;  |

## Detection classification analysis

| Outcome | Cases |
|---|---:|
| True positives | 12 |
| False positives | 2 |
| False negatives | 1 |
| True negatives | 8 |

Precision, recall, F1, accuracy, and false-positive rate are calculated against the authored `expected_security_incident` labels, not simply against whether a deterministic rule matched.
Benign maintenance bursts that trigger a rule are labeled false positives; labeled low-and-slow attack cases below the configured threshold are labeled false negatives.

## Metrics not calculated

- `single_llm_investigation_baseline_comparison`: A separate single-LLM baseline is not implemented.
- `multi_agent_without_verification_baseline_comparison`: A verification-disabled production workflow variant is not implemented.
- `complete_pipeline_llm_claim_quality`: No ground-truth labels exist for model interpretations; only explicit, separately labeled verifier probes are scored.
- `local_rag_retrieval_relevance`: The dataset has no human relevance judgments for retrieved knowledge passages.
- `real_world_detection_or_response_effectiveness`: The dataset contains only synthetic SSH cases and no executed response outcomes.
- `business_impact_or_asset_criticality`: No such ground-truth fields exist in the synthetic cases or current system inputs.

## Interpretation and limitations

- Ground-truth labels are authored in the synthetic dataset; they are not generated by the system.
- System outputs are captured separately from ground truth. Metrics are calculated from those outputs and labels.
- Verification claim rates are measured on explicit evaluation probes, not represented as LLM-generated claims.
- ATT&CK accuracy is exact per-case mapping-set agreement against the bundled local SSH catalog.
- Risk accuracy compares the existing deterministic severity category with the case label; it does not measure real-world impact.
- Results describe only these synthetic SSH cases and do not demonstrate superiority over any baseline.
- Integrity, fixture-conformance, and response-safety checks are reported as pass counts, not performance percentages. Safety constraints are safeguards to preserve, not scores to tune downward.
- Single-LLM-only and multi-agent-without-verification baselines are not implemented and have no results.
- The complete pipeline requires the configured local loopback Ollama service; an unrun or failed workflow is not a measured successful result.
- For the complete pipeline, detection and risk inputs are precomputed by the same deterministic local services; their scores are not independent measurements of the LLM stages.
- Complete-pipeline LLM claim quality, calibration, real-world response effectiveness, business impact, and asset criticality are not measured by this synthetic dataset.
