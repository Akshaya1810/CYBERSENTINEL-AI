# CyberSentinel AI Synthetic Evaluation

- Dataset: `cybersentinel-synthetic-ssh` version `1.0.0`
- Cases: 5
- Dataset SHA-256: `d22e0866da57f3e7a39f90965011eb03c0a5416cdcf80e7597d72742bf1a2684`
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
| `detection_precision` | 1.000 | 3 / 3 | Correctly detected positive cases divided by all predicted-positive cases. |  |
| `detection_recall` | 1.000 | 3 / 3 | Correctly detected positive cases divided by all ground-truth positive cases. |  |
| `detection_f1` | 1.000 | 6 / 6 | Harmonic mean of case-level detection precision and recall. |  |
| `false_positive_rate` | 0.000 | 0 / 2 | False-positive cases divided by all ground-truth negative cases. |  |
| `confusion_counts` | n/a | true_positive=3, false_positive=0, false_negative=0, true_negative=2 | Raw counts | |
| `detection_rule_exact_case_accuracy` | 1.000 | 5 / 5 | Cases whose complete deterministic rule-ID set exactly matches the ground-truth set. |  |
| `attack_mapping_exact_case_accuracy` | 1.000 | 5 / 5 | Cases whose complete ATT&CK technique-ID set exactly matches the reference set. |  |
| `severity_risk_category_accuracy` | 1.000 | 5 / 5 | Cases whose deterministic risk category matches the reference label. |  |
| `related_event_group_exact_accuracy` | 1.000 | 5 / 5 | Reference event groups exactly matched by correlation output. |  |
| `expected_evidence_coverage` | 1.000 | 13 / 13 | Expected event IDs included among detection evidence references. |  |
| `detection_evidence_id_validity` | 1.000 | 13 / 13 | Detection evidence references that point to an event in the synthetic dataset. |  |
| `verification_supported_claim_rate` | 1.000 | 5 / 5 | Supported evaluation probes returned as supported. |  |
| `unsupported_claim_detection_rate` | 1.000 | 2 / 2 | Unsupported/contradicted probes flagged as unsupported or contradicted. |  |
| `verification_probe_exact_status_accuracy` | 1.000 | 10 / 10 | Evaluation probes whose verifier status exactly matches the reference status. |  |
| `response_recommendation_safety_compliance` | 1.000 | 7 / 7 | Recommendations satisfying non-execution, event-reference, approval, and verifier-consistency constraints. |  |

## Per-case outcomes

| Case | Ground truth labels | System output | Workflow / error |
|---|---|---|---|
| `ssh-brute-force` | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification=recorded-failed-auth:supported, intent-is-hypothesis:unverified, unknown-evidence-id:unsupported | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=recorded-failed-auth=supported, intent-is-hypothesis=unverified, unknown-evidence-id=unsupported; recommendations=2; actions_executed=False | completed;  |
| `benign-ssh-authentication` | rules=no detection; risk=low; ATT&CK=none; verification=recorded-success:supported, contradicted-failure:contradicted | rules=no detection; risk=low; ATT&CK=none; probe statuses=recorded-success=supported, contradicted-failure=contradicted; recommendations=1; actions_executed=False | completed;  |
| `insufficient-failed-authentication` | rules=no detection; risk=medium; ATT&CK=none; verification=recorded-failure:supported, intent-remains-uncertain:unverified | rules=no detection; risk=medium; ATT&CK=none; probe statuses=recorded-failure=supported, intent-remains-uncertain=unverified; recommendations=1; actions_executed=False | completed;  |
| `related-invalid-user-events` | rules=SSH-AUTH-003; risk=medium; ATT&CK=none; verification=invalid-user-record:supported | rules=SSH-AUTH-003; risk=medium; ATT&CK=none; probe statuses=invalid-user-record=supported; recommendations=1; actions_executed=False | completed;  |
| `uncertain-repeated-failures` | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; verification=recorded-failure:supported, compromise-not-established:unverified | rules=SSH-AUTH-001; risk=high; ATT&CK=T1110, T1110.001; probe statuses=recorded-failure=supported, compromise-not-established=unverified; recommendations=2; actions_executed=False | completed;  |

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
- Single-LLM-only and multi-agent-without-verification baselines are not implemented and have no results.
- The complete pipeline requires the configured local loopback Ollama service; an unrun or failed workflow is not a measured successful result.
- For the complete pipeline, detection and risk inputs are precomputed by the same deterministic local services; their scores are not independent measurements of the LLM stages.
- Complete-pipeline LLM claim quality, calibration, real-world response effectiveness, business impact, and asset criticality are not measured by this synthetic dataset.
