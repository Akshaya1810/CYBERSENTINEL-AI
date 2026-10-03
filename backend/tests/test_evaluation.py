import json
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from app.evaluation.models import SyntheticEvaluationDataset
from app.evaluation.runner import (
    DEFAULT_DATASET,
    binary_detection_metrics,
    load_dataset,
    run_evaluation,
)


class EvaluationDatasetTests(unittest.TestCase):
    def test_synthetic_dataset_loads_and_has_expected_cases(self):
        dataset = load_dataset()

        self.assertEqual(dataset.dataset_id, "cybersentinel-synthetic-ssh")
        self.assertEqual(len(dataset.cases), 23)
        self.assertEqual(sum(case.expected_security_incident for case in dataset.cases), 13)
        self.assertEqual(sum(not case.expected_security_incident for case in dataset.cases), 10)

    def test_dataset_schema_rejects_expected_evidence_outside_case(self):
        raw = json.loads(DEFAULT_DATASET.read_text(encoding="utf-8"))
        raw["cases"][0]["expected_evidence_ids"] = [999999]

        with self.assertRaises(ValidationError):
            SyntheticEvaluationDataset.model_validate(raw)

    def test_dataset_schema_rejects_duplicate_event_ids_across_cases(self):
        raw = json.loads(DEFAULT_DATASET.read_text(encoding="utf-8"))
        raw["cases"][1]["events"][0]["id"] = raw["cases"][0]["events"][0]["id"]

        with self.assertRaises(ValidationError):
            SyntheticEvaluationDataset.model_validate(raw)


class EvaluationMetricTests(unittest.TestCase):
    def test_perfect_match_metrics(self):
        metrics = binary_detection_metrics(
            [True, True, False, False],
            [True, True, False, False],
        )

        self.assertEqual(metrics["detection_precision"]["value"], 1.0)
        self.assertEqual(metrics["detection_recall"]["value"], 1.0)
        self.assertEqual(metrics["detection_f1"]["value"], 1.0)
        self.assertEqual(metrics["false_positive_rate"]["value"], 0.0)

    def test_mismatched_labels_metrics(self):
        metrics = binary_detection_metrics(
            [True, False],
            [False, True],
        )

        self.assertEqual(metrics["detection_precision"]["value"], 0.0)
        self.assertEqual(metrics["detection_recall"]["value"], 0.0)
        self.assertEqual(metrics["detection_f1"]["value"], 0.0)
        self.assertEqual(metrics["false_positive_rate"]["value"], 1.0)

    def test_zero_positive_edge_case_marks_undefined_metrics_unavailable(self):
        metrics = binary_detection_metrics(
            [False, False],
            [False, False],
        )

        self.assertIsNone(metrics["detection_precision"]["value"])
        self.assertIsNotNone(metrics["detection_precision"]["unavailable_reason"])
        self.assertIsNone(metrics["detection_recall"]["value"])
        self.assertIsNone(metrics["detection_f1"]["value"])
        self.assertEqual(metrics["false_positive_rate"]["value"], 0.0)

    def test_label_lengths_must_match(self):
        with self.assertRaises(ValueError):
            binary_detection_metrics([True], [])


class EvaluationRunnerTests(unittest.TestCase):
    def test_deterministic_runner_evaluates_cases_and_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            results_dir = Path(temporary)
            document = run_evaluation(result_dir=results_dir)
            stored = json.loads((results_dir / "evaluation.json").read_text(encoding="utf-8"))
            markdown = (results_dir / "evaluation.md").read_text(encoding="utf-8")

        evaluation = document["evaluations"]["deterministic_baseline"]
        self.assertEqual(len(evaluation["cases"]), 23)
        self.assertEqual(stored["dataset"]["case_count"], 23)
        first_case = evaluation["cases"][0]
        self.assertIn("expected_status", first_case["ground_truth"]["verification_probes"][0])
        self.assertNotIn("expected_status", first_case["system_output"]["probe_verification"][0])
        self.assertIn("Ground-truth labels", markdown)
        self.assertIn("unsupported_claim_detection_rate", markdown)
        self.assertEqual(document["baselines"]["B_single_llm_investigation"]["status"], "unavailable")
        self.assertEqual(document["baselines"]["C_multi_agent_without_verification"]["status"], "unavailable")
        self.assertAlmostEqual(evaluation["metrics"]["detection_precision"]["value"], 12 / 14)
        self.assertAlmostEqual(evaluation["metrics"]["detection_recall"]["value"], 12 / 13)
        self.assertAlmostEqual(evaluation["metrics"]["detection_f1"]["value"], 24 / 27)
        self.assertAlmostEqual(evaluation["metrics"]["false_positive_rate"]["value"], 2 / 10)
        self.assertAlmostEqual(evaluation["metrics"]["detection_accuracy"]["value"], 20 / 23)
        self.assertEqual(evaluation["metrics"]["confusion_counts"], {
            "true_positive": 12,
            "false_positive": 2,
            "false_negative": 1,
            "true_negative": 8,
        })
        self.assertAlmostEqual(evaluation["metrics"]["severity_risk_category_accuracy"]["value"], 19 / 23)
        self.assertAlmostEqual(evaluation["metrics"]["attack_mapping_exact_case_accuracy"]["value"], 21 / 23)
        self.assertEqual(evaluation["metrics"]["detection_rule_exact_case_accuracy"]["value"], 1.0)
        self.assertEqual(evaluation["metrics"]["related_event_group_exact_accuracy"]["value"], 1.0)
        self.assertFalse(document["evaluation_parameters"]["ollama_execution_attempted"])
        self.assertTrue(document["metrics_not_calculated"])
        self.assertIn("Detection classification analysis", markdown)

    def test_evidence_verification_and_response_safety_metrics_are_calculated(self):
        with tempfile.TemporaryDirectory() as temporary:
            document = run_evaluation(result_dir=Path(temporary))

        metrics = document["evaluations"]["deterministic_baseline"]["metrics"]
        self.assertEqual(metrics["expected_evidence_coverage"]["value"], 1.0)
        self.assertEqual(metrics["detection_evidence_id_validity"]["value"], 1.0)
        self.assertEqual(metrics["verification_supported_claim_rate"]["value"], 1.0)
        self.assertAlmostEqual(metrics["unsupported_claim_detection_rate"]["value"], 3 / 5)
        self.assertAlmostEqual(metrics["verification_probe_exact_status_accuracy"]["value"], 11 / 13)
        self.assertEqual(metrics["response_recommendation_safety_compliance"]["value"], 1.0)

    def test_complete_runner_records_outputs_without_requiring_ollama_in_test(self):
        calls = []

        def simulated_pipeline(case, state):
            calls.append(case.case_id)
            state.status = "failed"
            state.error_message = "Test adapter intentionally did not run the LLM."
            return state

        with tempfile.TemporaryDirectory() as temporary:
            document = run_evaluation(
                mode="complete",
                result_dir=Path(temporary),
                complete_pipeline_runner=simulated_pipeline,
            )

        complete = document["evaluations"]["complete_pipeline"]
        self.assertEqual(len(calls), 23)
        self.assertEqual(complete["status"], "completed_with_failures")
        self.assertTrue(all(
            case["system_output"]["workflow_status"] == "failed"
            for case in complete["cases"]
        ))
        self.assertEqual(
            document["baselines"]["D_complete_cybersentinel_pipeline"]["status"],
            "executed",
        )
        self.assertFalse(document["evaluation_parameters"]["ollama_execution_attempted"])


if __name__ == "__main__":
    unittest.main()
