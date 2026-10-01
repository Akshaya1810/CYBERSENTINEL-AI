import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import evaluation


class EvaluationResultsEndpointTests(unittest.TestCase):
    def test_returns_stored_json_without_running_evaluation(self):
        expected = {
            "dataset": {"id": "test-evaluation", "case_count": 1},
            "evaluations": {"deterministic_baseline": {"metrics": {}}},
        }
        with tempfile.TemporaryDirectory() as temporary:
            result_path = Path(temporary) / "evaluation.json"
            result_path.write_text(json.dumps(expected), encoding="utf-8")
            with patch.object(evaluation, "EVALUATION_RESULTS_PATH", result_path):
                response = evaluation.evaluation_results()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body), expected)

    def test_missing_result_returns_clear_404(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.json"
            with patch.object(evaluation, "EVALUATION_RESULTS_PATH", missing):
                with self.assertRaises(HTTPException) as raised:
                    evaluation.evaluation_results()

        self.assertEqual(raised.exception.status_code, 404)
        self.assertIn("Run the local evaluation first", raised.exception.detail)

    def test_malformed_json_returns_safe_500(self):
        with tempfile.TemporaryDirectory() as temporary:
            result_path = Path(temporary) / "evaluation.json"
            result_path.write_text("{invalid", encoding="utf-8")
            with patch.object(evaluation, "EVALUATION_RESULTS_PATH", result_path):
                with self.assertRaises(HTTPException) as raised:
                    evaluation.evaluation_results()

        self.assertEqual(raised.exception.status_code, 500)
        self.assertEqual(
            raised.exception.detail,
            "Stored evaluation results could not be read.",
        )

    def test_non_object_json_returns_safe_500(self):
        with tempfile.TemporaryDirectory() as temporary:
            result_path = Path(temporary) / "evaluation.json"
            result_path.write_text("[]", encoding="utf-8")
            with patch.object(evaluation, "EVALUATION_RESULTS_PATH", result_path):
                with self.assertRaises(HTTPException) as raised:
                    evaluation.evaluation_results()

        self.assertEqual(raised.exception.status_code, 500)
        self.assertIn("invalid format", raised.exception.detail)


if __name__ == "__main__":
    unittest.main()
