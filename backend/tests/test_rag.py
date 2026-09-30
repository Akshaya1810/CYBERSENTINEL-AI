import unittest

from app.security.rag import retrieve_security_context


class RAGRetrievalTests(unittest.TestCase):
    def test_t1110_retrieves_brute_force(self):
        results = retrieve_security_context("T1110")
        self.assertTrue(results)
        self.assertEqual(results[0]["id"], "T1110")
        self.assertEqual(results[0]["title"], "Brute Force")

    def test_t1110_001_retrieves_password_guessing(self):
        results = retrieve_security_context("T1110.001")
        self.assertTrue(results)
        self.assertEqual(results[0]["id"], "T1110.001")
        self.assertEqual(results[0]["title"], "Password Guessing")

    def test_ssh_brute_force_authentication_retrieves_relevant_entries(self):
        results = retrieve_security_context("SSH brute force authentication")
        ids = {result["id"] for result in results}
        self.assertIn("T1110", ids)
        self.assertIn("SSH-AUTH-INVESTIGATION", ids)

    def test_unknown_query_returns_empty_list(self):
        self.assertEqual(retrieve_security_context("quantum banana orchestration"), [])

    def test_top_k_is_respected(self):
        self.assertLessEqual(len(retrieve_security_context("SSH authentication password", top_k=2)), 2)
        self.assertEqual(retrieve_security_context("SSH authentication", top_k=0), [])

    def test_results_are_knowledge_context_not_incident_evidence(self):
        results = retrieve_security_context("T1110")
        forbidden = {"incident_evidence", "event_id", "event_ids", "incident_id", "raw_log", "source_ip"}
        self.assertTrue(results)
        for result in results:
            self.assertEqual(set(result), {"id", "title", "description", "guidance", "relevance_score"})
            self.assertTrue(forbidden.isdisjoint(result))


if __name__ == "__main__":
    unittest.main()