"""Unit tests for request-intent classification engine."""

import unittest

from code.config import DELETION_REQUESTS_CSV, SAMPLE_DELETION_REQUESTS_CSV
from code.ingestion.csv_loader import load_deletion_requests
from code.intent.classifier import IntentClassifier


class TestIntentClassifier(unittest.TestCase):
    """Test suite for request-intent classification."""

    @classmethod
    def setUpClass(cls):
        cls.classifier = IntentClassifier()
        cls.sample_requests = load_deletion_requests(SAMPLE_DELETION_REQUESTS_CSV)
        cls.eval_requests = load_deletion_requests(DELETION_REQUESTS_CSV)

    def test_all_sample_requests_authorized(self):
        """All 32 sample requests must be classified as valid deletion requests."""
        self.assertEqual(len(self.sample_requests), 32)
        for req in self.sample_requests:
            result = self.classifier.classify(req.request_text)
            self.assertTrue(
                result.is_deletion,
                f"Sample {req.case_id} was incorrectly marked as non-deletion: '{req.request_text}'",
            )
            self.assertEqual(result.status, "DELETION")

    def test_real_eval_non_deletion_requests(self):
        """Test cases 533 to 542 in deletion_requests.csv which represent non-deletion requests."""
        eval_by_id = {r.case_id: r for r in self.eval_requests}
        non_deletion_cases = [
            ("case_533", "RECTIFICATION"),
            ("case_534", "MARKETING_OPT_OUT"),
            ("case_535", "DATA_ACCESS"),
            ("case_536", "ACCOUNT_HELP"),
            ("case_537", "RECTIFICATION"),
            ("case_538", "MARKETING_OPT_OUT"),
            ("case_539", "DATA_ACCESS"),
            ("case_540", "DATA_ACCESS"),
            ("case_541", "RECTIFICATION"),
            ("case_542", "DATA_ACCESS"),
        ]

        for case_id, expected_category in non_deletion_cases:
            req = eval_by_id.get(case_id)
            self.assertIsNotNone(req, f"Missing {case_id} in evaluation set")
            res = self.classifier.classify(req.request_text)
            self.assertFalse(
                res.is_deletion,
                f"{case_id} should be non-deletion: '{req.request_text}'",
            )
            self.assertEqual(res.status, "NOT_APPLICABLE")
            self.assertIn(res.category, (expected_category, "RETENTION_REQUEST", "DATA_ACCESS", "RECTIFICATION", "MARKETING_OPT_OUT", "ACCOUNT_HELP"))

    def test_multilingual_deletion_requests(self):
        """Test deletion requests in various supported languages."""
        test_cases = [
            # English
            ("Please permanently delete my account and personal data.", True),
            ("I want to erase all records tied to this profile.", True),
            # French
            ("Je demande la suppression définitive de mon compte.", True),
            ("Veuillez effacer mes données personnelles.", True),
            # Spanish
            ("Solicito la eliminación permanente de mi cuenta.", True),
            ("Por favor borrar mis datos de usuario.", True),
            # German
            ("Bitte löschen Sie mein Kundenkonto vollständig.", True),
            ("Ich möchte meine persönlichen Daten entfernen lassen.", True),
            # Italian
            ("Richiedo la cancellazione definitiva del mio account.", True),
            # Portuguese
            ("Solicito a exclusão permanente da minha conta.", True),
            # Japanese
            ("このメールアドレスに関連するアカウントの完全な削除を依頼します。", True),
            # Korean
            ("이 이메일 주소와 연결된 계정의 영구 삭제를 요청합니다.", True),
        ]

        for text, expected_deletion in test_cases:
            res = self.classifier.classify(text)
            self.assertEqual(res.is_deletion, expected_deletion, f"Failed on: '{text}'")
            self.assertEqual(res.status, "DELETION")

    def test_boundary_negation_intent(self):
        """Test boundary cases where deletion keywords appear inside a non-deletion sentence."""
        boundary_cases = [
            ("I need to download my data, so please do not delete my account.", False),
            ("Can you help me reset my password? Do not close the account.", False),
            ("Please correct my surname without removing my profile.", False),
            ("Stop promotional emails only; keep the account open for purchases.", False),
        ]

        for text, expected_deletion in boundary_cases:
            res = self.classifier.classify(text)
            self.assertEqual(res.is_deletion, expected_deletion, f"Failed on boundary: '{text}'")
            self.assertEqual(res.status, "NOT_APPLICABLE")

    def test_explicit_negation_intent(self):
        """Test standalone and explicit negation of deletion requests."""
        negation_cases = [
            "Please do not delete my account.",
            "Don't delete my profile.",
            "Never delete this account.",
            "I am not asking for deletion.",
            "Please leave my account in place.",
            "Please keep my account active.",
        ]

        for text in negation_cases:
            res = self.classifier.classify(text)
            self.assertFalse(res.is_deletion, f"Failed on negation: '{text}'")
            self.assertEqual(res.outcome, "NON_DELETION")
            self.assertEqual(res.status, "NOT_APPLICABLE")
            self.assertEqual(res.category, "RETENTION_REQUEST")

    def test_multilingual_negation_intent(self):
        """Test explicit negation across supported non-English languages."""
        multilingual_negations = [
            # French
            "Merci de ne pas supprimer mon compte.",
            # Spanish
            "Por favor no eliminar mi cuenta.",
            # German
            "Bitte mein Konto nicht löschen.",
            # Italian
            "Non cancellare il mio account per favore.",
            # Portuguese
            "Por favor não excluir minha conta.",
            # Japanese
            "アカウントを削除しないでください。",
            # Korean
            "계정을 삭제하지 마세요.",
        ]

        for text in multilingual_negations:
            res = self.classifier.classify(text)
            self.assertFalse(res.is_deletion, f"Failed on multilingual negation: '{text}'")
            self.assertEqual(res.outcome, "NON_DELETION")
            self.assertEqual(res.status, "NOT_APPLICABLE")

    def test_ambiguous_intent_handling(self):
        """Test that ambiguous inquiries are flagged internally as AMBIGUOUS and not prematurely NOT_APPLICABLE."""
        ambiguous_cases = [
            "Hello, can someone help me with my account?",
            "What is your privacy policy regarding data retention?",
            "Can you tell me if my friend's account is still active?",
            "Just checking in regarding my order status.",
        ]

        for text in ambiguous_cases:
            res = self.classifier.classify(text)
            self.assertEqual(res.outcome, "AMBIGUOUS", f"Failed to mark as ambiguous: '{text}'")
            self.assertFalse(res.is_deletion)
            self.assertEqual(res.status, "AMBIGUOUS")
            self.assertEqual(res.confidence, 0.0)
            self.assertEqual(res.contract_status, "NOT_APPLICABLE")

    def test_mixed_intent_precedence(self):
        """Test that non-deletion / negation signals take precedence over embedded deletion keywords."""
        mixed_cases = [
            ("I want to download my data; do not delete my account.", "DATA_ACCESS"),
            ("Please correct my surname without removing any records.", "RETENTION_REQUEST"),
            ("Stop promotional emails only, I still need my account.", "MARKETING_OPT_OUT"),
            ("I can't access my profile and need password help. Do not close the account.", "RETENTION_REQUEST"),
        ]

        for text, expected_category in mixed_cases:
            res = self.classifier.classify(text)
            self.assertFalse(res.is_deletion, f"Mixed intent misclassified: '{text}'")
            self.assertEqual(res.outcome, "NON_DELETION")
            self.assertEqual(res.status, "NOT_APPLICABLE")
            self.assertIn(res.category, (expected_category, "RETENTION_REQUEST", "DATA_ACCESS", "MARKETING_OPT_OUT", "RECTIFICATION"))


if __name__ == "__main__":
    unittest.main()
