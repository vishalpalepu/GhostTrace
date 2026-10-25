"""Unit tests for deletion policy engine and rules from deletion_rules.csv."""

import unittest
from datetime import datetime, timezone, timedelta

from code.config import DELETION_RULES_CSV
from code.policy.rules_engine import PolicyEngine


class TestPolicyEngine(unittest.TestCase):
    """Test suite for policy evaluation against deletion_rules.csv."""

    @classmethod
    def setUpClass(cls):
        cls.engine = PolicyEngine(DELETION_RULES_CSV)

    def test_all_15_rules_loaded_verbatim(self):
        """Verify that all 15 rules from deletion_rules.csv are loaded accurately."""
        self.assertEqual(len(self.engine.rules), 15)
        expected_rules = [
            ("rule_01", "USER_PROFILE", "Always", "DELETE"),
            ("rule_02", "SECONDARY_IDENTIFIER", "Always", "DELETE"),
            ("rule_03", "SEARCH_INDEX_ENTRY", "Always", "DELETE"),
            ("rule_04", "CACHE_ENTRY", "Always", "DELETE"),
            ("rule_05", "SUPPORT_MESSAGE", "Conversation contains shared customer, agent, or order context that must be retained", "REDACT"),
            ("rule_06", "SUPPORT_ATTACHMENT", "Attachment belongs only to the deletion subject", "DELETE"),
            ("rule_07", "ANALYTICS_PROFILE", "Record is still attributable to a user", "ANONYMIZE"),
            ("rule_08", "PRODUCT_TELEMETRY", "Record is still attributable to a user", "ANONYMIZE"),
            ("rule_09", "USER_EXPORT", "Always", "DELETE"),
            ("rule_10", "MARKETING_PROFILE", "Always", "DELETE"),
            ("rule_11", "EMAIL_DELIVERY_LOG", "Log contains a user email address", "REDACT"),
            ("rule_12", "SECURITY_AUDIT_LOG", "Record is within the supplied retention period", "RETAIN"),
            ("rule_13", "LEGAL_HOLD_RECORD", "A supplied legal hold is active", "RETAIN"),
            ("rule_14", "BACKUP_ARCHIVE", "Restore access can be blocked", "RETAIN"),
            ("rule_15", "ACCOUNT_TOMBSTONE", "Account is deleted and only a stable internal user_id is needed to preserve references to retained records", "REDACT"),
        ]

        for rid, cat, cond, act in expected_rules:
            r = self.engine.get_rule(rid)
            self.assertIsNotNone(r, f"Missing rule {rid}")
            self.assertEqual(r.data_category, cat)
            self.assertEqual(r.condition, cond)
            self.assertEqual(r.required_action, act)

    def test_unconditional_deletion_rules(self):
        """Rules 1, 2, 3, 4, 9, 10 must always require full DELETE."""
        for cat in ["USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "USER_EXPORT", "MARKETING_PROFILE"]:
            res = self.engine.evaluate(cat, {})
            self.assertTrue(res.condition_met)
            self.assertEqual(res.required_action, "DELETE")
            self.assertEqual(res.finding_operation, "REPORT_REMAINING_RECORD")
            self.assertEqual(res.remediation_operation, "DELETE_RECORD")
            self.assertEqual(res.verification_operation, "VERIFY_RECORD_ABSENT")

    def test_support_message_condition(self):
        """Rule 5: Shared context -> REDACT; No shared context -> NONE (no unauthorized action)."""
        # Shared context present
        res_shared = self.engine.evaluate("SUPPORT_MESSAGE", {"has_shared_context": True})
        self.assertTrue(res_shared.condition_met)
        self.assertEqual(res_shared.required_action, "REDACT")
        self.assertEqual(res_shared.remediation_operation, "REDACT_RECORD")
        self.assertEqual(res_shared.verification_operation, "VERIFY_RECORD_REDACTED")

        # No shared context -> rule does not mandate action, do NOT invent DELETE
        res_sole = self.engine.evaluate("SUPPORT_MESSAGE", {"has_shared_context": False})
        self.assertFalse(res_sole.condition_met)
        self.assertEqual(res_sole.required_action, "NONE")
        self.assertIsNone(res_sole.finding_operation)
        self.assertIsNone(res_sole.remediation_operation)

    def test_support_attachment_condition(self):
        """Rule 6: Belongs only to subject -> DELETE; Shared attachment -> NONE."""
        # Sole subject attachment
        res_sole = self.engine.evaluate("SUPPORT_ATTACHMENT", {"belongs_only_to_subject": True})
        self.assertTrue(res_sole.condition_met)
        self.assertEqual(res_sole.required_action, "DELETE")
        self.assertEqual(res_sole.remediation_operation, "DELETE_RECORD")

        # Multi-party attachment -> rule 6 condition not met, do NOT invent REDACT
        res_shared = self.engine.evaluate("SUPPORT_ATTACHMENT", {"belongs_only_to_subject": False})
        self.assertFalse(res_shared.condition_met)
        self.assertEqual(res_shared.required_action, "NONE")
        self.assertIsNone(res_shared.finding_operation)
        self.assertIsNone(res_shared.remediation_operation)

    def test_analytics_and_telemetry_anonymization(self):
        """Rules 7 & 8: Attributable -> ANONYMIZE; Unlinked -> NONE (already compliant)."""
        for cat in ["ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"]:
            res_attr = self.engine.evaluate(cat, {"is_attributable": True})
            self.assertTrue(res_attr.condition_met)
            self.assertEqual(res_attr.required_action, "ANONYMIZE")
            self.assertEqual(res_attr.finding_operation, "REPORT_EXPOSED_PII")
            self.assertEqual(res_attr.remediation_operation, "ANONYMIZE_RECORD")
            self.assertEqual(res_attr.verification_operation, "VERIFY_RECORD_ANONYMIZED")

            res_unlinked = self.engine.evaluate(cat, {"is_attributable": False})
            self.assertFalse(res_unlinked.condition_met)
            self.assertEqual(res_unlinked.required_action, "NONE")
            self.assertIsNone(res_unlinked.finding_operation)
            self.assertIsNone(res_unlinked.remediation_operation)
            self.assertEqual(res_unlinked.verification_operation, "VERIFY_RECORD_ANONYMIZED")

    def test_email_delivery_log_condition(self):
        """Rule 11: Contains email -> REDACT; Already redacted -> NONE."""
        res_with_email = self.engine.evaluate("EMAIL_DELIVERY_LOG", {"contains_email": True})
        self.assertTrue(res_with_email.condition_met)
        self.assertEqual(res_with_email.required_action, "REDACT")
        self.assertEqual(res_with_email.finding_operation, "REPORT_EXPOSED_PII")
        self.assertEqual(res_with_email.remediation_operation, "REDACT_RECORD")
        self.assertEqual(res_with_email.verification_operation, "VERIFY_RECORD_REDACTED")

        res_no_email = self.engine.evaluate("EMAIL_DELIVERY_LOG", {"contains_email": False})
        self.assertFalse(res_no_email.condition_met)
        self.assertEqual(res_no_email.required_action, "NONE")
        self.assertIsNone(res_no_email.finding_operation)
        self.assertIsNone(res_no_email.remediation_operation)

    def test_security_audit_log_retention_boundary(self):
        """Rule 12: audit_at <= retention_until -> RETAIN; Expired -> NONE (do NOT invent DELETE)."""
        t_ref = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Within retention
        res_active = self.engine.evaluate("SECURITY_AUDIT_LOG", {
            "audit_at": t_ref,
            "retention_until": t_ref + timedelta(days=365),
        })
        self.assertTrue(res_active.condition_met)
        self.assertEqual(res_active.required_action, "RETAIN")
        self.assertEqual(res_active.verification_operation, "VERIFY_RECORD_PRESENT")

        # Expired retention -> Rule 12 does not mandate action; do NOT invent DELETE
        res_expired = self.engine.evaluate("SECURITY_AUDIT_LOG", {
            "audit_at": t_ref,
            "retention_until": t_ref - timedelta(days=1),
        })
        self.assertFalse(res_expired.condition_met)
        self.assertEqual(res_expired.required_action, "NONE")
        self.assertIsNone(res_expired.finding_operation)
        self.assertIsNone(res_expired.remediation_operation)

    def test_legal_hold_condition(self):
        """Rule 13: Active legal hold -> RETAIN; Inactive hold -> NONE (do NOT invent DELETE)."""
        res_hold = self.engine.evaluate("LEGAL_HOLD_RECORD", {"is_legal_hold_active": True})
        self.assertTrue(res_hold.condition_met)
        self.assertEqual(res_hold.required_action, "RETAIN")
        self.assertEqual(res_hold.verification_operation, "VERIFY_RECORD_PRESENT")

        res_no_hold = self.engine.evaluate("LEGAL_HOLD_RECORD", {"is_legal_hold_active": False})
        self.assertFalse(res_no_hold.condition_met)
        self.assertEqual(res_no_hold.required_action, "NONE")
        self.assertIsNone(res_no_hold.finding_operation)
        self.assertIsNone(res_no_hold.remediation_operation)

    def test_backup_archive_restore_blocking(self):
        """Rule 14: Restore blocked -> RETAIN (compliant); Restore allowed -> REPORT_RESTORE_RISK; Unblockable -> NONE."""
        # Restore blocked (compliant retention)
        res_blocked = self.engine.evaluate("BACKUP_ARCHIVE", {
            "restore_can_be_blocked": True,
            "is_restore_allowed": False,
        })
        self.assertTrue(res_blocked.condition_met)
        self.assertEqual(res_blocked.required_action, "RETAIN")
        self.assertIsNone(res_blocked.finding_operation)
        self.assertEqual(res_blocked.verification_operation, "VERIFY_RESTORE_BLOCKED")

        # Restore allowed (active restore risk)
        res_allowed = self.engine.evaluate("BACKUP_ARCHIVE", {
            "restore_can_be_blocked": True,
            "is_restore_allowed": True,
        })
        self.assertTrue(res_allowed.condition_met)
        self.assertEqual(res_allowed.required_action, "RETAIN")
        self.assertEqual(res_allowed.finding_operation, "REPORT_RESTORE_RISK")
        self.assertEqual(res_allowed.remediation_operation, "BLOCK_RESTORE")
        self.assertEqual(res_allowed.verification_operation, "VERIFY_RESTORE_BLOCKED")

        # Restore cannot be blocked
        res_unblockable = self.engine.evaluate("BACKUP_ARCHIVE", {
            "restore_can_be_blocked": False,
            "is_restore_allowed": False,
        })
        self.assertFalse(res_unblockable.condition_met)
        self.assertEqual(res_unblockable.required_action, "NONE")

    def test_account_tombstone_redaction(self):
        """Rule 15: Needs user_id with direct PII -> REDACT_RECORD; Already redacted -> Compliant; Not needed -> NONE."""
        # Direct PII still present in tombstone
        res_pii = self.engine.evaluate("ACCOUNT_TOMBSTONE", {
            "needs_stable_user_id": True,
            "has_direct_pii": True,
        })
        self.assertTrue(res_pii.condition_met)
        self.assertEqual(res_pii.required_action, "REDACT")
        self.assertEqual(res_pii.finding_operation, "REPORT_EXPOSED_PII")
        self.assertEqual(res_pii.remediation_operation, "REDACT_RECORD")
        self.assertEqual(res_pii.verification_operation, "VERIFY_RECORD_REDACTED")

        # Properly redacted tombstone
        res_clean = self.engine.evaluate("ACCOUNT_TOMBSTONE", {
            "needs_stable_user_id": True,
            "has_direct_pii": False,
        })
        self.assertTrue(res_clean.condition_met)
        self.assertEqual(res_clean.required_action, "REDACT")
        self.assertIsNone(res_clean.finding_operation)
        self.assertEqual(res_clean.verification_operation, "VERIFY_RECORD_REDACTED")

        # No retained references require user_id
        res_unneeded = self.engine.evaluate("ACCOUNT_TOMBSTONE", {
            "needs_stable_user_id": False,
            "has_direct_pii": False,
        })
        self.assertFalse(res_unneeded.condition_met)
        self.assertEqual(res_unneeded.required_action, "NONE")
        self.assertIsNone(res_unneeded.finding_operation)
        self.assertIsNone(res_unneeded.remediation_operation)


if __name__ == "__main__":
    unittest.main()
