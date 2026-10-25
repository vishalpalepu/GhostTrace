"""Unit tests for CsvSerializer and Output Contract Validation."""

import json
import unittest

from code.planner.models import AuditDecision, AuditStep
from code.serializer.csv_serializer import CsvSerializer, ValidationError


class TestCsvSerializer(unittest.TestCase):
    """Test suite for strict serializer validation rules and RFC-4180 formatting."""

    def setUp(self):
        self.serializer = CsvSerializer(valid_evidence_ids={"evidence_01", "evidence_54", "evidence_56"})

    def test_valid_not_applicable(self):
        """NOT_APPLICABLE decision must have 0 steps and serialize properly."""
        dec = AuditDecision(case_id="case_999", deletion_status="NOT_APPLICABLE", steps=[])
        self.serializer.validate_decision(dec)
        row = self.serializer.serialize_decision_row(dec)
        self.assertEqual(row, ("case_999", "NOT_APPLICABLE", "[]"))

    def test_not_applicable_with_steps_rejected(self):
        """NOT_APPLICABLE decision cannot contain steps."""
        step = AuditStep(
            step_no=1, phase="VERIFICATION", operation="VERIFY_RECORD_ABSENT",
            system_id="account_service", resource_id="account_001", state="ABSENT", evidence_id="evidence_54"
        )
        dec = AuditDecision(case_id="case_999", deletion_status="NOT_APPLICABLE", steps=[step])
        with self.assertRaises(ValidationError):
            self.serializer.validate_decision(dec)

    def test_valid_complete_decision(self):
        """COMPLETE decision requires only VERIFICATION phase steps with valid evidence_id."""
        steps = [
            AuditStep(
                step_no=1, phase="VERIFICATION", operation="VERIFY_RECORD_ABSENT",
                system_id="account_service", resource_id="account_001", state="ABSENT", evidence_id="evidence_54"
            )
        ]
        dec = AuditDecision(case_id="case_01", deletion_status="COMPLETE", steps=steps)
        self.serializer.validate_decision(dec)
        cid, status, steps_json = self.serializer.serialize_decision_row(dec)
        self.assertEqual(cid, "case_01")
        self.assertEqual(status, "COMPLETE")
        loaded = json.loads(steps_json)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["resource_id"], "account_001")

    def test_complete_decision_with_findings_rejected(self):
        """COMPLETE decision cannot contain FINDING steps."""
        steps = [
            AuditStep(
                step_no=1, phase="FINDING", operation="REPORT_REMAINING_RECORD",
                system_id="account_service", resource_id="account_001", state="PRESENT", evidence_id="evidence_54"
            )
        ]
        dec = AuditDecision(case_id="case_01", deletion_status="COMPLETE", steps=steps)
        with self.assertRaises(ValidationError):
            self.serializer.validate_decision(dec)

    def test_incomplete_decision_evidence_invariants(self):
        """INCOMPLETE requires evidence_id on FINDING and empty evidence_id on REMEDIATION/VERIFICATION."""
        valid_steps = [
            AuditStep(
                step_no=1, phase="FINDING", operation="REPORT_REMAINING_RECORD",
                system_id="account_service", resource_id="account_005", state="PRESENT", evidence_id="evidence_54"
            ),
            AuditStep(
                step_no=2, phase="REMEDIATION", operation="DELETE_RECORD",
                system_id="account_service", resource_id="account_005", state="ABSENT", evidence_id=""
            ),
            AuditStep(
                step_no=3, phase="VERIFICATION", operation="VERIFY_RECORD_ABSENT",
                system_id="account_service", resource_id="account_005", state="ABSENT", evidence_id=""
            ),
        ]
        dec = AuditDecision(case_id="case_05", deletion_status="INCOMPLETE", steps=valid_steps)
        self.serializer.validate_decision(dec)

        # Invalid: non-empty evidence_id on remediation in INCOMPLETE
        invalid_steps = [
            AuditStep(
                step_no=1, phase="FINDING", operation="REPORT_REMAINING_RECORD",
                system_id="account_service", resource_id="account_005", state="PRESENT", evidence_id="evidence_54"
            ),
            AuditStep(
                step_no=2, phase="REMEDIATION", operation="DELETE_RECORD",
                system_id="account_service", resource_id="account_005", state="ABSENT", evidence_id="evidence_54"
            ),
        ]
        bad_dec = AuditDecision(case_id="case_05", deletion_status="INCOMPLETE", steps=invalid_steps)
        with self.assertRaises(ValidationError):
            self.serializer.validate_decision(bad_dec)

    def test_state_operation_correspondence(self):
        """Step operation must correspond strictly to required state."""
        bad_step = AuditStep(
            step_no=1, phase="VERIFICATION", operation="VERIFY_RECORD_ABSENT",
            system_id="account_service", resource_id="account_001", state="PRESENT",  # mismatch!
            evidence_id="evidence_54"
        )
        dec = AuditDecision(case_id="case_01", deletion_status="COMPLETE", steps=[bad_step])
        with self.assertRaises(ValidationError):
            self.serializer.validate_decision(dec)

    def test_step_sorting_invariants(self):
        """Steps must be sorted by (phase, operation, system_id, resource_id)."""
        bad_order_steps = [
            AuditStep(
                step_no=1, phase="VERIFICATION", operation="VERIFY_RECORD_ABSENT",
                system_id="account_service", resource_id="account_001", state="ABSENT", evidence_id=""
            ),
            AuditStep(
                step_no=2, phase="FINDING", operation="REPORT_REMAINING_RECORD",
                system_id="account_service", resource_id="account_001", state="PRESENT", evidence_id="evidence_54"
            ),
        ]
        dec = AuditDecision(case_id="case_05", deletion_status="INCOMPLETE", steps=bad_order_steps)
        with self.assertRaises(ValidationError):
            self.serializer.validate_decision(dec)

    def test_consecutive_step_numbering(self):
        """Step numbers must be 1-based consecutive integers."""
        bad_num_steps = [
            AuditStep(
                step_no=2, phase="VERIFICATION", operation="VERIFY_RECORD_ABSENT",
                system_id="account_service", resource_id="account_001", state="ABSENT", evidence_id="evidence_54"
            )
        ]
        dec = AuditDecision(case_id="case_01", deletion_status="COMPLETE", steps=bad_num_steps)
        with self.assertRaises(ValidationError):
            self.serializer.validate_decision(dec)

    def test_unknown_evidence_id_rejected(self):
        """Evidence IDs must exist in the validated manifest."""
        bad_step = AuditStep(
            step_no=1, phase="VERIFICATION", operation="VERIFY_RECORD_ABSENT",
            system_id="account_service", resource_id="account_001", state="ABSENT",
            evidence_id="nonexistent_evidence_999"
        )
        dec = AuditDecision(case_id="case_01", deletion_status="COMPLETE", steps=[bad_step])
        with self.assertRaises(ValidationError):
            self.serializer.validate_decision(dec)

    def test_rfc4180_csv_serialization(self):
        """Serialization output must adhere to RFC-4180 CSV standard."""
        decisions = [
            AuditDecision(
                case_id="case_01", deletion_status="COMPLETE",
                steps=[AuditStep(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_001", "ABSENT", "evidence_54")]
            ),
            AuditDecision(case_id="case_999", deletion_status="NOT_APPLICABLE", steps=[]),
        ]
        csv_str = self.serializer.serialize_to_csv_string(decisions)
        lines = csv_str.strip().split("\n")
        self.assertEqual(lines[0], "case_id,deletion_status,steps_json")
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[1].startswith("case_01,COMPLETE,"))
        self.assertEqual(lines[2], "case_999,NOT_APPLICABLE,[]")


if __name__ == "__main__":
    unittest.main()
