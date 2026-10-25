"""Unit tests for AuditPlanner and End-to-End Decision Parity."""

import json
import unittest
from pathlib import Path

from code.config import (
    DATASET_DIR,
    DELETION_RULES_CSV,
    EVIDENCE_FILES_CSV,
    SAMPLE_DELETION_REQUESTS_CSV,
    SAMPLE_OUTPUT_CSV,
    SYSTEM_ACTIVITY_CSV,
    USER_AUDIT_LOG_CSV,
    USER_IDENTITIES_CSV,
)
from code.evidence.evidence_index import EvidenceIndex
from code.identity.resolver import IdentityResolver
from code.ingestion.csv_loader import (
    DeletionRequest,
    load_deletion_requests,
    load_system_activity,
    load_user_audit_log,
    load_user_identities,
    parse_iso8601,
)
from code.intent.classifier import IntentClassifier
from code.planner.audit_planner import AuditPlanner
from code.policy.rules_engine import PolicyEngine


class TestAuditPlanner(unittest.TestCase):
    """Test suite for AuditPlanner footprint derivation, policy execution, and regression parity."""

    @classmethod
    def setUpClass(cls):
        cls.identities = load_user_identities(USER_IDENTITIES_CSV)
        cls.audit_log = load_user_audit_log(USER_AUDIT_LOG_CSV)
        cls.resolver = IdentityResolver(cls.identities, cls.audit_log)
        cls.classifier = IntentClassifier()
        cls.engine = PolicyEngine(DELETION_RULES_CSV)
        cls.evidence_index = EvidenceIndex(EVIDENCE_FILES_CSV, DATASET_DIR)
        cls.system_activity = load_system_activity(SYSTEM_ACTIVITY_CSV)
        cls.planner = AuditPlanner(
            cls.resolver,
            cls.classifier,
            cls.engine,
            cls.evidence_index,
            cls.system_activity,
        )

        cls.sample_requests = load_deletion_requests(SAMPLE_DELETION_REQUESTS_CSV)
        cls.gt_decisions = {}
        import csv
        with open(SAMPLE_OUTPUT_CSV, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                cls.gt_decisions[row["case_id"]] = row

    def test_intent_non_deletion_short_circuit(self):
        """Non-deletion requests must short-circuit to NOT_APPLICABLE with 0 steps."""
        req = DeletionRequest(
            case_id="case_test_export",
            email="amina.elmasri@gmail.com",
            requested_at=parse_iso8601("2026-08-18T09:14:00Z"),
            reported_status="COMPLETED",
            reported_at=parse_iso8601("2026-08-20T16:42:00Z"),
            audit_at=parse_iso8601("2026-09-03T11:30:00Z"),
            request_text="Please export all my personal data so I can download a copy.",
        )
        decision = self.planner.plan_case(req)
        self.assertEqual(decision.deletion_status, "NOT_APPLICABLE")
        self.assertEqual(decision.steps, [])
        self.assertEqual(decision.steps_json, "[]")

    def test_complete_case_has_only_verifications(self):
        """Case 01 is complete and should have exactly 1 step in VERIFICATION phase."""
        req = next(r for r in self.sample_requests if r.case_id == "case_01")
        decision = self.planner.plan_case(req)
        self.assertEqual(decision.deletion_status, "COMPLETE")
        self.assertEqual(len(decision.steps), 1)
        step = decision.steps[0]
        self.assertEqual(step.phase, "VERIFICATION")
        self.assertEqual(step.operation, "VERIFY_RECORD_ABSENT")
        self.assertEqual(step.system_id, "account_service")
        self.assertEqual(step.resource_id, "account_001")
        self.assertEqual(step.state, "ABSENT")
        self.assertEqual(step.evidence_id, "evidence_54")

    def test_incomplete_case_has_remediation_and_empty_evidence_ids(self):
        """Case 05 has remaining record in replica and must contain FINDING, REMEDIATION, VERIFICATION."""
        req = next(r for r in self.sample_requests if r.case_id == "case_05")
        decision = self.planner.plan_case(req)
        self.assertEqual(decision.deletion_status, "INCOMPLETE")
        self.assertEqual(len(decision.steps), 3)

        finding, remediation, verification = decision.steps
        self.assertEqual(finding.phase, "FINDING")
        self.assertEqual(finding.operation, "REPORT_REMAINING_RECORD")
        self.assertEqual(finding.evidence_id, "evidence_54")

        self.assertEqual(remediation.phase, "REMEDIATION")
        self.assertEqual(remediation.operation, "DELETE_RECORD")
        self.assertEqual(remediation.evidence_id, "")

        self.assertEqual(verification.phase, "VERIFICATION")
        self.assertEqual(verification.operation, "VERIFY_RECORD_ABSENT")
        self.assertEqual(verification.evidence_id, "")

    def test_security_audit_record_retention_rule_12(self):
        """Security audit records must be retained in VERIFICATION phase with PRESENT state."""
        # Case 03 includes audit_record_2016
        req = next(r for r in self.sample_requests if r.case_id == "case_03")
        decision = self.planner.plan_case(req)
        audit_steps = [s for s in decision.steps if s.system_id == "security_service"]
        self.assertEqual(len(audit_steps), 1)
        self.assertEqual(audit_steps[0].operation, "VERIFY_RECORD_PRESENT")
        self.assertEqual(audit_steps[0].state, "PRESENT")
        self.assertEqual(audit_steps[0].phase, "VERIFICATION")

    def test_all_32_sample_cases_exact_canonical_parity(self):
        """Verify 100% status, step count, and semantic field parity across all 32 sample cases."""
        status_matches = 0
        step_count_matches = 0
        total_fields_tested = 0
        total_fields_matched = 0

        for req in self.sample_requests:
            cid = req.case_id
            gt = self.gt_decisions[cid]
            gt_status = gt["deletion_status"]
            gt_steps = json.loads(gt["steps_json"])

            decision = self.planner.plan_case(req)
            pred_status = decision.deletion_status
            pred_steps = json.loads(decision.steps_json)

            if pred_status == gt_status:
                status_matches += 1
            if len(pred_steps) == len(gt_steps):
                step_count_matches += 1

            self.assertEqual(pred_status, gt_status, f"Status mismatch in {cid}")
            self.assertEqual(len(pred_steps), len(gt_steps), f"Step count mismatch in {cid}")

            # Verify field-level correspondence for every step
            for idx, (p_step, g_step) in enumerate(zip(pred_steps, gt_steps)):
                for k in ["step_no", "phase", "operation", "system_id", "resource_id", "state", "evidence_id"]:
                    total_fields_tested += 1
                    p_val = p_step.get(k)
                    g_val = g_step.get(k)
                    if p_val == g_val:
                        total_fields_matched += 1
                    self.assertEqual(
                        p_val, g_val,
                        f"Field '{k}' mismatch at step {idx+1} in {cid}: {p_val} != {g_val}"
                    )

        self.assertEqual(status_matches, 32)
        self.assertEqual(step_count_matches, 32)
        self.assertEqual(total_fields_tested, 1351)
        self.assertEqual(total_fields_matched, 1351)


if __name__ == "__main__":
    unittest.main()
