"""Policy rules engine driven by deletion_rules.csv."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..ingestion.csv_loader import DeletionRuleRecord, load_deletion_rules


@dataclass(frozen=True)
class PolicyEvaluationResult:
    """The result of evaluating a data category and context against deletion policy."""
    rule_id: str
    data_category: str
    condition: str
    condition_met: bool
    is_evidence_sufficient: bool
    required_action: str  # 'DELETE', 'REDACT', 'ANONYMIZE', 'RETAIN', or 'NONE'
    finding_operation: Optional[str]      # e.g. 'REPORT_REMAINING_RECORD', 'REPORT_EXPOSED_PII', 'REPORT_RESTORE_RISK'
    finding_state: Optional[str]          # 'PRESENT', 'ACTIVE'
    remediation_operation: Optional[str]  # 'DELETE_RECORD', 'REDACT_RECORD', 'ANONYMIZE_RECORD', 'BLOCK_RESTORE'
    remediation_state: Optional[str]      # 'ABSENT', 'REDACTED', 'ANONYMIZED', 'BLOCKED'
    verification_operation: Optional[str] # 'VERIFY_RECORD_ABSENT', 'VERIFY_RECORD_PRESENT', etc.
    verification_state: Optional[str]     # 'ABSENT', 'PRESENT', 'REDACTED', 'ANONYMIZED', 'BLOCKED'
    reason: str


class PolicyEngine:
    """Evaluates organization deletion rules against observed records and processes."""

    def __init__(self, rules_path: Path) -> None:
        self.rules: Dict[str, DeletionRuleRecord] = {}
        self.rules_by_category: Dict[str, DeletionRuleRecord] = {}
        self._load_rules(rules_path)

    def _load_rules(self, rules_path: Path) -> None:
        records = load_deletion_rules(rules_path)
        for r in records:
            self.rules[r.rule_id] = r
            self.rules_by_category[r.data_category] = r

    def get_rule(self, rule_id: str) -> Optional[DeletionRuleRecord]:
        return self.rules.get(rule_id)

    def get_rule_by_category(self, category: str) -> Optional[DeletionRuleRecord]:
        return self.rules_by_category.get(category)

    def evaluate(self, data_category: str, context: Dict[str, Any]) -> PolicyEvaluationResult:
        """Evaluate a data category and evidence context against deletion_rules.csv."""
        rule = self.rules_by_category.get(data_category)
        if not rule:
            raise ValueError(f"Unknown data category: '{data_category}'")

        # Missing evidence handling
        if context.get("evidence_missing", False):
            return PolicyEvaluationResult(
                rule_id=rule.rule_id,
                data_category=data_category,
                condition=rule.condition,
                condition_met=False,
                is_evidence_sufficient=False,
                required_action="NONE",
                finding_operation=None,
                finding_state=None,
                remediation_operation=None,
                remediation_state=None,
                verification_operation=None,
                verification_state=None,
                reason=f"Evidence missing or unparseable for {data_category}; condition cannot be established.",
            )

        # 1. Unconditional DELETE rules (rule_01, rule_02, rule_03, rule_04, rule_09, rule_10)
        if rule.condition == "Always":
            return PolicyEvaluationResult(
                rule_id=rule.rule_id,
                data_category=data_category,
                condition=rule.condition,
                condition_met=True,
                is_evidence_sufficient=True,
                required_action="DELETE",
                finding_operation="REPORT_REMAINING_RECORD",
                finding_state="PRESENT",
                remediation_operation="DELETE_RECORD",
                remediation_state="ABSENT",
                verification_operation="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
                reason=f"Unconditional deletion rule {rule.rule_id} applies to {data_category}.",
            )

        # 2. rule_05: SUPPORT_MESSAGE (Condition: Conversation contains shared customer, agent, or order context that must be retained)
        if rule.rule_id == "rule_05":
            has_shared_context = context.get("has_shared_context", True)
            if has_shared_context:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=True,
                    is_evidence_sufficient=True,
                    required_action="REDACT",
                    finding_operation="REPORT_EXPOSED_PII",
                    finding_state="PRESENT",
                    remediation_operation="REDACT_RECORD",
                    remediation_state="REDACTED",
                    verification_operation="VERIFY_RECORD_REDACTED",
                    verification_state="REDACTED",
                    reason="Support conversation contains shared agent/order context; customer PII must be redacted.",
                )
            else:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=False,
                    is_evidence_sufficient=True,
                    required_action="NONE",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation=None,
                    verification_state=None,
                    reason="Support message does not satisfy the shared-context condition of rule_05; rule does not mandate redaction.",
                )

        # 3. rule_06: SUPPORT_ATTACHMENT (Condition: Attachment belongs only to the deletion subject)
        if rule.rule_id == "rule_06":
            belongs_only_to_subject = context.get("belongs_only_to_subject", True)
            if belongs_only_to_subject:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=True,
                    is_evidence_sufficient=True,
                    required_action="DELETE",
                    finding_operation="REPORT_REMAINING_RECORD",
                    finding_state="PRESENT",
                    remediation_operation="DELETE_RECORD",
                    remediation_state="ABSENT",
                    verification_operation="VERIFY_RECORD_ABSENT",
                    verification_state="ABSENT",
                    reason="Support attachment belongs solely to deletion subject; must be deleted under rule_06.",
                )
            else:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=False,
                    is_evidence_sufficient=True,
                    required_action="NONE",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation=None,
                    verification_state=None,
                    reason="Attachment is shared or contains multi-party context; deletion is not authorized under rule_06.",
                )

        # 4. rule_07 / rule_08: ANALYTICS_PROFILE / PRODUCT_TELEMETRY (Condition: Record is still attributable to a user)
        if rule.rule_id in ("rule_07", "rule_08"):
            is_attributable = context.get("is_attributable", True)
            if is_attributable:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=True,
                    is_evidence_sufficient=True,
                    required_action="ANONYMIZE",
                    finding_operation="REPORT_EXPOSED_PII",
                    finding_state="PRESENT",
                    remediation_operation="ANONYMIZE_RECORD",
                    remediation_state="ANONYMIZED",
                    verification_operation="VERIFY_RECORD_ANONYMIZED",
                    verification_state="ANONYMIZED",
                    reason=f"{data_category} record contains user attribution; must be anonymized.",
                )
            else:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=False,
                    is_evidence_sufficient=True,
                    required_action="NONE",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation="VERIFY_RECORD_ANONYMIZED",
                    verification_state="ANONYMIZED",
                    reason=f"{data_category} is already unlinked/anonymized; compliant with policy.",
                )

        # 5. rule_11: EMAIL_DELIVERY_LOG (Condition: Log contains a user email address)
        if rule.rule_id == "rule_11":
            contains_email = context.get("contains_email", True)
            if contains_email:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=True,
                    is_evidence_sufficient=True,
                    required_action="REDACT",
                    finding_operation="REPORT_EXPOSED_PII",
                    finding_state="PRESENT",
                    remediation_operation="REDACT_RECORD",
                    remediation_state="REDACTED",
                    verification_operation="VERIFY_RECORD_REDACTED",
                    verification_state="REDACTED",
                    reason="Email delivery log contains identifying user email address; must be redacted under rule_11.",
                )
            else:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=False,
                    is_evidence_sufficient=True,
                    required_action="NONE",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation="VERIFY_RECORD_REDACTED",
                    verification_state="REDACTED",
                    reason="Delivery log has email already redacted; compliant with rule_11.",
                )

        # 6. rule_12: SECURITY_AUDIT_LOG (Condition: Record is within the supplied retention period)
        if rule.rule_id == "rule_12":
            audit_at = context.get("audit_at")
            retention_until = context.get("retention_until")

            is_within_retention = True
            if audit_at and retention_until:
                is_within_retention = (audit_at <= retention_until)

            if is_within_retention:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=True,
                    is_evidence_sufficient=True,
                    required_action="RETAIN",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation="VERIFY_RECORD_PRESENT",
                    verification_state="PRESENT",
                    reason="Security audit log is within legal retention period; must be retained intact under rule_12.",
                )
            else:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=False,
                    is_evidence_sufficient=True,
                    required_action="NONE",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation=None,
                    verification_state=None,
                    reason="Security audit log retention period has expired; retention is no longer mandated under rule_12.",
                )

        # 7. rule_13: LEGAL_HOLD_RECORD (Condition: A supplied legal hold is active)
        if rule.rule_id == "rule_13":
            is_legal_hold_active = context.get("is_legal_hold_active", True)
            if is_legal_hold_active:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=True,
                    is_evidence_sufficient=True,
                    required_action="RETAIN",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation="VERIFY_RECORD_PRESENT",
                    verification_state="PRESENT",
                    reason="An active legal hold is present; record must be retained under rule_13.",
                )
            else:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=False,
                    is_evidence_sufficient=True,
                    required_action="NONE",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation=None,
                    verification_state=None,
                    reason="No active legal hold present; retention is not mandated under rule_13.",
                )

        # 8. rule_14: BACKUP_ARCHIVE (Condition: Restore access can be blocked)
        if rule.rule_id == "rule_14":
            restore_can_be_blocked = context.get("restore_can_be_blocked", True)
            is_restore_allowed = context.get("is_restore_allowed", False)

            if not restore_can_be_blocked:
                # Condition not met
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=False,
                    is_evidence_sufficient=True,
                    required_action="NONE",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation=None,
                    verification_state=None,
                    reason="Restore access cannot be blocked; rule_14 condition not satisfied.",
                )
            elif is_restore_allowed:
                # Condition met: restore can be blocked, but active restore is currently allowed
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=True,
                    is_evidence_sufficient=True,
                    required_action="RETAIN",
                    finding_operation="REPORT_RESTORE_RISK",
                    finding_state="ACTIVE",
                    remediation_operation="BLOCK_RESTORE",
                    remediation_state="BLOCKED",
                    verification_operation="VERIFY_RESTORE_BLOCKED",
                    verification_state="BLOCKED",
                    reason="Backup archive allows active restoration of deleted user data; restore must be blocked.",
                )
            else:
                # Compliant: archive retained and restore access is confirmed blocked
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=True,
                    is_evidence_sufficient=True,
                    required_action="RETAIN",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation="VERIFY_RESTORE_BLOCKED",
                    verification_state="BLOCKED",
                    reason="Backup archive retained with restore access confirmed blocked under rule_14.",
                )

        # 9. rule_15: ACCOUNT_TOMBSTONE (Condition: Account is deleted and only a stable internal user_id is needed to preserve references to retained records)
        if rule.rule_id == "rule_15":
            needs_stable_user_id = context.get("needs_stable_user_id", True)
            has_direct_pii = context.get("has_direct_pii", False)

            if needs_stable_user_id:
                if has_direct_pii:
                    return PolicyEvaluationResult(
                        rule_id=rule.rule_id,
                        data_category=data_category,
                        condition=rule.condition,
                        condition_met=True,
                        is_evidence_sufficient=True,
                        required_action="REDACT",
                        finding_operation="REPORT_EXPOSED_PII",
                        finding_state="PRESENT",
                        remediation_operation="REDACT_RECORD",
                        remediation_state="REDACTED",
                        verification_operation="VERIFY_RECORD_REDACTED",
                        verification_state="REDACTED",
                        reason="Account tombstone preserves user_id but still exposes direct PII; direct identifiers must be redacted under rule_15.",
                    )
                else:
                    return PolicyEvaluationResult(
                        rule_id=rule.rule_id,
                        data_category=data_category,
                        condition=rule.condition,
                        condition_met=True,
                        is_evidence_sufficient=True,
                        required_action="REDACT",
                        finding_operation=None,
                        finding_state=None,
                        remediation_operation=None,
                        remediation_state=None,
                        verification_operation="VERIFY_RECORD_REDACTED",
                        verification_state="REDACTED",
                        reason="Account tombstone is properly redacted, preserving only the stable user_id under rule_15.",
                    )
            else:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    data_category=data_category,
                    condition=rule.condition,
                    condition_met=False,
                    is_evidence_sufficient=True,
                    required_action="NONE",
                    finding_operation=None,
                    finding_state=None,
                    remediation_operation=None,
                    remediation_state=None,
                    verification_operation=None,
                    verification_state=None,
                    reason="No retained records reference this user_id; tombstone preservation condition of rule_15 is not satisfied.",
                )

        raise NotImplementedError(f"Unhandled rule {rule.rule_id} for category {data_category}")
