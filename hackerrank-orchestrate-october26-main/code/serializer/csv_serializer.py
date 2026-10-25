"""Strict Serializer and Contract Validator for GhostTrace Audit Decisions."""

import csv
import json
from io import StringIO
from typing import Dict, List, Optional, Set, Tuple

from ..planner.models import (
    AuditDecision,
    AuditStep,
    OP_ORDER,
    OP_STATE_MAP,
    PHASE_ORDER,
)


class ValidationError(ValueError):
    """Raised when an audit step or decision violates output specifications."""
    pass


class CsvSerializer:
    """Serializes and strictly validates audit decisions against the challenge specification."""

    def __init__(self, valid_evidence_ids: Optional[Set[str]] = None) -> None:
        self.valid_evidence_ids = valid_evidence_ids or set()

    def validate_step(self, step: AuditStep, status: str) -> None:
        """Validates a single AuditStep against the strict specification contract."""
        # 1. Phase validation
        if step.phase not in PHASE_ORDER:
            raise ValidationError(f"Invalid phase '{step.phase}' on resource '{step.resource_id}'")

        # 2. Operation validation
        if step.operation not in OP_ORDER:
            raise ValidationError(f"Invalid operation '{step.operation}' on resource '{step.resource_id}'")

        # 3. State correspondence
        expected_state = OP_STATE_MAP.get(step.operation)
        if step.state != expected_state:
            raise ValidationError(
                f"State mismatch: op '{step.operation}' requires state '{expected_state}', got '{step.state}'"
            )

        # 4. Evidence reference validation
        if self.valid_evidence_ids and step.evidence_id:
            if step.evidence_id not in self.valid_evidence_ids:
                raise ValidationError(f"Unknown evidence_id '{step.evidence_id}' on resource '{step.resource_id}'")

        # 5. Status-specific evidence invariants
        if status == "INCOMPLETE":
            if step.phase in ("REMEDIATION", "VERIFICATION") and step.evidence_id != "":
                raise ValidationError(
                    f"INCOMPLETE case requires empty evidence_id on {step.phase} step, got '{step.evidence_id}'"
                )
            if step.phase == "FINDING" and not step.evidence_id:
                raise ValidationError(f"FINDING step requires non-empty evidence_id on '{step.resource_id}'")
        elif status == "COMPLETE":
            if step.phase != "VERIFICATION":
                raise ValidationError(f"COMPLETE case cannot contain {step.phase} steps")
            if not step.evidence_id:
                raise ValidationError(f"COMPLETE case requires non-empty evidence_id on '{step.resource_id}'")

    def validate_decision(self, decision: AuditDecision) -> None:
        """Validates an entire AuditDecision for sequential integrity and sorting."""
        status = decision.deletion_status
        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            raise ValidationError(f"Invalid deletion_status '{status}' on case '{decision.case_id}'")

        if status == "NOT_APPLICABLE":
            if decision.steps:
                raise ValidationError(f"NOT_APPLICABLE case '{decision.case_id}' must have 0 steps")
            return

        if not decision.steps:
            raise ValidationError(f"{status} case '{decision.case_id}' must have at least 1 step")

        has_findings = any(s.phase == "FINDING" for s in decision.steps)
        if status == "COMPLETE" and has_findings:
            raise ValidationError(f"COMPLETE case '{decision.case_id}' cannot contain findings")
        if status == "INCOMPLETE" and not has_findings:
            raise ValidationError(f"INCOMPLETE case '{decision.case_id}' must contain at least 1 finding")

        # Verify strict ordering
        for i in range(len(decision.steps) - 1):
            s1 = decision.steps[i]
            s2 = decision.steps[i + 1]

            k1 = (PHASE_ORDER[s1.phase], OP_ORDER[s1.operation], s1.system_id, s1.resource_id)
            k2 = (PHASE_ORDER[s2.phase], OP_ORDER[s2.operation], s2.system_id, s2.resource_id)
            if k1 > k2:
                raise ValidationError(
                    f"Sorting violation in case '{decision.case_id}': step {s1.step_no} > step {s2.step_no}"
                )

        # Verify 1-based sequential step numbers
        for idx, s in enumerate(decision.steps, start=1):
            if s.step_no != idx:
                raise ValidationError(
                    f"Step number violation in case '{decision.case_id}': expected {idx}, got {s.step_no}"
                )
            self.validate_step(s, status)

    def serialize_decision_row(self, decision: AuditDecision) -> Tuple[str, str, str]:
        """Validates and returns a single (case_id, deletion_status, steps_json) tuple."""
        self.validate_decision(decision)
        return (decision.case_id, decision.deletion_status, decision.steps_json)

    def serialize_to_csv_string(self, decisions: List[AuditDecision]) -> str:
        """Serializes a list of decisions to a compliant RFC-4180 CSV string."""
        buf = StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for d in decisions:
            row = self.serialize_decision_row(d)
            writer.writerow(row)
        return buf.getvalue()
