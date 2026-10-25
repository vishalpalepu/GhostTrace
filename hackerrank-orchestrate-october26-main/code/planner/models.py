"""Data models and ordering contracts for audit steps and planner decisions."""

import json
from dataclasses import dataclass
from typing import Any, Dict, List


PHASE_ORDER: Dict[str, int] = {
    "FINDING": 0,
    "REMEDIATION": 1,
    "VERIFICATION": 2,
}

OP_ORDER: Dict[str, int] = {
    # Phase 0: Findings
    "REPORT_REMAINING_RECORD": 10,
    "REPORT_EXPOSED_PII": 20,
    "REPORT_ACTIVE_DATA_FLOW": 30,
    "REPORT_RESTORE_RISK": 40,
    # Phase 1: Remediation
    "DISABLE_DATA_FLOW": 110,
    "BLOCK_RESTORE": 120,
    "DELETE_RECORD": 130,
    "REDACT_RECORD": 140,
    "ANONYMIZE_RECORD": 150,
    # Phase 2: Verification
    "VERIFY_RECORD_ABSENT": 210,
    "VERIFY_RECORD_PRESENT": 220,
    "VERIFY_RECORD_REDACTED": 230,
    "VERIFY_RECORD_ANONYMIZED": 240,
    "VERIFY_DATA_FLOW_DISABLED": 250,
    "VERIFY_RESTORE_BLOCKED": 260,
}

# 1-to-1 canonical state corresponding to each operation
OP_STATE_MAP: Dict[str, str] = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}


@dataclass
class AuditStep:
    """A single deterministic audit finding, remediation, or verification step."""

    step_no: int
    phase: str
    operation: str
    system_id: str
    resource_id: str
    state: str
    evidence_id: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert step to exact dictionary matching canonical schema."""
        return {
            "evidence_id": self.evidence_id,
            "operation": self.operation,
            "phase": self.phase,
            "resource_id": self.resource_id,
            "state": self.state,
            "step_no": self.step_no,
            "system_id": self.system_id,
        }


@dataclass
class AuditDecision:
    """The complete audit decision for a single deletion request case."""

    case_id: str
    deletion_status: str  # 'COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'
    steps: List[AuditStep]

    @property
    def steps_json(self) -> str:
        """Serializes steps into compact JSON with sorted keys matching canonical format."""
        if self.deletion_status == "NOT_APPLICABLE" or not self.steps:
            return "[]"
        return json.dumps([s.to_dict() for s in self.steps], sort_keys=True, separators=(",", ":"))

    @property
    def is_complete(self) -> bool:
        return self.deletion_status == "COMPLETE"

    @property
    def is_incomplete(self) -> bool:
        return self.deletion_status == "INCOMPLETE"

    @property
    def is_not_applicable(self) -> bool:
        return self.deletion_status == "NOT_APPLICABLE"
