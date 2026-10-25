"""Evaluation script for GhostTrace."""

import json
import logging
import sys
from pathlib import Path

# Ensure repository root is on sys.path for direct script execution
_repo_root = Path(__file__).resolve().parent.parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

try:
    from ..config import DATASET_DIR, SAMPLE_DELETION_REQUESTS_CSV, SAMPLE_OUTPUT_CSV
    from ..evidence.evidence_index import EvidenceIndex
    from ..identity.resolver import IdentityResolver
    from ..ingestion.csv_loader import (
        load_deletion_requests,
        load_system_activity,
        load_user_audit_log,
        load_user_identities,
    )
    from ..intent.classifier import IntentClassifier
    from ..planner.audit_planner import AuditPlanner
    from ..policy.rules_engine import PolicyEngine
except (ImportError, ValueError):
    from code.config import DATASET_DIR, SAMPLE_DELETION_REQUESTS_CSV, SAMPLE_OUTPUT_CSV
    from code.evidence.evidence_index import EvidenceIndex
    from code.identity.resolver import IdentityResolver
    from code.ingestion.csv_loader import (
        load_deletion_requests,
        load_system_activity,
        load_user_audit_log,
        load_user_identities,
    )
    from code.intent.classifier import IntentClassifier
    from code.planner.audit_planner import AuditPlanner
    from code.policy.rules_engine import PolicyEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("GhostTraceEval")


def run_evaluation(dataset_dir: Path = DATASET_DIR) -> None:
    """Executes sample evaluation against canonical ground truth."""
    logger.info("Starting GhostTrace Benchmark Evaluation...")

    identities = load_user_identities(dataset_dir / "user_identities.csv")
    audit_log = load_user_audit_log(dataset_dir / "user_audit_log.csv")
    resolver = IdentityResolver(identities, audit_log)
    classifier = IntentClassifier()
    engine = PolicyEngine(dataset_dir / "deletion_rules.csv")
    index = EvidenceIndex(dataset_dir / "evidence_files.csv", dataset_dir)
    system_activity = load_system_activity(dataset_dir / "system_activity.csv")

    planner = AuditPlanner(resolver, classifier, engine, index, system_activity)

    sample_requests = load_deletion_requests(SAMPLE_DELETION_REQUESTS_CSV)
    gt_rows = {}
    import csv
    with open(SAMPLE_OUTPUT_CSV, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            gt_rows[r["case_id"]] = r

    status_matches = 0
    step_matches = 0
    total_fields = 0
    matched_fields = 0

    for req in sample_requests:
        cid = req.case_id
        gt = gt_rows[cid]
        gt_status = gt["deletion_status"]
        gt_steps = json.loads(gt["steps_json"])

        decision = planner.plan_case(req)
        pred_status = decision.deletion_status
        pred_steps = json.loads(decision.steps_json)

        if pred_status == gt_status:
            status_matches += 1
        if len(pred_steps) == len(gt_steps):
            step_matches += 1

        for p_step, g_step in zip(pred_steps, gt_steps):
            for k in ["step_no", "phase", "operation", "system_id", "resource_id", "state", "evidence_id"]:
                total_fields += 1
                if p_step.get(k) == g_step.get(k):
                    matched_fields += 1

    print("\n" + "=" * 60)
    print("GHOSTTRACE SAMPLE BENCHMARK EVALUATION SUMMARY")
    print("=" * 60)
    print(f"Sample Requests Audited:      {len(sample_requests)}")
    print(f"Status Accuracy:              {status_matches} / {len(sample_requests)} ({status_matches/len(sample_requests)*100:.1f}%)")
    print(f"Step-Count Accuracy:          {step_matches} / {len(sample_requests)} ({step_matches/len(sample_requests)*100:.1f}%)")
    print(f"Field-Level Property Parity:  {matched_fields} / {total_fields} ({matched_fields/total_fields*100:.1f}%)")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run_evaluation()
