"""GhostTrace CLI entrypoint and orchestrator."""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

# Ensure repository root is on sys.path for direct execution (e.g. python code/main.py)
_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

try:
    from .config import (
        DATASET_DIR,
        DELETION_REQUESTS_CSV,
        DELETION_RULES_CSV,
        EVIDENCE_FILES_CSV,
        SAMPLE_DELETION_REQUESTS_CSV,
        SYSTEM_ACTIVITY_CSV,
        USER_AUDIT_LOG_CSV,
        USER_IDENTITIES_CSV,
    )
    from .evidence.evidence_index import EvidenceIndex
    from .identity.resolver import IdentityResolver
    from .ingestion.csv_loader import (
        DeletionRequest,
        load_deletion_requests,
        load_system_activity,
        load_user_audit_log,
        load_user_identities,
    )
    from .intent.classifier import IntentClassifier
    from .planner.audit_planner import AuditPlanner
    from .planner.models import AuditDecision
    from .policy.rules_engine import PolicyEngine
    from .serializer.csv_serializer import CsvSerializer
except (ImportError, ValueError):
    from code.config import (
        DATASET_DIR,
        DELETION_REQUESTS_CSV,
        DELETION_RULES_CSV,
        EVIDENCE_FILES_CSV,
        SAMPLE_DELETION_REQUESTS_CSV,
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
    )
    from code.intent.classifier import IntentClassifier
    from code.planner.audit_planner import AuditPlanner
    from code.planner.models import AuditDecision
    from code.policy.rules_engine import PolicyEngine
    from code.serializer.csv_serializer import CsvSerializer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("GhostTrace")


class GhostTracePipeline:
    """End-to-end audit engine combining identity, intent, policy, evidence, and planner."""

    def __init__(self, dataset_dir: Path = DATASET_DIR) -> None:
        self.dataset_dir = dataset_dir
        logger.info("Initializing GhostTrace Pipeline with dataset: %s", dataset_dir)

        # 1. Ingestion & Identity Resolution
        identities = load_user_identities(dataset_dir / "user_identities.csv")
        audit_log = load_user_audit_log(dataset_dir / "user_audit_log.csv")
        self.resolver = IdentityResolver(identities, audit_log)
        logger.info("Loaded %d identities, %d audit log entries", len(identities), len(audit_log))

        # 2. Intent Classifier & Policy Engine
        self.intent_classifier = IntentClassifier()
        self.policy_engine = PolicyEngine(dataset_dir / "deletion_rules.csv")
        logger.info("Policy engine loaded %d rules", len(self.policy_engine.rules))

        # 3. Evidence Indexing
        manifest_path = dataset_dir / "evidence_files.csv"
        self.evidence_index = EvidenceIndex(manifest_path, dataset_dir)
        logger.info(
            "Evidence index built: %d parsed files, %d total observations",
            len(self.evidence_index.parsed_files),
            len(self.evidence_index.observations),
        )

        # 4. Activity Logs
        activity_path = dataset_dir / "system_activity.csv"
        self.system_activity = load_system_activity(activity_path)
        logger.info("Loaded %d system activity records", len(self.system_activity))

        # 5. Audit Planner & Strict Serializer
        self.planner = AuditPlanner(
            self.resolver,
            self.intent_classifier,
            self.policy_engine,
            self.evidence_index,
            self.system_activity,
        )
        valid_eids = {f.file_id for f in self.evidence_index.manifest_records}
        self.serializer = CsvSerializer(valid_evidence_ids=valid_eids)

    def audit_requests(self, requests: List[DeletionRequest]) -> List[AuditDecision]:
        """Audits a list of requests and returns validated AuditDecisions."""
        decisions: List[AuditDecision] = []
        for idx, req in enumerate(requests, start=1):
            decision = self.planner.plan_case(req)
            self.serializer.validate_decision(decision)
            decisions.append(decision)
            if idx % 100 == 0 or idx == len(requests):
                logger.info("Audited %d / %d requests...", idx, len(requests))
        return decisions

    def run_and_serialize(self, requests_csv: Path, output_csv: Path) -> None:
        """Loads requests from requests_csv, executes audit, and writes output_csv."""
        requests = load_deletion_requests(requests_csv)
        logger.info("Loaded %d requests from %s", len(requests), requests_csv)

        decisions = self.audit_requests(requests)
        csv_content = self.serializer.serialize_to_csv_string(decisions)

        output_csv.parent.mkdir(parents=True, exist_ok=True)
        output_csv.write_text(csv_content, encoding="utf-8")
        logger.info("Successfully serialized %d decisions to %s", len(decisions), output_csv)


def main():
    parser = argparse.ArgumentParser(description="GhostTrace Deletion Verification Engine")
    parser.add_argument("--mode", choices=["sample", "eval", "all"], default="eval", help="Execution mode")
    parser.add_argument("--requests", type=Path, default=None, help="Path to input requests CSV")
    parser.add_argument("--output", type=Path, default=None, help="Path to output CSV")
    parser.add_argument("--dataset-dir", type=Path, default=DATASET_DIR, help="Path to dataset directory")
    args = parser.parse_args()

    pipeline = GhostTracePipeline(args.dataset_dir)

    if args.mode == "sample":
        req_path = args.requests or (args.dataset_dir / "sample_deletion_requests.csv")
        out_path = args.output or (args.dataset_dir / "sample_output_reproduced.csv")
        pipeline.run_and_serialize(req_path, out_path)
    elif args.mode in ("eval", "all"):
        req_path = args.requests or (args.dataset_dir / "deletion_requests.csv")
        out_path = args.output or Path("output.csv")
        pipeline.run_and_serialize(req_path, out_path)


if __name__ == "__main__":
    main()
