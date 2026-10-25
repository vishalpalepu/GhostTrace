"""Configuration and path definitions for GhostTrace."""

from pathlib import Path

# Paths
CODE_DIR = Path(__file__).resolve().parent
REPO_ROOT = CODE_DIR.parent
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"

# Input CSVs
DELETION_REQUESTS_CSV = DATASET_DIR / "deletion_requests.csv"
SAMPLE_DELETION_REQUESTS_CSV = DATASET_DIR / "sample_deletion_requests.csv"
SAMPLE_OUTPUT_CSV = DATASET_DIR / "sample_output.csv"
USER_IDENTITIES_CSV = DATASET_DIR / "user_identities.csv"
USER_AUDIT_LOG_CSV = DATASET_DIR / "user_audit_log.csv"
SYSTEM_ACTIVITY_CSV = DATASET_DIR / "system_activity.csv"
DELETION_RULES_CSV = DATASET_DIR / "deletion_rules.csv"
EVIDENCE_FILES_CSV = DATASET_DIR / "evidence_files.csv"

# Output CSV
SUBMISSION_OUTPUT_CSV = REPO_ROOT / "output.csv"

# Date format
ISO_8601_FMT = "%Y-%m-%dT%H:%M:%SZ"
