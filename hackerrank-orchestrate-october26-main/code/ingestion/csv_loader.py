"""Typed CSV loader for GhostTrace datasets."""

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


def parse_iso8601(dt_str: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp into a timezone-aware datetime object.
    
    Rejects timezone-naive strings, empty inputs, and malformed date strings.
    Converts any valid offset-aware timestamp to UTC.
    """
    if not isinstance(dt_str, str):
        raise ValueError(f"Expected timestamp string, got {type(dt_str).__name__}")
    s = dt_str.strip()
    if not s:
        raise ValueError("Empty timestamp string")

    # Standard UTC suffix 'Z'
    if s.endswith("Z"):
        try:
            dt = datetime.fromisoformat(s[:-1])
            return dt.replace(tzinfo=timezone.utc)
        except Exception as e:
            raise ValueError(f"Malformed ISO-8601 timestamp '{dt_str}': {e}") from e

    # Format with explicit offset (e.g. +00:00 or -05:00)
    try:
        dt = datetime.fromisoformat(s)
    except Exception as e:
        raise ValueError(f"Malformed ISO-8601 timestamp '{dt_str}': {e}") from e

    if dt.tzinfo is None:
        raise ValueError(
            f"Timezone-naive timestamp '{dt_str}' is invalid; must include explicit timezone (e.g. 'Z' or '+00:00')"
        )

    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class DeletionRequest:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str


@dataclass(frozen=True)
class UserIdentityRecord:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime


@dataclass(frozen=True)
class UserAuditLogRecord:
    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str


@dataclass(frozen=True)
class DeletionRuleRecord:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass(frozen=True)
class EvidenceFileRecord:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime


@dataclass(frozen=True)
class SystemActivityRecord:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


def load_deletion_requests(path: Path) -> List[DeletionRequest]:
    """Load and type-check deletion requests."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(
                DeletionRequest(
                    case_id=row["case_id"].strip(),
                    email=row["email"].strip(),
                    requested_at=parse_iso8601(row["requested_at"]),
                    reported_status=row["reported_status"].strip(),
                    reported_at=parse_iso8601(row["reported_at"]),
                    audit_at=parse_iso8601(row["audit_at"]),
                    request_text=row["request_text"].strip(),
                )
            )
    return records


def load_user_identities(path: Path) -> List[UserIdentityRecord]:
    """Load and type-check current user identities."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(
                UserIdentityRecord(
                    user_id=row["user_id"].strip(),
                    name=row["name"].strip(),
                    email=row["email"].strip(),
                    phone=row["phone"].strip(),
                    email_hash=row["email_hash"].strip(),
                    updated_at=parse_iso8601(row["updated_at"]),
                )
            )
    return records


def load_user_audit_log(path: Path) -> List[UserAuditLogRecord]:
    """Load and type-check historical identity audit log."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(
                UserAuditLogRecord(
                    audit_id=row["audit_id"].strip(),
                    user_id=row["user_id"].strip(),
                    event_time=parse_iso8601(row["event_time"]),
                    field_name=row["field_name"].strip(),
                    old_value=row["old_value"].strip(),
                    new_value=row["new_value"].strip(),
                )
            )
    return records


def load_deletion_rules(path: Path) -> List[DeletionRuleRecord]:
    """Load and type-check deletion rules."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(
                DeletionRuleRecord(
                    rule_id=row["rule_id"].strip(),
                    data_category=row["data_category"].strip(),
                    condition=row["condition"].strip(),
                    required_action=row["required_action"].strip(),
                )
            )
    return records


def load_evidence_manifest(path: Path) -> List[EvidenceFileRecord]:
    """Load and type-check evidence files manifest."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(
                EvidenceFileRecord(
                    file_id=row["file_id"].strip(),
                    file_path=row["file_path"].strip(),
                    origin=row["origin"].strip(),
                    captured_at=parse_iso8601(row["captured_at"]),
                )
            )
    return records


def load_system_activity(path: Path) -> List[SystemActivityRecord]:
    """Load and type-check system activity events."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(
                SystemActivityRecord(
                    activity_id=row["activity_id"].strip(),
                    event_time=parse_iso8601(row["event_time"]),
                    event_type=row["event_type"].strip(),
                    source_system=row["source_system"].strip(),
                    target_system=row["target_system"].strip(),
                    resource_id=row["resource_id"].strip(),
                    reported_result=row["reported_result"].strip(),
                    details=row["details"].strip(),
                )
            )
    return records
