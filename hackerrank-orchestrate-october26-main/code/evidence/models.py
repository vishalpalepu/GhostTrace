"""Data structures for provenance-tracked evidence observations."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class ExtractedObservation:
    """A verified, provenance-tracked observation extracted from an evidence file.
    
    Every observation preserves source file identity, target system and resource,
    subject linkage, observed physical/logical state, observation time, manifest
    capture time, extraction method, and any uncertainty.
    """
    file_id: str                          # Manifest evidence ID (e.g. 'evidence_54')
    source_path: str                      # Relative file path (e.g. 'evidence/databases/...')
    system_id: str                        # Target service/system (e.g. 'account_service')
    resource_id: str                      # Target resource ID (e.g. 'account_001', 'backup_3870')
    observed_state: str                   # 'PRESENT', 'ABSENT', 'REDACTED', 'ANONYMIZED', 'ACTIVE', 'BLOCKED', 'DISABLED'
    data_category: Optional[str] = None   # Policy category (e.g. 'USER_PROFILE', 'BACKUP_ARCHIVE')
    subject_id: Optional[str] = None      # Resolved internal user ID (e.g. 'user_123')
    subject_email: Optional[str] = None   # Associated email address (lowercased)
    subject_phone: Optional[str] = None   # Associated phone number
    observation_time: Optional[datetime] = None  # Point-in-time timestamp inside record/file
    captured_at: Optional[datetime] = None       # Manifest captured_at timestamp
    extraction_method: str = "UNKNOWN"    # 'SQL_EXEC', 'JSON_PARSE', 'LOG_PARSE', 'PDF_DECODE', 'TXT_PARSE'
    details: Dict[str, Any] = field(default_factory=dict)
    uncertainty: Optional[str] = None     # Any extraction or interpretation uncertainty
