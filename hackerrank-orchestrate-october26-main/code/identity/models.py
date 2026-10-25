"""Data models for identity timelines and ownership intervals."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set


@dataclass(frozen=True)
class OwnershipInterval:
    """Represents ownership of an attribute by a user over [start_time, end_time)."""
    attribute_type: str  # 'email', 'phone', 'email_hash'
    normalized_value: str
    user_id: str
    start_time: Optional[datetime]  # None means -infinity (inferred account inception)
    end_time: Optional[datetime]    # None means +infinity (ongoing active)
    is_start_observed: bool = False  # True if bounded by an observed audit event
    is_end_observed: bool = False    # True if bounded by an observed audit event
    source_event_id: Optional[str] = None

    def contains(self, dt: datetime) -> bool:
        """Evaluate half-open interval: start_time <= dt < end_time."""
        if self.start_time is not None and dt < self.start_time:
            return False
        if self.end_time is not None and dt >= self.end_time:
            return False
        return True


@dataclass
class UserTimeline:
    """Complete reconstructed identity timeline and historical aliases for a user."""
    user_id: str
    name: str
    current_email: str
    current_phone: str
    current_email_hash: str
    updated_at: datetime
    all_emails: Set[str] = field(default_factory=set)
    all_phones: Set[str] = field(default_factory=set)
    all_email_hashes: Set[str] = field(default_factory=set)
    intervals: List[OwnershipInterval] = field(default_factory=list)


@dataclass(frozen=True)
class IdentityResolutionResult:
    """The outcome of resolving a deletion request identifier against identity timelines."""
    user_id: Optional[str]
    timeline: Optional[UserTimeline]
    matched_by: str  # 'current_email', 'historical_email', 'unmatched', 'ambiguous'
    confidence: float
    notes: str
