"""Deterministic temporal identity resolution engine."""

from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from .models import IdentityResolutionResult, OwnershipInterval, UserTimeline
from ..ingestion.csv_loader import UserAuditLogRecord, UserIdentityRecord


class IdentityResolver:
    """Reconstructs temporal identity timelines and resolves request identifiers."""

    def __init__(
        self,
        identities: List[UserIdentityRecord],
        audit_logs: List[UserAuditLogRecord],
    ) -> None:
        self.timelines: Dict[str, UserTimeline] = {}
        # Ownership index: (attribute_type, normalized_value) -> List[OwnershipInterval]
        self.ownership_index: Dict[Tuple[str, str], List[OwnershipInterval]] = defaultdict(list)
        self._build_timelines(identities, audit_logs)

    @staticmethod
    def normalize_email(email: str) -> str:
        return email.strip().lower()

    @staticmethod
    def normalize_phone(phone: str) -> str:
        return phone.strip()

    @staticmethod
    def normalize_hash(email_hash: str) -> str:
        return email_hash.strip().lower()

    def _build_timelines(
        self,
        identities: List[UserIdentityRecord],
        audit_logs: List[UserAuditLogRecord],
    ) -> None:
        # Group audit logs by user_id and field_name
        logs_by_user_field: Dict[Tuple[str, str], List[UserAuditLogRecord]] = defaultdict(list)
        for log in audit_logs:
            logs_by_user_field[(log.user_id, log.field_name)].append(log)

        # Sort logs chronologically for each group
        for group in logs_by_user_field.values():
            group.sort(key=lambda x: x.event_time)

        # Build each user's timeline
        for ident in identities:
            uid = ident.user_id
            timeline = UserTimeline(
                user_id=uid,
                name=ident.name,
                current_email=self.normalize_email(ident.email),
                current_phone=self.normalize_phone(ident.phone),
                current_email_hash=self.normalize_hash(ident.email_hash),
                updated_at=ident.updated_at,
            )

            # Process attributes
            self._process_attribute_timeline(
                timeline,
                "email",
                ident.email,
                logs_by_user_field.get((uid, "email"), []),
                self.normalize_email,
            )
            self._process_attribute_timeline(
                timeline,
                "phone",
                ident.phone,
                logs_by_user_field.get((uid, "phone"), []),
                self.normalize_phone,
            )
            self._process_attribute_timeline(
                timeline,
                "email_hash",
                ident.email_hash,
                logs_by_user_field.get((uid, "email_hash"), []),
                self.normalize_hash,
            )

            self.timelines[uid] = timeline

        # Populate raw ownership index
        raw_index: Dict[Tuple[str, str], List[OwnershipInterval]] = defaultdict(list)
        for timeline in self.timelines.values():
            for interval in timeline.intervals:
                key = (interval.attribute_type, interval.normalized_value)
                raw_index[key].append(interval)

        # Reconcile cross-user intervals (e.g. historical reassignment)
        for key, intervals in raw_index.items():
            reconciled = self._reconcile_cross_user_intervals(intervals)
            self.ownership_index[key] = reconciled

    def _reconcile_cross_user_intervals(
        self, intervals: List[OwnershipInterval]
    ) -> List[OwnershipInterval]:
        """Reconcile intervals for the same attribute across multiple users."""
        if len(intervals) <= 1:
            return intervals

        # Check if intervals belong to different users
        uids = {inv.user_id for inv in intervals}
        if len(uids) <= 1:
            return intervals

        # When multiple users share an identifier historically:
        # If user A has an end_time T (released it), and user B has start_time None (unbounded past),
        # clip user B's start_time to T so intervals do not conflict.
        reconciled = []
        release_times = [inv.end_time for inv in intervals if inv.end_time is not None]
        latest_release = max(release_times) if release_times else None

        for inv in intervals:
            if inv.end_time is not None:
                reconciled.append(inv)
            else:
                if inv.start_time is None and latest_release is not None:
                    clipped = OwnershipInterval(
                        attribute_type=inv.attribute_type,
                        normalized_value=inv.normalized_value,
                        user_id=inv.user_id,
                        start_time=latest_release,
                        end_time=inv.end_time,
                        is_start_observed=True,
                        is_end_observed=inv.is_end_observed,
                        source_event_id=inv.source_event_id,
                    )
                    reconciled.append(clipped)
                else:
                    reconciled.append(inv)

        return reconciled

    def _process_attribute_timeline(
        self,
        timeline: UserTimeline,
        attr_type: str,
        current_val: str,
        logs: List[UserAuditLogRecord],
        normalizer,
    ) -> None:
        norm_curr = normalizer(current_val)
        if attr_type == "email":
            timeline.all_emails.add(norm_curr)
        elif attr_type == "phone":
            timeline.all_phones.add(norm_curr)
        elif attr_type == "email_hash":
            timeline.all_email_hashes.add(norm_curr)

        if not logs:
            # No changes: current value was valid indefinitely [None, None)
            interval = OwnershipInterval(
                attribute_type=attr_type,
                normalized_value=norm_curr,
                user_id=timeline.user_id,
                start_time=None,
                end_time=None,
                is_start_observed=False,
                is_end_observed=False,
                source_event_id=None,
            )
            timeline.intervals.append(interval)
            return

        # Logs exist: chain chronologically
        prev_time = None
        for log in logs:
            norm_old = normalizer(log.old_value)
            norm_new = normalizer(log.new_value)

            if attr_type == "email":
                timeline.all_emails.add(norm_old)
                timeline.all_emails.add(norm_new)
            elif attr_type == "phone":
                timeline.all_phones.add(norm_old)
                timeline.all_phones.add(norm_new)
            elif attr_type == "email_hash":
                timeline.all_email_hashes.add(norm_old)
                timeline.all_email_hashes.add(norm_new)

            # Interval for old_value: [prev_time, log.event_time)
            interval_old = OwnershipInterval(
                attribute_type=attr_type,
                normalized_value=norm_old,
                user_id=timeline.user_id,
                start_time=prev_time,
                end_time=log.event_time,
                is_start_observed=(prev_time is not None),
                is_end_observed=True,
                source_event_id=log.audit_id,
            )
            timeline.intervals.append(interval_old)
            prev_time = log.event_time

        # Final value from last event_time to +inf
        interval_final = OwnershipInterval(
            attribute_type=attr_type,
            normalized_value=norm_curr,
            user_id=timeline.user_id,
            start_time=prev_time,
            end_time=None,
            is_start_observed=(prev_time is not None),
            is_end_observed=False,
            source_event_id=logs[-1].audit_id,
        )
        timeline.intervals.append(interval_final)

    def resolve_email(self, email: str, requested_at: datetime) -> IdentityResolutionResult:
        """Resolve a request email and requested_at timestamp to a canonical user_id."""
        norm_email = self.normalize_email(email)
        intervals = self.ownership_index.get(("email", norm_email), [])

        if not intervals:
            return IdentityResolutionResult(
                user_id=None,
                timeline=None,
                matched_by="unmatched",
                confidence=0.0,
                notes=f"Email '{email}' not found in current snapshot or audit history.",
            )

        # 1. Filter intervals that contain requested_at using half-open [start, end)
        matching_intervals = [inv for inv in intervals if inv.contains(requested_at)]

        # Unique users owning this email at requested_at
        active_uids = {inv.user_id for inv in matching_intervals}

        if len(active_uids) == 1:
            uid = next(iter(active_uids))
            timeline = self.timelines[uid]
            matched_by = "current_email" if norm_email == timeline.current_email else "historical_email"
            return IdentityResolutionResult(
                user_id=uid,
                timeline=timeline,
                matched_by=matched_by,
                confidence=1.0,
                notes=f"Resolved via {matched_by} valid at requested_at ({requested_at.isoformat()}).",
            )

        if len(active_uids) > 1:
            # Conflicting ownership at the same timestamp
            return IdentityResolutionResult(
                user_id=None,
                timeline=None,
                matched_by="ambiguous",
                confidence=0.0,
                notes=f"Conflicting ownership for '{norm_email}' at {requested_at.isoformat()} across users {active_uids}.",
            )

        # 2. No interval strictly contained requested_at (e.g. requested_at after deletion or before earliest log)
        # Check if only ONE user ever owned this email across all intervals
        all_uids = {inv.user_id for inv in intervals}
        if len(all_uids) == 1:
            uid = next(iter(all_uids))
            timeline = self.timelines[uid]
            matched_by = "current_email" if norm_email == timeline.current_email else "historical_email"
            return IdentityResolutionResult(
                user_id=uid,
                timeline=timeline,
                matched_by=matched_by,
                confidence=0.95,
                notes=f"Resolved to sole historical owner {uid}; requested_at ({requested_at.isoformat()}) outside tracked interval.",
            )

        # Multiple users held this email in different intervals, but none active at requested_at
        return IdentityResolutionResult(
            user_id=None,
            timeline=None,
            matched_by="ambiguous",
            confidence=0.0,
            notes=f"Multiple historical owners {all_uids} for '{norm_email}', but none active at {requested_at.isoformat()}.",
        )

    def get_timeline(self, user_id: str) -> Optional[UserTimeline]:
        """Retrieve the timeline for a given user_id."""
        return self.timelines.get(user_id)
