"""Unit tests for deterministic temporal identity resolution and ingestion hardening."""

import unittest
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from code.config import (
    DELETION_REQUESTS_CSV,
    SAMPLE_DELETION_REQUESTS_CSV,
    USER_AUDIT_LOG_CSV,
    USER_IDENTITIES_CSV,
)
from code.ingestion.csv_loader import (
    load_deletion_requests,
    load_user_audit_log,
    load_user_identities,
    parse_iso8601,
    UserIdentityRecord,
    UserAuditLogRecord,
)
from code.identity.models import OwnershipInterval
from code.identity.resolver import IdentityResolver


class TestTemporalIdentityResolution(unittest.TestCase):
    """Comprehensive unit tests for identity resolution and interval semantics."""

    @classmethod
    def setUpClass(cls):
        cls.identities = load_user_identities(USER_IDENTITIES_CSV)
        cls.audit_logs = load_user_audit_log(USER_AUDIT_LOG_CSV)
        cls.resolver = IdentityResolver(cls.identities, cls.audit_logs)
        cls.sample_requests = load_deletion_requests(SAMPLE_DELETION_REQUESTS_CSV)
        cls.eval_requests = load_deletion_requests(DELETION_REQUESTS_CSV)

    def test_hardened_parse_iso8601(self):
        """Test strict ISO-8601 UTC parsing and error handling."""
        # Valid standard UTC with Z
        dt1 = parse_iso8601("2026-08-18T09:14:00Z")
        self.assertEqual(dt1, datetime(2026, 8, 18, 9, 14, 0, tzinfo=timezone.utc))

        # Valid standard UTC with +00:00
        dt2 = parse_iso8601("2026-08-18T09:14:00+00:00")
        self.assertEqual(dt2, datetime(2026, 8, 18, 9, 14, 0, tzinfo=timezone.utc))

        # Valid offset converted to UTC (e.g. +05:30)
        dt3 = parse_iso8601("2026-08-18T14:44:00+05:30")
        self.assertEqual(dt3, datetime(2026, 8, 18, 9, 14, 0, tzinfo=timezone.utc))

        # Year boundary instant
        dt4 = parse_iso8601("2026-12-31T23:59:59Z")
        self.assertEqual(dt4, datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc))

        # Rejection: Timezone-naive string
        with self.assertRaises(ValueError) as ctx_naive:
            parse_iso8601("2026-08-18 09:14:00")
        self.assertIn("Timezone-naive", str(ctx_naive.exception))

        # Rejection: Malformed date string
        with self.assertRaises(ValueError):
            parse_iso8601("not_a_real_timestamp")

        # Rejection: Empty string
        with self.assertRaises(ValueError):
            parse_iso8601("")

        # Rejection: Non-string type
        with self.assertRaises(ValueError):
            parse_iso8601(123456789)

    def test_half_open_interval_boundaries(self):
        """Test [start, end) exact boundary semantics."""
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

        inv = OwnershipInterval(
            attribute_type="email",
            normalized_value="test@example.com",
            user_id="user_test",
            start_time=t1,
            end_time=t2,
            is_start_observed=True,
            is_end_observed=True,
        )

        # Before start
        self.assertFalse(inv.contains(t1 - timedelta(seconds=1)))
        # At start (inclusive)
        self.assertTrue(inv.contains(t1))
        # Within interval
        self.assertTrue(inv.contains(t1 + timedelta(days=30)))
        # Just before end
        self.assertTrue(inv.contains(t2 - timedelta(seconds=1)))
        # At end (exclusive)
        self.assertFalse(inv.contains(t2))
        # After end
        self.assertFalse(inv.contains(t2 + timedelta(seconds=1)))

    def test_infinite_interval_boundaries(self):
        """Test intervals with -inf start or +inf end."""
        t_ref = datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc)

        # [-inf, +inf)
        inv_all = OwnershipInterval("email", "all@ex.com", "u1", None, None)
        self.assertTrue(inv_all.contains(t_ref))
        self.assertFalse(inv_all.is_start_observed)
        self.assertFalse(inv_all.is_end_observed)

        # [-inf, t_ref)
        inv_past = OwnershipInterval("email", "past@ex.com", "u1", None, t_ref, is_end_observed=True)
        self.assertTrue(inv_past.contains(t_ref - timedelta(days=1)))
        self.assertFalse(inv_past.contains(t_ref))
        self.assertFalse(inv_past.is_start_observed)
        self.assertTrue(inv_past.is_end_observed)

        # [t_ref, +inf)
        inv_future = OwnershipInterval("email", "future@ex.com", "u1", t_ref, None, is_start_observed=True)
        self.assertFalse(inv_future.contains(t_ref - timedelta(days=1)))
        self.assertTrue(inv_future.contains(t_ref))
        self.assertTrue(inv_future.contains(t_ref + timedelta(days=100)))
        self.assertTrue(inv_future.is_start_observed)
        self.assertFalse(inv_future.is_end_observed)

    def test_multi_hop_historical_timeline(self):
        """Test user_10 who underwent 2 email mutations."""
        timeline = self.resolver.get_timeline("user_10")
        self.assertIsNotNone(timeline)
        self.assertEqual(len(timeline.all_emails), 3)
        self.assertIn("nadia.ionescu@yahoo.com", timeline.all_emails)
        self.assertIn("nadia.petrescu@yahoo.com", timeline.all_emails)
        self.assertIn("n.petrescu@yahoo.com", timeline.all_emails)

        # Request at 2025-06-01 with earliest email -> matches user_10
        res1 = self.resolver.resolve_email(
            "nadia.ionescu@yahoo.com",
            datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(res1.user_id, "user_10")

        # Request at 2026-02-01 with intermediate email -> matches user_10
        res2 = self.resolver.resolve_email(
            "nadia.petrescu@yahoo.com",
            datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(res2.user_id, "user_10")

        # Request at 2026-08-01 with current email -> matches user_10
        res3 = self.resolver.resolve_email(
            "n.petrescu@yahoo.com",
            datetime(2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(res3.user_id, "user_10")
        self.assertEqual(res3.matched_by, "current_email")

    def test_reassignment_handling(self):
        """Synthetic test: Reassignment of email between two distinct users."""
        t_split = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
        identities = [
            UserIdentityRecord("uA", "User A", "old_a@test.com", "111", "hA", t_split),
            UserIdentityRecord("uB", "User B", "shared@test.com", "222", "hB", t_split),
        ]
        # User A used shared@test.com until t_split, then switched to old_a@test.com
        audit = [
            UserAuditLogRecord("aud1", "uA", t_split, "email", "shared@test.com", "old_a@test.com")
        ]

        resolver = IdentityResolver(identities, audit)

        # Before t_split -> User A
        res_before = resolver.resolve_email("shared@test.com", t_split - timedelta(days=10))
        self.assertEqual(res_before.user_id, "uA")

        # At or after t_split -> User B (current owner)
        res_after = resolver.resolve_email("shared@test.com", t_split + timedelta(days=10))
        self.assertEqual(res_after.user_id, "uB")

    def test_zero_name_based_merging(self):
        """Verify that similar names do NOT result in cross-user attribution."""
        priya1 = self.resolver.get_timeline("user_07")  # Priya Raman
        self.assertIsNotNone(priya1)
        self.assertEqual(priya1.name, "Priya Raman")

        # Ensure Priya Raman cannot be resolved by an unrelated email even with identical name tokens
        res = self.resolver.resolve_email(
            "p.ramanathan@gmail.com",
            datetime(2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc),
        )
        self.assertNotEqual(res.user_id, "user_07")

    def test_independent_attribution_audit(self):
        """Independent ground truth cross-validation across all 550 requests."""
        # Build independent expected mappings directly from raw records
        current_map = {u.email.strip().lower(): u.user_id for u in self.identities}
        audit_map = defaultdict(set)
        for a in self.audit_logs:
            if a.field_name == "email":
                if a.old_value:
                    audit_map[a.old_value.strip().lower()].add(a.user_id)
                if a.new_value:
                    audit_map[a.new_value.strip().lower()].add(a.user_id)

        all_requests = self.sample_requests + self.eval_requests
        self.assertEqual(len(all_requests), 550)

        for req in all_requests:
            norm_email = req.email.strip().lower()
            # Derive expected user_id independently
            if norm_email in current_map:
                expected_uid = current_map[norm_email]
            elif norm_email in audit_map:
                uids = audit_map[norm_email]
                self.assertEqual(len(uids), 1, f"Ambiguous audit mapping for {norm_email}")
                expected_uid = next(iter(uids))
            else:
                expected_uid = None

            self.assertIsNotNone(expected_uid, f"Request {req.case_id} email {req.email} missing from dataset")

            # Check resolver
            res = self.resolver.resolve_email(req.email, req.requested_at)
            self.assertEqual(
                res.user_id,
                expected_uid,
                f"Attribution mismatch on {req.case_id}: expected {expected_uid}, got {res.user_id}"
            )
            self.assertIn(res.matched_by, ("current_email", "historical_email"))
            self.assertGreaterEqual(res.confidence, 0.95)


if __name__ == "__main__":
    unittest.main()
