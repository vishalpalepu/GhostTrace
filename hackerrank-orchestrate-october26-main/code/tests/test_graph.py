"""Unit tests for evidence ingestion, temporal filtering, and Resurrection Graph."""

import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from code.config import (
    DATASET_DIR,
    EVIDENCE_FILES_CSV,
    SAMPLE_DELETION_REQUESTS_CSV,
    USER_AUDIT_LOG_CSV,
    USER_IDENTITIES_CSV,
)
from code.evidence.evidence_index import EvidenceIndex
from code.evidence.models import ExtractedObservation
from code.graph.builder import GraphBuilder
from code.identity.resolver import IdentityResolver
from code.ingestion.csv_loader import (
    load_deletion_requests,
    load_evidence_manifest,
    load_user_audit_log,
    load_user_identities,
)


class TestEvidenceIngestionAndGraph(unittest.TestCase):
    """Test suite for evidence indexing, temporal reconstruction, and graph building."""

    @classmethod
    def setUpClass(cls):
        cls.identities = load_user_identities(USER_IDENTITIES_CSV)
        cls.audit_log = load_user_audit_log(USER_AUDIT_LOG_CSV)
        cls.resolver = IdentityResolver(cls.identities, cls.audit_log)
        cls.evidence_index = EvidenceIndex(EVIDENCE_FILES_CSV, DATASET_DIR)
        cls.graph_builder = GraphBuilder(cls.resolver, cls.evidence_index)
        cls.sample_requests = load_deletion_requests(SAMPLE_DELETION_REQUESTS_CSV)
        cls.sample_by_id = {r.case_id: r for r in cls.sample_requests}

    def test_full_evidence_manifest_coverage(self):
        """Verify that all 94 evidence files are parsed with 0 unhandled failures."""
        manifest = load_evidence_manifest(EVIDENCE_FILES_CSV)
        self.assertEqual(len(manifest), 94)
        self.assertEqual(len(self.evidence_index.parsed_files), 94)
        self.assertEqual(len(self.evidence_index.failed_files), 0)
        self.assertGreater(len(self.evidence_index.observations), 3000)

    def test_surviving_record_in_replica_after_primary_deletion(self):
        """Test case_05: account record surviving in replica (evidence_54) despite deletion claim."""
        req = self.sample_by_id["case_05"]
        graph = self.graph_builder.build_graph(req.case_id, req.email, req.audit_at)

        # In evidence_54, account_005 is still present in failover replica
        acc_key = ("account_service", "account_005")
        self.assertIn(acc_key, graph.resources)
        res_node = graph.resources[acc_key]
        self.assertEqual(res_node.state, "PRESENT")
        self.assertEqual(res_node.provenance_file_id, "evidence_54")

    def test_past_successful_sync_with_later_disabled_state(self):
        """Past SUCCESS sync must not override direct evidence that connector is currently disabled."""
        req = self.sample_by_id["case_26"]
        graph = self.graph_builder.build_graph(req.case_id, req.email, req.audit_at)

        # data_flow_6244 is verified as DISABLED in evidence_92
        self.assertIn("data_flow_6244", graph.processes)
        proc = graph.processes["data_flow_6244"]
        self.assertEqual(proc.state, "DISABLED")
        self.assertFalse(proc.is_active)
        self.assertEqual(proc.provenance_file_id, "evidence_92")

    def test_process_with_affirmative_active_evidence(self):
        """Active sync process confirmed by affirmative evidence (e.g. data_flow_9522 in case_11)."""
        req = self.sample_by_id["case_11"]
        graph = self.graph_builder.build_graph(req.case_id, req.email, req.audit_at)

        # In evidence_03, data_flow_9522 is explicitly ACTIVE
        self.assertIn("data_flow_9522", graph.processes)
        proc = graph.processes["data_flow_9522"]
        self.assertEqual(proc.state, "ACTIVE")
        self.assertTrue(proc.is_active)
        self.assertEqual(proc.provenance_file_id, "evidence_03")

    def test_backup_restoration_allowed_can_be_blocked(self):
        """Backup archive with active restore capability (case_09: backup_4978)."""
        req = self.sample_by_id["case_09"]
        graph = self.graph_builder.build_graph(req.case_id, req.email, req.audit_at)

        self.assertIn("backup_4978", graph.restore_paths)
        backup = graph.restore_paths["backup_4978"]
        self.assertEqual(backup.state, "ACTIVE")
        self.assertTrue(backup.restore_allowed)
        self.assertTrue(backup.can_be_blocked)
        self.assertEqual(backup.provenance_file_id, "evidence_93")

    def test_backup_restoration_already_blocked(self):
        """Backup archive with restore access confirmed blocked (case_26: backup_3120)."""
        req = self.sample_by_id["case_26"]
        graph = self.graph_builder.build_graph(req.case_id, req.email, req.audit_at)

        self.assertIn("backup_3120", graph.restore_paths)
        backup = graph.restore_paths["backup_3120"]
        self.assertEqual(backup.state, "BLOCKED")
        self.assertFalse(backup.restore_allowed)
        self.assertEqual(backup.provenance_file_id, "evidence_92")

    def test_temporal_cutoff_exclusion(self):
        """Observations with captured_at or observation_time > audit_at must be strictly excluded."""
        cutoff = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
        obs_past = self.evidence_index.get_observations_for_subject(
            user_id="user_01",
            emails=["amina.elmasri@gmail.com"],
            cutoff=cutoff,
        )
        for obs in obs_past:
            self.assertLessEqual(obs.captured_at, cutoff)
            if obs.observation_time:
                self.assertLessEqual(obs.observation_time, cutoff)

    def test_account_tombstone_distinction(self):
        """Verify distinction between redacted tombstone (case_31) and direct PII exposure (case_32)."""
        # Case 31: clean redacted tombstone
        req31 = self.sample_by_id["case_31"]
        graph31 = self.graph_builder.build_graph(req31.case_id, req31.email, req31.audit_at)
        tomb_key_31 = ("identity_service", "tombstone_440")
        self.assertIn(tomb_key_31, graph31.resources)
        self.assertEqual(graph31.resources[tomb_key_31].state, "REDACTED")

        # Case 32: exposed PII in tombstone
        req32 = self.sample_by_id["case_32"]
        graph32 = self.graph_builder.build_graph(req32.case_id, req32.email, req32.audit_at)
        tomb_key_32 = ("identity_service", "tombstone_9178")
        self.assertIn(tomb_key_32, graph32.resources)
        self.assertEqual(graph32.resources[tomb_key_32].state, "PRESENT")


if __name__ == "__main__":
    unittest.main()
