"""Global evidence repository index and point-in-time retrieval."""

from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from ..ingestion.csv_loader import EvidenceFileRecord, load_evidence_manifest
from .document_extractor import DocumentExtractor
from .json_extractor import JsonExtractor
from .log_extractor import LogExtractor
from .models import ExtractedObservation
from .sql_extractor import SqlExtractor


class EvidenceIndex:
    """Indexes all evidence files once and provides point-in-time retrieval by subject and resource."""

    def __init__(self, manifest_path: Path, dataset_dir: Path) -> None:
        self.manifest_path = manifest_path
        self.dataset_dir = dataset_dir
        self.manifest_records: List[EvidenceFileRecord] = []
        self.observations: List[ExtractedObservation] = []

        # Lookup indices
        self.by_user_id: Dict[str, List[ExtractedObservation]] = defaultdict(list)
        self.by_email: Dict[str, List[ExtractedObservation]] = defaultdict(list)
        self.by_phone: Dict[str, List[ExtractedObservation]] = defaultdict(list)
        self.by_hash: Dict[str, List[ExtractedObservation]] = defaultdict(list)
        self.by_resource_id: Dict[str, List[ExtractedObservation]] = defaultdict(list)
        self.by_file_id: Dict[str, List[ExtractedObservation]] = defaultdict(list)

        # Coverage tracking
        self.parsed_files: Set[str] = set()
        self.failed_files: Dict[str, str] = {}
        self.discovered_resources: Set[str] = set()

        self._build_index()

    def _build_index(self) -> None:
        """Parses and indexes every evidence file in evidence_files.csv."""
        self.manifest_records = load_evidence_manifest(self.manifest_path)

        for rec in self.manifest_records:
            fpath = self.dataset_dir / rec.file_path
            fid = rec.file_id
            cap_at = rec.captured_at
            ext = fpath.suffix.lower()

            try:
                if ext == ".sql":
                    obs_list = SqlExtractor.extract_from_file(fid, fpath, cap_at)
                elif ext == ".json":
                    obs_list = JsonExtractor.extract_from_file(fid, fpath, cap_at)
                elif ext == ".log":
                    obs_list = LogExtractor.extract_from_file(fid, fpath, cap_at)
                elif ext in (".txt", ".pdf", ".png"):
                    obs_list = DocumentExtractor.extract_from_file(fid, fpath, cap_at)
                else:
                    obs_list = []

                self.parsed_files.add(fid)
                for obs in obs_list:
                    self.observations.append(obs)
                    self.by_file_id[fid].append(obs)
                    if obs.resource_id:
                        self.by_resource_id[obs.resource_id].append(obs)
                        self.discovered_resources.add(obs.resource_id)
                    if obs.subject_id:
                        self.by_user_id[obs.subject_id].append(obs)
                    if obs.subject_email:
                        self.by_email[obs.subject_email.lower()].append(obs)
                    if obs.subject_phone:
                        self.by_phone[obs.subject_phone].append(obs)
                    sh = obs.details.get("subject_hash") or obs.details.get("correlation_key") or obs.details.get("email_hash")
                    if sh and isinstance(sh, str):
                        self.by_hash[sh.strip().lower()].append(obs)

            except Exception as e:
                self.failed_files[fid] = str(e)

    def get_observations_for_subject(
        self,
        user_id: Optional[str],
        emails: List[str],
        phones: Optional[List[str]] = None,
        hashes: Optional[List[str]] = None,
        cutoff: Optional[datetime] = None,
    ) -> List[ExtractedObservation]:
        """Retrieves and chronologically orders all observations linked to the subject strictly <= cutoff."""
        matched: List[ExtractedObservation] = []
        seen = set()

        # Query by user_id
        if user_id and user_id in self.by_user_id:
            for obs in self.by_user_id[user_id]:
                key = (obs.file_id, obs.resource_id, obs.observed_state, obs.observation_time)
                if key not in seen:
                    seen.add(key)
                    matched.append(obs)

        # Query by emails
        for em in emails:
            norm_em = em.strip().lower()
            if norm_em in self.by_email:
                for obs in self.by_email[norm_em]:
                    key = (obs.file_id, obs.resource_id, obs.observed_state, obs.observation_time)
                    if key not in seen:
                        seen.add(key)
                        matched.append(obs)

        # Query by phones
        if phones:
            for ph in phones:
                norm_ph = ph.strip()
                if norm_ph in self.by_phone:
                    for obs in self.by_phone[norm_ph]:
                        key = (obs.file_id, obs.resource_id, obs.observed_state, obs.observation_time)
                        if key not in seen:
                            seen.add(key)
                            matched.append(obs)

        # Query by email hashes
        if hashes:
            for h in hashes:
                norm_h = h.strip().lower()
                if norm_h in self.by_hash:
                    for obs in self.by_hash[norm_h]:
                        key = (obs.file_id, obs.resource_id, obs.observed_state, obs.observation_time)
                        if key not in seen:
                            seen.add(key)
                            matched.append(obs)

        # Apply strict temporal filter: captured_at <= cutoff AND observation_time <= cutoff
        if cutoff:
            filtered = []
            for obs in matched:
                if obs.captured_at and obs.captured_at > cutoff:
                    continue
                if obs.observation_time and obs.observation_time > cutoff:
                    continue
                filtered.append(obs)
            matched = filtered

        # Sort chronologically by observation_time or captured_at
        matched.sort(key=lambda o: (o.observation_time or o.captured_at, o.resource_id))
        return matched

    def get_observations_for_resource(
        self,
        resource_id: str,
        cutoff: Optional[datetime] = None,
    ) -> List[ExtractedObservation]:
        """Retrieves observations for a specific resource_id strictly <= cutoff."""
        matched = self.by_resource_id.get(resource_id, [])
        if cutoff:
            filtered = []
            for obs in matched:
                if obs.captured_at and obs.captured_at > cutoff:
                    continue
                if obs.observation_time and obs.observation_time > cutoff:
                    continue
                filtered.append(obs)
            matched = filtered
        matched.sort(key=lambda o: (o.observation_time or o.captured_at))
        return matched
