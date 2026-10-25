"""In-memory Resurrection Graph builder combining identity, evidence, and activity."""

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from ..evidence.evidence_index import EvidenceIndex
from ..evidence.models import ExtractedObservation
from ..identity.resolver import IdentityResolver
from ..ingestion.csv_loader import SystemActivityRecord
from .models import (
    GraphEdge,
    ProcessNode,
    ResourceNode,
    RestorePathNode,
    ResurrectionGraph,
    SubjectNode,
)


class GraphBuilder:
    """Builds an evidence-backed in-memory Resurrection Graph for a deletion audit request."""

    def __init__(
        self,
        resolver: IdentityResolver,
        evidence_index: EvidenceIndex,
        system_activity: Optional[List[SystemActivityRecord]] = None,
    ) -> None:
        self.resolver = resolver
        self.evidence_index = evidence_index
        self.system_activity = system_activity or []
        self._activity_by_resource: Dict[str, List[SystemActivityRecord]] = defaultdict(list)
        self._activity_by_user: Dict[str, List[SystemActivityRecord]] = defaultdict(list)
        self._index_activity()

    def _index_activity(self) -> None:
        """Indexes system activity records for efficient retrieval."""
        for act in self.system_activity:
            if act.resource_id:
                self._activity_by_resource[act.resource_id].append(act)
            if "user_" in act.details:
                # Extract user_id from details
                import re
                m = re.findall(r"user_\d+", act.details)
                for uid in m:
                    self._activity_by_user[uid].append(act)

    def build_graph(
        self,
        case_id: str,
        requester_email: str,
        audit_at: datetime,
    ) -> ResurrectionGraph:
        """Constructs the Resurrection Graph for a case strictly up to audit_at."""
        # Step 1: Temporal Identity Resolution
        matched_user = self.resolver.resolve_email(requester_email, audit_at)
        user_id = matched_user.user_id if matched_user else f"unresolved_{case_id}"

        emails: Set[str] = {requester_email.lower()}
        phones: Set[str] = set()

        if matched_user and user_id != f"unresolved_{case_id}":
            timeline = self.resolver.get_timeline(user_id)
            if timeline:
                emails.update(timeline.all_emails)
                phones.update(timeline.all_phones)

        subject_node = SubjectNode(user_id=user_id, emails=emails, phones=phones)
        graph = ResurrectionGraph(case_id=case_id, audit_at=audit_at, subject=subject_node)

        # Step 2: Ingest point-in-time evidence observations <= audit_at
        observations = self.evidence_index.get_observations_for_subject(
            user_id=user_id if user_id != f"unresolved_{case_id}" else None,
            emails=list(emails),
            phones=list(phones),
            cutoff=audit_at,
        )

        # Also search for standard account identifier mapping (e.g. user_01 -> account_001)
        if user_id.startswith("user_"):
            num_part = user_id[len("user_"):]
            if num_part.isdigit():
                padded_acc = f"account_{int(num_part):03d}"
                acc_obs = self.evidence_index.get_observations_for_resource(padded_acc, cutoff=audit_at)
                for o in acc_obs:
                    if o not in observations:
                        observations.append(o)

        # Group observations by (system_id, resource_id) to select the latest point-in-time state
        obs_by_resource: Dict[Tuple[str, str], List[ExtractedObservation]] = defaultdict(list)
        for obs in observations:
            obs_by_resource[(obs.system_id, obs.resource_id)].append(obs)

        # Step 3: Populate Graph Nodes
        for (sys_id, res_id), obs_list in obs_by_resource.items():
            # Latest observation <= audit_at dictates the ground-truth physical state
            latest_obs = obs_list[-1]
            if latest_obs.observed_state == "METADATA_ONLY" or latest_obs.extraction_method == "IMAGE_METADATA":
                # Image metadata alone does not establish resource existence or absence
                continue

            # 3A: Connector Data Flow Processes (integration_service)
            if sys_id == "integration_service" or res_id.startswith("data_flow_"):
                is_active = (latest_obs.observed_state == "ACTIVE")
                process_node = ProcessNode(
                    system_id="integration_service",
                    resource_id=res_id,
                    process_type="CONNECTOR_SYNC",
                    state=latest_obs.observed_state,
                    is_active=is_active,
                    provenance_file_id=latest_obs.file_id,
                    observed_at=latest_obs.observation_time or latest_obs.captured_at,
                    details=latest_obs.details,
                )
                graph.add_process(process_node, edge_provenance=latest_obs.file_id, timestamp=latest_obs.observation_time)

            # 3B: Backup Archive Restore Paths (backup_service)
            elif sys_id == "backup_service" or res_id.startswith("backup_"):
                restore_allowed = (latest_obs.observed_state == "ACTIVE")
                can_be_blocked = latest_obs.details.get("can_be_blocked", True)
                restore_node = RestorePathNode(
                    system_id="backup_service",
                    resource_id=res_id,
                    state=latest_obs.observed_state,
                    restore_allowed=restore_allowed,
                    can_be_blocked=can_be_blocked,
                    provenance_file_id=latest_obs.file_id,
                    observed_at=latest_obs.observation_time or latest_obs.captured_at,
                    details=latest_obs.details,
                )
                graph.add_restore_path(restore_node, edge_provenance=latest_obs.file_id, timestamp=latest_obs.observation_time)

            # 3C: Standard Data Resources (profile, search, support, analytics, export, tombstone, etc.)
            else:
                res_node = ResourceNode(
                    system_id=sys_id,
                    resource_id=res_id,
                    data_category=latest_obs.data_category,
                    state=latest_obs.observed_state,
                    provenance_file_id=latest_obs.file_id,
                    observed_at=latest_obs.observation_time or latest_obs.captured_at,
                    details=latest_obs.details,
                )
                graph.add_resource(res_node, edge_provenance=latest_obs.file_id, timestamp=latest_obs.observation_time)

        return graph
