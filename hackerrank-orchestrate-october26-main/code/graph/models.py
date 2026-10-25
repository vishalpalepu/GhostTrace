"""In-memory Resurrection Graph models for subjects, resources, processes, and restore paths."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class SubjectNode:
    """The subject of a deletion request with resolved current and historical identifiers."""
    user_id: str
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)


@dataclass
class ResourceNode:
    """An individual data resource (e.g. account profile, search entry, support ticket)."""
    system_id: str
    resource_id: str
    data_category: Optional[str]
    state: str  # 'PRESENT', 'ABSENT', 'REDACTED', 'ANONYMIZED'
    provenance_file_id: str
    observed_at: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessNode:
    """An active or disabled synchronization/import process (e.g. connector flow)."""
    system_id: str
    resource_id: str  # e.g. 'data_flow_9522'
    process_type: str = "CONNECTOR_SYNC"
    state: str = "DISABLED"  # 'ACTIVE' or 'DISABLED'
    is_active: bool = False
    provenance_file_id: str = ""
    observed_at: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RestorePathNode:
    """A backup archive that represents a potential data resurrection risk."""
    system_id: str
    resource_id: str  # e.g. 'backup_3870'
    state: str = "BLOCKED"  # 'ACTIVE' (allowed) or 'BLOCKED'
    restore_allowed: bool = False
    can_be_blocked: bool = True
    provenance_file_id: str = ""
    observed_at: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """A relationship between nodes with explicit evidence provenance and timestamp."""
    source_id: str
    target_id: str
    relation: str  # 'OWNS_RESOURCE', 'LINKED_TO_PROCESS', 'CONTAINED_IN_BACKUP', 'AUDITED_IN_LOG'
    provenance: str  # file_id or activity_id
    timestamp: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResurrectionGraph:
    """In-memory graph modeling data footprint, active processes, and restore paths at audit_at."""
    case_id: str
    audit_at: datetime
    subject: SubjectNode
    resources: Dict[Tuple[str, str], ResourceNode] = field(default_factory=dict)  # (system_id, resource_id) -> Node
    processes: Dict[str, ProcessNode] = field(default_factory=dict)                # resource_id -> Node
    restore_paths: Dict[str, RestorePathNode] = field(default_factory=dict)        # resource_id -> Node
    edges: List[GraphEdge] = field(default_factory=list)

    def add_resource(self, node: ResourceNode, edge_provenance: str, timestamp: Optional[datetime] = None) -> None:
        key = (node.system_id, node.resource_id)
        self.resources[key] = node
        self.edges.append(
            GraphEdge(
                source_id=self.subject.user_id,
                target_id=f"{node.system_id}:{node.resource_id}",
                relation="OWNS_RESOURCE",
                provenance=edge_provenance,
                timestamp=timestamp,
            )
        )

    def add_process(self, node: ProcessNode, edge_provenance: str, timestamp: Optional[datetime] = None) -> None:
        self.processes[node.resource_id] = node
        self.edges.append(
            GraphEdge(
                source_id=self.subject.user_id,
                target_id=f"{node.system_id}:{node.resource_id}",
                relation="LINKED_TO_PROCESS",
                provenance=edge_provenance,
                timestamp=timestamp,
            )
        )

    def add_restore_path(self, node: RestorePathNode, edge_provenance: str, timestamp: Optional[datetime] = None) -> None:
        self.restore_paths[node.resource_id] = node
        self.edges.append(
            GraphEdge(
                source_id=self.subject.user_id,
                target_id=f"{node.system_id}:{node.resource_id}",
                relation="CONTAINED_IN_BACKUP",
                provenance=edge_provenance,
                timestamp=timestamp,
            )
        )
