from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class GraphNodeType(str, Enum):
    USER = "user"
    WORKSTATION = "workstation"
    SERVER = "server"
    APPLICATION = "application"
    DATABASE = "database"
    IDENTITY_PROVIDER = "identity_provider"
    STORAGE = "storage"
    BACKUP = "backup"
    SECURITY_SYSTEM = "security_system"
    NETWORK_DEVICE = "network_device"


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConnectionType(str, Enum):
    AUTHENTICATES_TO = "authenticates_to"
    CONNECTS_TO = "connects_to"
    HOSTS = "hosts"
    READS_FROM = "reads_from"
    WRITES_TO = "writes_to"
    ADMINISTERS = "administers"
    BACKS_UP = "backs_up"
    MONITORS = "monitors"
    TRUSTS = "trusts"
    REMOTE_ACCESS = "remote_access"


class PathAlgorithm(str, Enum):
    BFS = "bfs"
    DIJKSTRA = "dijkstra"


class AttackGraphNode(BaseModel):
    node_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    node_type: GraphNodeType
    criticality: AssetCriticality

    ip_address: str | None = None
    zone: str | None = None
    owner: str | None = None

    exposure_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    vulnerability_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    business_impact_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    compromised: bool = False

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @property
    def risk_score(self) -> float:
        score = (
            0.35 * self.exposure_score
            + 0.35 * self.vulnerability_score
            + 0.30 * self.business_impact_score
        )

        return round(
            min(max(score, 0.0), 1.0),
            4,
        )


class AttackGraphEdge(BaseModel):
    source_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)

    connection_type: ConnectionType

    resistance: float = Field(
        default=0.5,
        ge=0.01,
        le=1.0,
    )

    trust_level: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

    enabled: bool = True
    bidirectional: bool = False

    controls: list[str] = Field(
        default_factory=list
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    @property
    def attacker_cost(self) -> float:
        cost = (
            0.75 * self.resistance
            + 0.25 * (1.0 - self.trust_level)
        )

        return round(
            max(cost, 0.01),
            4,
        )


class NeighbourRelationship(BaseModel):
    node: AttackGraphNode
    edge: AttackGraphEdge


class GraphStatistics(BaseModel):
    node_count: int
    edge_count: int
    critical_node_count: int
    compromised_node_count: int
    isolated_node_count: int
    average_out_degree: float


class InfrastructureTopology(BaseModel):
    topology_id: str
    organisation_id: str
    name: str

    nodes: list[AttackGraphNode]
    edges: list[AttackGraphEdge]

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class AttackPathStep(BaseModel):
    step_number: int = Field(ge=0)

    node_id: str
    node_name: str
    node_type: GraphNodeType
    criticality: AssetCriticality

    incoming_connection: ConnectionType | None = None
    edge_resistance: float | None = None
    edge_trust_level: float | None = None
    edge_cost: float | None = None

    node_risk_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    controls: list[str] = Field(
        default_factory=list
    )


class AttackPathResult(BaseModel):
    source_id: str
    target_id: str

    found: bool
    algorithm: PathAlgorithm

    hop_count: int = Field(ge=0)
    total_resistance: float = Field(ge=0.0)
    total_cost: float = Field(ge=0.0)

    path_risk_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    node_ids: list[str] = Field(
        default_factory=list
    )

    steps: list[AttackPathStep] = Field(
        default_factory=list
    )

    controls_encountered: list[str] = Field(
        default_factory=list
    )

    explanation: str


class CriticalAssetPathResult(BaseModel):
    source_id: str
    target_id: str | None = None

    found: bool
    target_criticality: AssetCriticality | None = None

    algorithm: PathAlgorithm
    path: AttackPathResult | None = None

    searched_target_count: int = Field(ge=0)


class BlastRadiusNode(BaseModel):
    node_id: str
    node_name: str
    node_type: GraphNodeType
    criticality: AssetCriticality

    depth: int = Field(ge=0)

    parent_node_id: str | None = None
    incoming_connection: ConnectionType | None = None

    node_risk_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    business_impact_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    compromised: bool = False


class BlastRadiusResult(BaseModel):
    source_id: str

    reachable_node_count: int = Field(ge=0)
    critical_node_count: int = Field(ge=0)
    high_or_critical_node_count: int = Field(ge=0)

    maximum_depth: int = Field(ge=0)

    cumulative_business_impact: float = Field(
        ge=0.0,
    )

    average_risk_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    blast_radius_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    reachable_nodes: list[BlastRadiusNode] = Field(
        default_factory=list
    )

    critical_assets_at_risk: list[str] = Field(
        default_factory=list
    )

    traversal_order: list[str] = Field(
        default_factory=list
    )

    explanation: str


class ContainmentComparison(BaseModel):
    source_id: str

    before: BlastRadiusResult
    after: BlastRadiusResult

    removed_reachable_nodes: int = Field(ge=0)
    removed_critical_nodes: int = Field(ge=0)

    business_impact_reduction: float = Field(
        ge=0.0,
    )

    blast_radius_reduction: float = Field(
        ge=0.0,
        le=1.0,
    )

    disabled_connections: list[str] = Field(
        default_factory=list
    )

    recommendation: str