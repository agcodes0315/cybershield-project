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
        """
        Contextual node risk.

        Exposure and vulnerability describe likelihood.
        Business impact describes consequence.
        """
        score = (
            0.35 * self.exposure_score
            + 0.35 * self.vulnerability_score
            + 0.30 * self.business_impact_score
        )

        return round(min(max(score, 0.0), 1.0), 4)


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