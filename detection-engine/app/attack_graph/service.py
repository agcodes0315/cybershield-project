from __future__ import annotations

import json
from pathlib import Path
from threading import RLock
from typing import Any

from .blast_radius import BlastRadiusAnalyzer
from .graph import AttackGraph
from .pathfinder import AttackPathfinder
from .remediation import (
    RemediationPlan,
    RemediationPrioritizer,
)
from .schemas import (
    AttackPathResult,
    BlastRadiusResult,
    ContainmentComparison,
    CriticalAssetPathResult,
    GraphStatistics,
    InfrastructureTopology,
    PathAlgorithm,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_TOPOLOGY_PATH = (
    PROJECT_ROOT
    / "event-simulator"
    / "datasets"
    / "infrastructure_topology.json"
)


class AttackGraphService:
    """
    Application service for CyberShield attack-graph intelligence.

    The service owns the active in-memory graph and exposes safe,
    reusable operations for API routes and future incident pipelines.
    """

    def __init__(
        self,
        topology_path: Path = DEFAULT_TOPOLOGY_PATH,
    ) -> None:
        self.topology_path = topology_path
        self.graph = AttackGraph()
        self.topology: InfrastructureTopology | None = None
        self._lock = RLock()

    @property
    def is_loaded(self) -> bool:
        return self.topology is not None

    def ensure_loaded(self) -> InfrastructureTopology:
        with self._lock:
            if self.topology is None:
                return self.load_default_topology()

            return self.topology

    def load_default_topology(
        self,
    ) -> InfrastructureTopology:
        with self._lock:
            if not self.topology_path.exists():
                raise FileNotFoundError(
                    "Infrastructure topology dataset was not found: "
                    f"{self.topology_path}"
                )

            with self.topology_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                payload = json.load(file)

            return self.load_topology(payload)

    def load_topology(
        self,
        topology: InfrastructureTopology | dict[str, Any],
    ) -> InfrastructureTopology:
        with self._lock:
            if isinstance(topology, InfrastructureTopology):
                validated = topology
            else:
                validated = InfrastructureTopology.model_validate(
                    topology
                )

            self.graph.load(
                nodes=validated.nodes,
                edges=validated.edges,
                clear_existing=True,
            )

            self.topology = validated

            return validated

    def active_topology(self) -> InfrastructureTopology:
        return self.ensure_loaded()

    def statistics(self) -> GraphStatistics:
        self.ensure_loaded()
        return self.graph.statistics()

    def bfs_path(
        self,
        source_id: str,
        target_id: str,
    ) -> AttackPathResult:
        self.ensure_loaded()

        return AttackPathfinder(
            self.graph
        ).shortest_hop_path(
            source_id=source_id,
            target_id=target_id,
        )

    def dijkstra_path(
        self,
        source_id: str,
        target_id: str,
    ) -> AttackPathResult:
        self.ensure_loaded()

        return AttackPathfinder(
            self.graph
        ).lowest_resistance_path(
            source_id=source_id,
            target_id=target_id,
        )

    def nearest_critical_asset(
        self,
        source_id: str,
        algorithm: PathAlgorithm,
        exclude_compromised: bool = False,
    ) -> CriticalAssetPathResult:
        self.ensure_loaded()

        return AttackPathfinder(
            self.graph
        ).nearest_critical_asset(
            source_id=source_id,
            algorithm=algorithm,
            exclude_compromised=exclude_compromised,
        )

    def blast_radius(
        self,
        source_id: str,
        maximum_depth: int | None = None,
        include_source: bool = True,
    ) -> BlastRadiusResult:
        self.ensure_loaded()

        return BlastRadiusAnalyzer(
            self.graph
        ).analyse(
            source_id=source_id,
            maximum_depth=maximum_depth,
            include_source=include_source,
        )

    def containment_comparison(
        self,
        source_id: str,
        connections_to_disable: list[tuple[str, str]],
        maximum_depth: int | None = None,
    ) -> ContainmentComparison:
        self.ensure_loaded()

        simulation_graph = self._clone_graph()

        return BlastRadiusAnalyzer(
            simulation_graph
        ).compare_after_containment(
            source_id=source_id,
            connections_to_disable=connections_to_disable,
            maximum_depth=maximum_depth,
        )

    def remediation_plan(
        self,
        source_id: str,
        maximum_depth: int | None = None,
        maximum_recommendations: int = 10,
    ) -> RemediationPlan:
        self.ensure_loaded()

        simulation_graph = self._clone_graph()

        return RemediationPrioritizer(
            simulation_graph
        ).generate_plan(
            source_id=source_id,
            maximum_depth=maximum_depth,
            maximum_recommendations=maximum_recommendations,
        )

    def reset(self) -> None:
        with self._lock:
            self.graph.clear()
            self.topology = None

    def _clone_graph(self) -> AttackGraph:
        cloned = AttackGraph()

        cloned.load(
            nodes=[
                node.model_copy(deep=True)
                for node in self.graph.nodes()
            ],
            edges=[
                edge.model_copy(deep=True)
                for edge in self.graph.edges()
            ],
            clear_existing=True,
        )

        return cloned


attack_graph_service = AttackGraphService()