from __future__ import annotations

import heapq
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .blast_radius import BlastRadiusAnalyzer
from .graph import AttackGraph
from .schemas import (
    AssetCriticality,
    BlastRadiusResult,
)


class RemediationActionType(str, Enum):
    ISOLATE_NODE = "isolate_node"
    DISABLE_CONNECTION = "disable_connection"


class RemediationCandidate(BaseModel):
    rank: int = Field(ge=1)

    action_id: str
    action_type: RemediationActionType

    title: str
    description: str

    source_node_id: str
    target_node_id: str | None = None

    priority_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    effectiveness_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    operational_cost: float = Field(
        ge=0.0,
        le=1.0,
    )

    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    reachable_nodes_removed: int = Field(ge=0)
    critical_nodes_protected: int = Field(ge=0)

    business_impact_reduction: float = Field(ge=0.0)

    blast_radius_before: float = Field(
        ge=0.0,
        le=1.0,
    )

    blast_radius_after: float = Field(
        ge=0.0,
        le=1.0,
    )

    blast_radius_reduction: float = Field(
        ge=0.0,
        le=1.0,
    )

    affected_connections: list[str] = Field(
        default_factory=list
    )

    protected_assets: list[str] = Field(
        default_factory=list
    )

    analyst_approval_required: bool = True

    recommended_command: str
    explanation: str

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class RemediationPlan(BaseModel):
    source_id: str

    baseline: BlastRadiusResult

    candidate_count: int = Field(ge=0)
    recommended_action_count: int = Field(ge=0)

    candidates: list[RemediationCandidate] = Field(
        default_factory=list
    )

    top_recommendation: RemediationCandidate | None = None

    algorithm: str = "max-heap priority ranking"

    explanation: str


class RemediationPrioritizer:
    """
    Rank defensive actions using simulated containment.

    Data structures:
    - Max-heap for priority ranking
    - Hash maps for action lookup
    - Sets for protected-asset comparison
    - Cloned adjacency-list graphs for safe simulation

    Complexity:
    Let C be the number of candidate actions.

    Each action performs a graph traversal:
    O(C × (V + E))

    Heap ranking:
    O(C log C)
    """

    def __init__(
        self,
        graph: AttackGraph,
    ) -> None:
        self.graph = graph

    def generate_plan(
        self,
        source_id: str,
        maximum_depth: int | None = None,
        maximum_recommendations: int = 10,
    ) -> RemediationPlan:
        self.graph.require_node(source_id)

        if maximum_recommendations <= 0:
            raise ValueError(
                "maximum_recommendations must be greater than zero"
            )

        baseline = BlastRadiusAnalyzer(
            self.graph
        ).analyse(
            source_id=source_id,
            maximum_depth=maximum_depth,
        )

        reachable_ids = {
            node.node_id
            for node in baseline.reachable_nodes
        }

        candidate_results: list[
            RemediationCandidate
        ] = []

        for node_id in sorted(reachable_ids):
            candidate = self._evaluate_node_isolation(
                incident_source_id=source_id,
                node_id=node_id,
                baseline=baseline,
                maximum_depth=maximum_depth,
            )

            if candidate is not None:
                candidate_results.append(candidate)

        for edge in self.graph.edges():
            if not edge.enabled:
                continue

            if edge.source_id not in reachable_ids:
                continue

            candidate = self._evaluate_connection_disable(
                incident_source_id=source_id,
                edge_source_id=edge.source_id,
                edge_target_id=edge.target_id,
                baseline=baseline,
                maximum_depth=maximum_depth,
            )

            if candidate is not None:
                candidate_results.append(candidate)

        ranked = self._rank_candidates(
            candidate_results
        )

        selected = ranked[
            :maximum_recommendations
        ]

        ranked_candidates = [
            candidate.model_copy(
                update={"rank": index}
            )
            for index, candidate in enumerate(
                selected,
                start=1,
            )
        ]

        top_recommendation = (
            ranked_candidates[0]
            if ranked_candidates
            else None
        )

        explanation = (
            f"CyberShield evaluated {len(candidate_results)} "
            f"containment actions for compromise source {source_id}. "
            f"The actions were ranked using blast-radius reduction, "
            f"critical-asset protection, business-impact reduction, "
            f"confidence, and operational cost."
        )

        return RemediationPlan(
            source_id=source_id,
            baseline=baseline,
            candidate_count=len(
                candidate_results
            ),
            recommended_action_count=len(
                ranked_candidates
            ),
            candidates=ranked_candidates,
            top_recommendation=top_recommendation,
            explanation=explanation,
        )

    def _evaluate_node_isolation(
        self,
        incident_source_id: str,
        node_id: str,
        baseline: BlastRadiusResult,
        maximum_depth: int | None,
    ) -> RemediationCandidate | None:
        simulation_graph = self._clone_graph()

        affected_connections: list[str] = []

        for relationship in simulation_graph.neighbours(
            node_id,
            enabled_only=True,
        ):
            changed = simulation_graph.disable_edge(
                node_id,
                relationship.node.node_id,
            )

            if changed:
                affected_connections.append(
                    f"{node_id}->{relationship.node.node_id}"
                )

        for relationship in simulation_graph.incoming_neighbours(
            node_id,
            enabled_only=True,
        ):
            changed = simulation_graph.disable_edge(
                relationship.node.node_id,
                node_id,
            )

            if changed:
                affected_connections.append(
                    f"{relationship.node.node_id}->{node_id}"
                )

        if not affected_connections:
            return None

        after = BlastRadiusAnalyzer(
            simulation_graph
        ).analyse(
            source_id=incident_source_id,
            maximum_depth=maximum_depth,
        )

        node = self.graph.require_node(node_id)

        operational_cost = self._node_operational_cost(
            node.criticality,
            node.business_impact_score,
        )

        result = self._build_candidate(
            action_id=f"ISOLATE-{node_id}",
            action_type=RemediationActionType.ISOLATE_NODE,
            title=f"Isolate {node.name}",
            description=(
                f"Temporarily isolate {node_id} from all enabled "
                f"incoming and outgoing infrastructure connections."
            ),
            source_node_id=node_id,
            target_node_id=None,
            baseline=baseline,
            after=after,
            operational_cost=operational_cost,
            affected_connections=affected_connections,
            recommended_command=(
                f"Request analyst approval to isolate node {node_id} "
                f"and revoke its active network sessions."
            ),
            metadata={
                "node_type": node.node_type.value,
                "criticality": node.criticality.value,
                "business_impact_score": (
                    node.business_impact_score
                ),
            },
        )

        return result

    def _evaluate_connection_disable(
        self,
        incident_source_id: str,
        edge_source_id: str,
        edge_target_id: str,
        baseline: BlastRadiusResult,
        maximum_depth: int | None,
    ) -> RemediationCandidate | None:
        simulation_graph = self._clone_graph()

        changed = simulation_graph.disable_edge(
            edge_source_id,
            edge_target_id,
        )

        if not changed:
            return None

        after = BlastRadiusAnalyzer(
            simulation_graph
        ).analyse(
            source_id=incident_source_id,
            maximum_depth=maximum_depth,
        )

        source_node = self.graph.require_node(
            edge_source_id
        )
        target_node = self.graph.require_node(
            edge_target_id
        )

        operational_cost = self._connection_operational_cost(
            source_criticality=source_node.criticality,
            target_criticality=target_node.criticality,
            target_business_impact=(
                target_node.business_impact_score
            ),
        )

        return self._build_candidate(
            action_id=(
                f"DISABLE-{edge_source_id}-{edge_target_id}"
            ),
            action_type=(
                RemediationActionType.DISABLE_CONNECTION
            ),
            title=(
                f"Disable connection from "
                f"{source_node.name} to {target_node.name}"
            ),
            description=(
                f"Temporarily disable the directed connection "
                f"{edge_source_id}->{edge_target_id}."
            ),
            source_node_id=edge_source_id,
            target_node_id=edge_target_id,
            baseline=baseline,
            after=after,
            operational_cost=operational_cost,
            affected_connections=[
                f"{edge_source_id}->{edge_target_id}"
            ],
            recommended_command=(
                f"Request analyst approval to block connection "
                f"{edge_source_id}->{edge_target_id}."
            ),
            metadata={
                "source_criticality": (
                    source_node.criticality.value
                ),
                "target_criticality": (
                    target_node.criticality.value
                ),
            },
        )

    def _build_candidate(
        self,
        action_id: str,
        action_type: RemediationActionType,
        title: str,
        description: str,
        source_node_id: str,
        target_node_id: str | None,
        baseline: BlastRadiusResult,
        after: BlastRadiusResult,
        operational_cost: float,
        affected_connections: list[str],
        recommended_command: str,
        metadata: dict[str, Any],
    ) -> RemediationCandidate | None:
        reachable_nodes_removed = max(
            baseline.reachable_node_count
            - after.reachable_node_count,
            0,
        )

        critical_nodes_protected = max(
            baseline.critical_node_count
            - after.critical_node_count,
            0,
        )

        business_impact_reduction = max(
            baseline.cumulative_business_impact
            - after.cumulative_business_impact,
            0.0,
        )

        blast_radius_reduction = max(
            baseline.blast_radius_score
            - after.blast_radius_score,
            0.0,
        )

        if (
            reachable_nodes_removed == 0
            and critical_nodes_protected == 0
            and business_impact_reduction == 0
            and blast_radius_reduction == 0
        ):
            return None

        baseline_reachable = max(
            baseline.reachable_node_count,
            1,
        )

        baseline_critical = max(
            baseline.critical_node_count,
            1,
        )

        baseline_business_impact = max(
            baseline.cumulative_business_impact,
            0.0001,
        )

        reachable_reduction_ratio = min(
            reachable_nodes_removed
            / baseline_reachable,
            1.0,
        )

        critical_protection_ratio = min(
            critical_nodes_protected
            / baseline_critical,
            1.0,
        )

        business_impact_ratio = min(
            business_impact_reduction
            / baseline_business_impact,
            1.0,
        )

        normalised_blast_reduction = min(
            blast_radius_reduction
            / max(
                baseline.blast_radius_score,
                0.0001,
            ),
            1.0,
        )

        effectiveness_score = min(
            0.30 * reachable_reduction_ratio
            + 0.30 * critical_protection_ratio
            + 0.20 * business_impact_ratio
            + 0.20 * normalised_blast_reduction,
            1.0,
        )

        evidence_count = sum(
            [
                reachable_nodes_removed > 0,
                critical_nodes_protected > 0,
                business_impact_reduction > 0,
                blast_radius_reduction > 0,
            ]
        )

        confidence_score = min(
            0.55
            + 0.10 * evidence_count,
            0.95,
        )

        priority_score = min(
            0.65 * effectiveness_score
            + 0.20 * confidence_score
            + 0.15 * (1.0 - operational_cost),
            1.0,
        )

        baseline_critical_assets = set(
            baseline.critical_assets_at_risk
        )

        after_critical_assets = set(
            after.critical_assets_at_risk
        )

        protected_assets = sorted(
            baseline_critical_assets
            - after_critical_assets
        )

        explanation = (
            f"This action removes {reachable_nodes_removed} reachable "
            f"nodes, protects {critical_nodes_protected} critical "
            f"nodes, and reduces the blast-radius score by "
            f"{blast_radius_reduction:.4f}. "
            f"Estimated operational cost is "
            f"{operational_cost:.4f}."
        )

        return RemediationCandidate(
            rank=1,
            action_id=action_id,
            action_type=action_type,
            title=title,
            description=description,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            priority_score=round(
                priority_score,
                4,
            ),
            effectiveness_score=round(
                effectiveness_score,
                4,
            ),
            operational_cost=round(
                operational_cost,
                4,
            ),
            confidence_score=round(
                confidence_score,
                4,
            ),
            reachable_nodes_removed=(
                reachable_nodes_removed
            ),
            critical_nodes_protected=(
                critical_nodes_protected
            ),
            business_impact_reduction=round(
                business_impact_reduction,
                4,
            ),
            blast_radius_before=(
                baseline.blast_radius_score
            ),
            blast_radius_after=(
                after.blast_radius_score
            ),
            blast_radius_reduction=round(
                blast_radius_reduction,
                4,
            ),
            affected_connections=sorted(
                set(affected_connections)
            ),
            protected_assets=protected_assets,
            recommended_command=recommended_command,
            explanation=explanation,
            metadata=metadata,
        )

    @staticmethod
    def _rank_candidates(
        candidates: list[RemediationCandidate],
    ) -> list[RemediationCandidate]:
        priority_queue: list[
            tuple[
                float,
                float,
                float,
                str,
                RemediationCandidate,
            ]
        ] = []

        for candidate in candidates:
            heapq.heappush(
                priority_queue,
                (
                    -candidate.priority_score,
                    -candidate.effectiveness_score,
                    candidate.operational_cost,
                    candidate.action_id,
                    candidate,
                ),
            )

        ranked: list[RemediationCandidate] = []

        while priority_queue:
            *_, candidate = heapq.heappop(
                priority_queue
            )
            ranked.append(candidate)

        return ranked

    def _clone_graph(self) -> AttackGraph:
        cloned_graph = AttackGraph()

        cloned_graph.load(
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

        return cloned_graph

    @staticmethod
    def _node_operational_cost(
        criticality: AssetCriticality,
        business_impact_score: float,
    ) -> float:
        criticality_costs = {
            AssetCriticality.LOW: 0.15,
            AssetCriticality.MEDIUM: 0.30,
            AssetCriticality.HIGH: 0.55,
            AssetCriticality.CRITICAL: 0.80,
        }

        score = (
            0.55 * criticality_costs[criticality]
            + 0.45 * business_impact_score
        )

        return round(
            min(score, 1.0),
            4,
        )

    @staticmethod
    def _connection_operational_cost(
        source_criticality: AssetCriticality,
        target_criticality: AssetCriticality,
        target_business_impact: float,
    ) -> float:
        criticality_weights = {
            AssetCriticality.LOW: 0.10,
            AssetCriticality.MEDIUM: 0.25,
            AssetCriticality.HIGH: 0.50,
            AssetCriticality.CRITICAL: 0.75,
        }

        score = (
            0.20
            * criticality_weights[source_criticality]
            + 0.40
            * criticality_weights[target_criticality]
            + 0.40
            * target_business_impact
        )

        return round(
            min(score, 1.0),
            4,
        )