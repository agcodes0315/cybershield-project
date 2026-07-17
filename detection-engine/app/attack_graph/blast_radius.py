from __future__ import annotations

from .graph import AttackGraph
from .schemas import (
    AssetCriticality,
    BlastRadiusNode,
    BlastRadiusResult,
    ContainmentComparison,
)


class BlastRadiusAnalyzer:
    """
    Calculate compromise reachability using iterative DFS.

    Data structures:
    - Stack for depth-first traversal
    - Set for cycle prevention
    - Hash maps for parent and depth tracking

    Complexity:
    - Time: O(V + E)
    - Space: O(V)
    """

    def __init__(self, graph: AttackGraph) -> None:
        self.graph = graph

    def analyse(
        self,
        source_id: str,
        maximum_depth: int | None = None,
        include_source: bool = True,
    ) -> BlastRadiusResult:
        self.graph.require_node(source_id)

        if maximum_depth is not None and maximum_depth < 0:
            raise ValueError("maximum_depth cannot be negative")

        visited: set[str] = set()

        stack: list[
            tuple[str, int, str | None, object | None]
        ] = [
            (source_id, 0, None, None)
        ]

        reachable_nodes: list[BlastRadiusNode] = []
        traversal_order: list[str] = []

        while stack:
            current_id, depth, parent_id, incoming_edge = stack.pop()

            if current_id in visited:
                continue

            if maximum_depth is not None and depth > maximum_depth:
                continue

            visited.add(current_id)
            traversal_order.append(current_id)

            node = self.graph.require_node(current_id)

            if include_source or current_id != source_id:
                reachable_nodes.append(
                    BlastRadiusNode(
                        node_id=node.node_id,
                        node_name=node.name,
                        node_type=node.node_type,
                        criticality=node.criticality,
                        depth=depth,
                        parent_node_id=parent_id,
                        incoming_connection=(
                            incoming_edge.connection_type
                            if incoming_edge is not None
                            else None
                        ),
                        node_risk_score=node.risk_score,
                        business_impact_score=node.business_impact_score,
                        compromised=node.compromised,
                    )
                )

            if maximum_depth is not None and depth == maximum_depth:
                continue

            neighbours = self.graph.neighbours(
                current_id,
                enabled_only=True,
            )

            neighbours = sorted(
                neighbours,
                key=lambda relationship: relationship.node.node_id,
                reverse=True,
            )

            for relationship in neighbours:
                neighbour_id = relationship.node.node_id

                if neighbour_id in visited:
                    continue

                stack.append(
                    (
                        neighbour_id,
                        depth + 1,
                        current_id,
                        relationship.edge,
                    )
                )

        critical_nodes = [
            node
            for node in reachable_nodes
            if node.criticality == AssetCriticality.CRITICAL
        ]

        high_or_critical_nodes = [
            node
            for node in reachable_nodes
            if node.criticality
            in {
                AssetCriticality.HIGH,
                AssetCriticality.CRITICAL,
            }
        ]

        cumulative_business_impact = sum(
            node.business_impact_score
            for node in reachable_nodes
        )

        average_risk_score = (
            sum(node.node_risk_score for node in reachable_nodes)
            / len(reachable_nodes)
            if reachable_nodes
            else 0.0
        )

        maximum_observed_depth = max(
            (node.depth for node in reachable_nodes),
            default=0,
        )

        total_graph_nodes = max(len(self.graph.nodes()), 1)

        reachability_ratio = (
            len(reachable_nodes) / total_graph_nodes
        )

        criticality_ratio = (
            len(critical_nodes)
            / max(len(self.graph.critical_nodes()), 1)
        )

        normalised_business_impact = min(
            cumulative_business_impact / total_graph_nodes,
            1.0,
        )

        blast_radius_score = min(
            0.35 * reachability_ratio
            + 0.35 * criticality_ratio
            + 0.20 * normalised_business_impact
            + 0.10 * average_risk_score,
            1.0,
        )

        explanation = (
            f"DFS identified {len(reachable_nodes)} reachable nodes "
            f"from {source_id}, including {len(critical_nodes)} "
            f"critical assets, with maximum depth "
            f"{maximum_observed_depth}."
        )

        return BlastRadiusResult(
            source_id=source_id,
            reachable_node_count=len(reachable_nodes),
            critical_node_count=len(critical_nodes),
            high_or_critical_node_count=len(high_or_critical_nodes),
            maximum_depth=maximum_observed_depth,
            cumulative_business_impact=round(
                cumulative_business_impact,
                4,
            ),
            average_risk_score=round(
                average_risk_score,
                4,
            ),
            blast_radius_score=round(
                blast_radius_score,
                4,
            ),
            reachable_nodes=sorted(
                reachable_nodes,
                key=lambda item: (
                    item.depth,
                    item.node_id,
                ),
            ),
            critical_assets_at_risk=sorted(
                node.node_id
                for node in critical_nodes
            ),
            traversal_order=traversal_order,
            explanation=explanation,
        )

    def analyse_multiple_sources(
        self,
        source_ids: list[str],
        maximum_depth: int | None = None,
    ) -> dict[str, BlastRadiusResult]:
        if not source_ids:
            raise ValueError(
                "At least one source node is required"
            )

        return {
            source_id: self.analyse(
                source_id=source_id,
                maximum_depth=maximum_depth,
            )
            for source_id in source_ids
        }

    def compare_after_containment(
        self,
        source_id: str,
        connections_to_disable: list[tuple[str, str]],
        maximum_depth: int | None = None,
    ) -> ContainmentComparison:
        before = self.analyse(
            source_id=source_id,
            maximum_depth=maximum_depth,
        )

        disabled_connections: list[str] = []

        for source_node, target_node in connections_to_disable:
            changed = self.graph.disable_edge(
                source_node,
                target_node,
            )

            if changed > 0:
                disabled_connections.append(
                    f"{source_node}->{target_node}"
                )

        after = self.analyse(
            source_id=source_id,
            maximum_depth=maximum_depth,
        )

        removed_reachable_nodes = max(
            before.reachable_node_count
            - after.reachable_node_count,
            0,
        )

        removed_critical_nodes = max(
            before.critical_node_count
            - after.critical_node_count,
            0,
        )

        business_impact_reduction = max(
            before.cumulative_business_impact
            - after.cumulative_business_impact,
            0.0,
        )

        blast_radius_reduction = max(
            before.blast_radius_score
            - after.blast_radius_score,
            0.0,
        )

        if removed_critical_nodes > 0:
            recommendation = (
                "Containment successfully removed one or more "
                "critical assets from the reachable attack surface."
            )
        elif removed_reachable_nodes > 0:
            recommendation = (
                "Containment reduced attacker reach, but critical "
                "assets may remain accessible."
            )
        else:
            recommendation = (
                "The selected containment connections did not "
                "meaningfully reduce the calculated blast radius."
            )

        return ContainmentComparison(
            source_id=source_id,
            before=before,
            after=after,
            removed_reachable_nodes=removed_reachable_nodes,
            removed_critical_nodes=removed_critical_nodes,
            business_impact_reduction=round(
                business_impact_reduction,
                4,
            ),
            blast_radius_reduction=round(
                blast_radius_reduction,
                4,
            ),
            disabled_connections=disabled_connections,
            recommendation=recommendation,
        )