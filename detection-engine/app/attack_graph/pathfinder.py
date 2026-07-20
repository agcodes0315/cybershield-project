from __future__ import annotations

import heapq
from collections import deque
from math import inf

from .graph import AttackGraph
from .schemas import (
    AssetCriticality,
    AttackGraphEdge,
    AttackPathResult,
    AttackPathStep,
    CriticalAssetPathResult,
    PathAlgorithm,
)


class AttackPathfinder:
    """
    Find attack paths through the infrastructure graph.

    Algorithms:
    - BFS finds the path with the fewest hops.
    - Dijkstra finds the path with the lowest attacker cost.

    Complexity:
    - BFS: O(V + E)
    - Dijkstra: O((V + E) log V)
    """

    def __init__(
        self,
        graph: AttackGraph,
    ) -> None:
        self.graph = graph

    def shortest_hop_path(
        self,
        source_id: str,
        target_id: str,
    ) -> AttackPathResult:
        self.graph.require_node(source_id)
        self.graph.require_node(target_id)

        if source_id == target_id:
            return self._single_node_result(
                source_id=source_id,
                algorithm=PathAlgorithm.BFS,
            )

        queue: deque[str] = deque([source_id])
        visited: set[str] = {source_id}

        predecessor: dict[
            str,
            tuple[str, AttackGraphEdge],
        ] = {}

        while queue:
            current_id = queue.popleft()

            for relationship in self.graph.neighbours(
                current_id,
                enabled_only=True,
            ):
                neighbour_id = (
                    relationship.node.node_id
                )

                if neighbour_id in visited:
                    continue

                visited.add(neighbour_id)

                predecessor[neighbour_id] = (
                    current_id,
                    relationship.edge,
                )

                if neighbour_id == target_id:
                    return self._build_result(
                        source_id=source_id,
                        target_id=target_id,
                        predecessor=predecessor,
                        algorithm=PathAlgorithm.BFS,
                    )

                queue.append(neighbour_id)

        return self._not_found_result(
            source_id=source_id,
            target_id=target_id,
            algorithm=PathAlgorithm.BFS,
        )

    def lowest_resistance_path(
        self,
        source_id: str,
        target_id: str,
    ) -> AttackPathResult:
        self.graph.require_node(source_id)
        self.graph.require_node(target_id)

        if source_id == target_id:
            return self._single_node_result(
                source_id=source_id,
                algorithm=PathAlgorithm.DIJKSTRA,
            )

        distances: dict[str, float] = {
            node.node_id: inf
            for node in self.graph.nodes()
        }

        distances[source_id] = 0.0

        predecessor: dict[
            str,
            tuple[str, AttackGraphEdge],
        ] = {}

        priority_queue: list[
            tuple[float, str]
        ] = [
            (0.0, source_id)
        ]

        visited: set[str] = set()

        while priority_queue:
            current_cost, current_id = (
                heapq.heappop(priority_queue)
            )

            if current_id in visited:
                continue

            visited.add(current_id)

            if current_id == target_id:
                break

            for relationship in self.graph.neighbours(
                current_id,
                enabled_only=True,
            ):
                neighbour_id = (
                    relationship.node.node_id
                )
                edge = relationship.edge

                candidate_cost = (
                    current_cost
                    + edge.attacker_cost
                )

                if (
                    candidate_cost
                    >= distances[neighbour_id]
                ):
                    continue

                distances[neighbour_id] = (
                    candidate_cost
                )

                predecessor[neighbour_id] = (
                    current_id,
                    edge,
                )

                heapq.heappush(
                    priority_queue,
                    (
                        candidate_cost,
                        neighbour_id,
                    ),
                )

        if distances[target_id] == inf:
            return self._not_found_result(
                source_id=source_id,
                target_id=target_id,
                algorithm=PathAlgorithm.DIJKSTRA,
            )

        return self._build_result(
            source_id=source_id,
            target_id=target_id,
            predecessor=predecessor,
            algorithm=PathAlgorithm.DIJKSTRA,
        )

    def nearest_critical_asset(
        self,
        source_id: str,
        algorithm: PathAlgorithm = (
            PathAlgorithm.DIJKSTRA
        ),
        exclude_compromised: bool = False,
    ) -> CriticalAssetPathResult:
        self.graph.require_node(source_id)

        critical_nodes = [
            node
            for node in self.graph.critical_nodes()
            if node.node_id != source_id
            and (
                not exclude_compromised
                or not node.compromised
            )
        ]

        candidate_paths: list[
            AttackPathResult
        ] = []

        for node in critical_nodes:
            if algorithm == PathAlgorithm.BFS:
                result = self.shortest_hop_path(
                    source_id,
                    node.node_id,
                )
            else:
                result = self.lowest_resistance_path(
                    source_id,
                    node.node_id,
                )

            if result.found:
                candidate_paths.append(result)

        if not candidate_paths:
            return CriticalAssetPathResult(
                source_id=source_id,
                target_id=None,
                found=False,
                target_criticality=None,
                algorithm=algorithm,
                path=None,
                searched_target_count=len(
                    critical_nodes
                ),
            )

        if algorithm == PathAlgorithm.BFS:
            best_path = min(
                candidate_paths,
                key=lambda path: (
                    path.hop_count,
                    path.total_cost,
                    path.target_id,
                ),
            )
        else:
            best_path = min(
                candidate_paths,
                key=lambda path: (
                    path.total_cost,
                    path.hop_count,
                    path.target_id,
                ),
            )

        target = self.graph.require_node(
            best_path.target_id
        )

        return CriticalAssetPathResult(
            source_id=source_id,
            target_id=best_path.target_id,
            found=True,
            target_criticality=target.criticality,
            algorithm=algorithm,
            path=best_path,
            searched_target_count=len(
                critical_nodes
            ),
        )

    def all_reachable_critical_paths(
        self,
        source_id: str,
        algorithm: PathAlgorithm = (
            PathAlgorithm.DIJKSTRA
        ),
    ) -> list[AttackPathResult]:
        self.graph.require_node(source_id)

        paths: list[AttackPathResult] = []

        for node in self.graph.critical_nodes():
            if node.node_id == source_id:
                continue

            if algorithm == PathAlgorithm.BFS:
                result = self.shortest_hop_path(
                    source_id,
                    node.node_id,
                )
            else:
                result = self.lowest_resistance_path(
                    source_id,
                    node.node_id,
                )

            if result.found:
                paths.append(result)

        if algorithm == PathAlgorithm.BFS:
            return sorted(
                paths,
                key=lambda path: (
                    path.hop_count,
                    path.total_cost,
                    path.target_id,
                ),
            )

        return sorted(
            paths,
            key=lambda path: (
                path.total_cost,
                path.hop_count,
                path.target_id,
            ),
        )

    def _build_result(
        self,
        source_id: str,
        target_id: str,
        predecessor: dict[
            str,
            tuple[str, AttackGraphEdge],
        ],
        algorithm: PathAlgorithm,
    ) -> AttackPathResult:
        node_ids: list[str] = [
            target_id
        ]

        edges_reversed: list[
            AttackGraphEdge
        ] = []

        current_id = target_id

        while current_id != source_id:
            previous = predecessor.get(
                current_id
            )

            if previous is None:
                return self._not_found_result(
                    source_id=source_id,
                    target_id=target_id,
                    algorithm=algorithm,
                )

            previous_id, edge = previous

            node_ids.append(previous_id)
            edges_reversed.append(edge)

            current_id = previous_id

        node_ids.reverse()
        edges = list(reversed(edges_reversed))

        steps: list[AttackPathStep] = []
        controls: set[str] = set()

        node_risk_values: list[float] = []

        total_resistance = 0.0
        total_cost = 0.0

        for index, node_id in enumerate(
            node_ids
        ):
            node = self.graph.require_node(
                node_id
            )

            node_risk_values.append(
                node.risk_score
            )

            if index == 0:
                steps.append(
                    AttackPathStep(
                        step_number=0,
                        node_id=node.node_id,
                        node_name=node.name,
                        node_type=node.node_type,
                        criticality=node.criticality,
                        incoming_connection=None,
                        edge_resistance=None,
                        edge_trust_level=None,
                        edge_cost=None,
                        node_risk_score=(
                            node.risk_score
                        ),
                        controls=[],
                    )
                )

                continue

            edge = edges[index - 1]

            total_resistance += (
                edge.resistance
            )
            total_cost += (
                edge.attacker_cost
            )

            controls.update(edge.controls)

            steps.append(
                AttackPathStep(
                    step_number=index,
                    node_id=node.node_id,
                    node_name=node.name,
                    node_type=node.node_type,
                    criticality=node.criticality,
                    incoming_connection=(
                        edge.connection_type
                    ),
                    edge_resistance=(
                        edge.resistance
                    ),
                    edge_trust_level=(
                        edge.trust_level
                    ),
                    edge_cost=(
                        edge.attacker_cost
                    ),
                    node_risk_score=(
                        node.risk_score
                    ),
                    controls=edge.controls,
                )
            )

        average_node_risk = (
            sum(node_risk_values)
            / len(node_risk_values)
            if node_risk_values
            else 0.0
        )

        target_node = self.graph.require_node(
            target_id
        )

        target_impact = (
            target_node.business_impact_score
        )

        ease_of_traversal = (
            1.0
            / (1.0 + total_cost)
        )

        path_risk_score = min(
            (
                0.40 * average_node_risk
                + 0.35 * target_impact
                + 0.25 * ease_of_traversal
            ),
            1.0,
        )

        explanation = (
            f"{algorithm.value.upper()} found an attack path "
            f"from {source_id} to {target_id} through "
            f"{len(node_ids) - 1} edges. "
            f"Total attacker cost is {total_cost:.4f}."
        )

        return AttackPathResult(
            source_id=source_id,
            target_id=target_id,
            found=True,
            algorithm=algorithm,
            hop_count=len(node_ids) - 1,
            total_resistance=round(
                total_resistance,
                4,
            ),
            total_cost=round(
                total_cost,
                4,
            ),
            path_risk_score=round(
                path_risk_score,
                4,
            ),
            node_ids=node_ids,
            steps=steps,
            controls_encountered=sorted(
                controls
            ),
            explanation=explanation,
        )

    def _single_node_result(
        self,
        source_id: str,
        algorithm: PathAlgorithm,
    ) -> AttackPathResult:
        node = self.graph.require_node(
            source_id
        )

        return AttackPathResult(
            source_id=source_id,
            target_id=source_id,
            found=True,
            algorithm=algorithm,
            hop_count=0,
            total_resistance=0.0,
            total_cost=0.0,
            path_risk_score=node.risk_score,
            node_ids=[source_id],
            steps=[
                AttackPathStep(
                    step_number=0,
                    node_id=node.node_id,
                    node_name=node.name,
                    node_type=node.node_type,
                    criticality=node.criticality,
                    incoming_connection=None,
                    edge_resistance=None,
                    edge_trust_level=None,
                    edge_cost=None,
                    node_risk_score=(
                        node.risk_score
                    ),
                    controls=[],
                )
            ],
            controls_encountered=[],
            explanation=(
                "Source and target are the same node."
            ),
        )

    @staticmethod
    def _not_found_result(
        source_id: str,
        target_id: str,
        algorithm: PathAlgorithm,
    ) -> AttackPathResult:
        return AttackPathResult(
            source_id=source_id,
            target_id=target_id,
            found=False,
            algorithm=algorithm,
            hop_count=0,
            total_resistance=0.0,
            total_cost=0.0,
            path_risk_score=0.0,
            node_ids=[],
            steps=[],
            controls_encountered=[],
            explanation=(
                f"No enabled path exists from "
                f"{source_id} to {target_id}."
            ),
        )