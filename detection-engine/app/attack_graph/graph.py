from __future__ import annotations

from collections import defaultdict
from threading import RLock
from typing import Iterable

from .schemas import (
    AssetCriticality,
    AttackGraphEdge,
    AttackGraphNode,
    GraphStatistics,
    NeighbourRelationship,
)


class AttackGraph:
    """
    Directed weighted graph for critical infrastructure.

    Data structures:
    - Hash map for O(1)-average node lookup.
    - Adjacency list for memory-efficient edge storage.
    - Reverse adjacency list for incoming-edge analysis.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, AttackGraphNode] = {}

        self._adjacency: dict[
            str,
            list[AttackGraphEdge],
        ] = defaultdict(list)

        self._reverse_adjacency: dict[
            str,
            list[AttackGraphEdge],
        ] = defaultdict(list)

        self._edge_keys: set[
            tuple[str, str, str]
        ] = set()

        self._lock = RLock()

    def add_node(
        self,
        node: AttackGraphNode,
    ) -> AttackGraphNode:
        with self._lock:
            if node.node_id in self._nodes:
                raise ValueError(
                    f"Node already exists: {node.node_id}"
                )

            self._nodes[node.node_id] = node

            # Initialise empty adjacency entries so isolated nodes
            # still appear in graph statistics.
            self._adjacency[node.node_id]
            self._reverse_adjacency[node.node_id]

            return node

    def upsert_node(
        self,
        node: AttackGraphNode,
    ) -> AttackGraphNode:
        with self._lock:
            self._nodes[node.node_id] = node

            self._adjacency[node.node_id]
            self._reverse_adjacency[node.node_id]

            return node

    def add_edge(
        self,
        edge: AttackGraphEdge,
    ) -> AttackGraphEdge:
        with self._lock:
            self._validate_edge_nodes(edge)

            key = self._edge_key(edge)

            if key in self._edge_keys:
                raise ValueError(
                    "Edge already exists: "
                    f"{edge.source_id} -> {edge.target_id} "
                    f"({edge.connection_type.value})"
                )

            self._store_directed_edge(edge)

            if edge.bidirectional:
                reverse_edge = edge.model_copy(
                    update={
                        "source_id": edge.target_id,
                        "target_id": edge.source_id,
                        "bidirectional": False,
                    }
                )

                reverse_key = self._edge_key(
                    reverse_edge
                )

                if reverse_key not in self._edge_keys:
                    self._store_directed_edge(
                        reverse_edge
                    )

            return edge

    def load(
        self,
        nodes: Iterable[AttackGraphNode],
        edges: Iterable[AttackGraphEdge],
        clear_existing: bool = True,
    ) -> None:
        with self._lock:
            if clear_existing:
                self.clear()

            for node in nodes:
                self.add_node(node)

            for edge in edges:
                self.add_edge(edge)

    def get_node(
        self,
        node_id: str,
    ) -> AttackGraphNode | None:
        with self._lock:
            return self._nodes.get(node_id)

    def require_node(
        self,
        node_id: str,
    ) -> AttackGraphNode:
        node = self.get_node(node_id)

        if node is None:
            raise KeyError(
                f"Node not found: {node_id}"
            )

        return node

    def nodes(self) -> list[AttackGraphNode]:
        with self._lock:
            return list(self._nodes.values())

    def edges(self) -> list[AttackGraphEdge]:
        with self._lock:
            return [
                edge
                for edge_list in self._adjacency.values()
                for edge in edge_list
            ]

    def neighbours(
        self,
        node_id: str,
        enabled_only: bool = True,
    ) -> list[NeighbourRelationship]:
        with self._lock:
            self.require_node(node_id)

            relationships: list[
                NeighbourRelationship
            ] = []

            for edge in self._adjacency[node_id]:
                if enabled_only and not edge.enabled:
                    continue

                target = self._nodes[edge.target_id]

                relationships.append(
                    NeighbourRelationship(
                        node=target,
                        edge=edge,
                    )
                )

            return relationships

    def incoming_neighbours(
        self,
        node_id: str,
        enabled_only: bool = True,
    ) -> list[NeighbourRelationship]:
        with self._lock:
            self.require_node(node_id)

            relationships: list[
                NeighbourRelationship
            ] = []

            for edge in self._reverse_adjacency[node_id]:
                if enabled_only and not edge.enabled:
                    continue

                source = self._nodes[edge.source_id]

                relationships.append(
                    NeighbourRelationship(
                        node=source,
                        edge=edge,
                    )
                )

            return relationships

    def critical_nodes(
        self,
    ) -> list[AttackGraphNode]:
        with self._lock:
            return [
                node
                for node in self._nodes.values()
                if node.criticality
                == AssetCriticality.CRITICAL
            ]

    def compromised_nodes(
        self,
    ) -> list[AttackGraphNode]:
        with self._lock:
            return [
                node
                for node in self._nodes.values()
                if node.compromised
            ]

    def mark_compromised(
        self,
        node_id: str,
        compromised: bool = True,
    ) -> AttackGraphNode:
        with self._lock:
            node = self.require_node(node_id)

            updated = node.model_copy(
                update={
                    "compromised": compromised
                }
            )

            self._nodes[node_id] = updated

            return updated

    def disable_edge(
        self,
        source_id: str,
        target_id: str,
    ) -> int:
        """
        Disable every directed edge between the two nodes.

        Returns the number of changed edges.
        """
        with self._lock:
            self.require_node(source_id)
            self.require_node(target_id)

            changed = 0
            updated_edges: list[
                AttackGraphEdge
            ] = []

            for edge in self._adjacency[source_id]:
                if (
                    edge.target_id == target_id
                    and edge.enabled
                ):
                    edge = edge.model_copy(
                        update={"enabled": False}
                    )
                    changed += 1

                updated_edges.append(edge)

            self._adjacency[source_id] = (
                updated_edges
            )

            if changed:
                self._rebuild_reverse_adjacency()

            return changed

    def statistics(self) -> GraphStatistics:
        with self._lock:
            node_count = len(self._nodes)
            edge_count = sum(
                len(edge_list)
                for edge_list
                in self._adjacency.values()
            )

            isolated_node_count = sum(
                1
                for node_id in self._nodes
                if not self._adjacency[node_id]
                and not self._reverse_adjacency[node_id]
            )

            average_out_degree = (
                edge_count / node_count
                if node_count
                else 0.0
            )

            return GraphStatistics(
                node_count=node_count,
                edge_count=edge_count,
                critical_node_count=len(
                    self.critical_nodes()
                ),
                compromised_node_count=len(
                    self.compromised_nodes()
                ),
                isolated_node_count=(
                    isolated_node_count
                ),
                average_out_degree=round(
                    average_out_degree,
                    4,
                ),
            )

    def clear(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._adjacency.clear()
            self._reverse_adjacency.clear()
            self._edge_keys.clear()

    def contains_node(
        self,
        node_id: str,
    ) -> bool:
        with self._lock:
            return node_id in self._nodes

    def contains_edge(
        self,
        source_id: str,
        target_id: str,
    ) -> bool:
        with self._lock:
            return any(
                edge.target_id == target_id
                for edge
                in self._adjacency.get(
                    source_id,
                    [],
                )
            )

    def _validate_edge_nodes(
        self,
        edge: AttackGraphEdge,
    ) -> None:
        if edge.source_id not in self._nodes:
            raise ValueError(
                "Cannot add edge because source "
                f"node does not exist: {edge.source_id}"
            )

        if edge.target_id not in self._nodes:
            raise ValueError(
                "Cannot add edge because target "
                f"node does not exist: {edge.target_id}"
            )

        if edge.source_id == edge.target_id:
            raise ValueError(
                "Self-referencing edges are not allowed"
            )

    def _store_directed_edge(
        self,
        edge: AttackGraphEdge,
    ) -> None:
        key = self._edge_key(edge)

        self._adjacency[
            edge.source_id
        ].append(edge)

        self._reverse_adjacency[
            edge.target_id
        ].append(edge)

        self._edge_keys.add(key)

    @staticmethod
    def _edge_key(
        edge: AttackGraphEdge,
    ) -> tuple[str, str, str]:
        return (
            edge.source_id,
            edge.target_id,
            edge.connection_type.value,
        )

    def _rebuild_reverse_adjacency(
        self,
    ) -> None:
        rebuilt: dict[
            str,
            list[AttackGraphEdge],
        ] = defaultdict(list)

        for node_id in self._nodes:
            rebuilt[node_id]

        for edge_list in self._adjacency.values():
            for edge in edge_list:
                rebuilt[edge.target_id].append(
                    edge
                )

        self._reverse_adjacency = rebuilt