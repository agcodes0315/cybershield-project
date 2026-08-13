from __future__ import annotations

import csv
import random
import statistics
import sys
import time
from pathlib import Path


# ============================================================
# PROJECT IMPORT SETUP
# ============================================================

ROOT_DIR = Path(__file__).resolve().parents[1]
DETECTION_ENGINE_DIR = ROOT_DIR / "detection-engine"

sys.path.insert(0, str(DETECTION_ENGINE_DIR))


from app.attack_graph.graph import AttackGraph
from app.attack_graph.pathfinder import AttackPathfinder
from app.attack_graph.blast_radius import BlastRadiusAnalyzer
from app.attack_graph.schemas import (
    AttackGraphNode,
    AttackGraphEdge,
    AssetCriticality,
    GraphNodeType,
    ConnectionType,
)


# ============================================================
# BENCHMARK CONFIGURATION
# ============================================================

GRAPH_SIZES = [
    100,
    500,
    1000,
    2500,
]

EDGES_PER_NODE = 4

RUNS_PER_ALGORITHM = 10

RANDOM_SEED = 42


# ============================================================
# HELPERS
# ============================================================

def milliseconds(seconds: float) -> float:
    return seconds * 1000


def percentile(
    values: list[float],
    percentile_value: float,
) -> float:

    if not values:
        return 0.0

    ordered = sorted(values)

    index = round(
        (len(ordered) - 1)
        * percentile_value
    )

    return ordered[index]


# ============================================================
# SYNTHETIC ATTACK GRAPH
# ============================================================

def build_graph(
    node_count: int,
    edges_per_node: int,
) -> AttackGraph:

    graph = AttackGraph()

    rng = random.Random(
        RANDOM_SEED + node_count
    )

    # --------------------------------------------------------
    # Nodes
    # --------------------------------------------------------

    for index in range(node_count):

        if index % 20 == 0:
            criticality = (
                AssetCriticality.CRITICAL
            )

        elif index % 10 == 0:
            criticality = (
                AssetCriticality.HIGH
            )

        elif index % 5 == 0:
            criticality = (
                AssetCriticality.MEDIUM
            )

        else:
            criticality = (
                AssetCriticality.LOW
            )

        node = AttackGraphNode(
            node_id=f"node-{index}",
            name=f"Asset {index}",
            node_type=GraphNodeType.SERVER,
            criticality=criticality,
            exposure_score=rng.random(),
            vulnerability_score=rng.random(),
            business_impact_score=rng.random(),
            compromised=(index == 0),
        )

        graph.add_node(node)

    # --------------------------------------------------------
    # Guarantee connectivity
    #
    # node-0 -> node-1 -> node-2 -> ...
    # --------------------------------------------------------

    for index in range(
        node_count - 1
    ):

        edge = AttackGraphEdge(
            source_id=f"node-{index}",
            target_id=f"node-{index + 1}",
            connection_type=(
                ConnectionType.CONNECTS_TO
            ),
            resistance=rng.uniform(
                0.01,
                1.0,
            ),
            trust_level=rng.uniform(
                0.0,
                1.0,
            ),
            controls=[],
            enabled=True,
            bidirectional=False,
        )

        graph.add_edge(edge)

    # --------------------------------------------------------
    # Additional random edges
    # --------------------------------------------------------

    target_edge_count = (
        node_count
        * edges_per_node
    )

    current_edge_count = (
        node_count - 1
    )

    attempts = 0

    maximum_attempts = (
        target_edge_count * 50
    )

    while (
        current_edge_count
        < target_edge_count
        and attempts < maximum_attempts
    ):

        attempts += 1

        source_index = rng.randrange(
            node_count
        )

        target_index = rng.randrange(
            node_count
        )

        if source_index == target_index:
            continue

        edge = AttackGraphEdge(
            source_id=f"node-{source_index}",
            target_id=f"node-{target_index}",
            connection_type=(
                ConnectionType.CONNECTS_TO
            ),
            resistance=rng.uniform(
                0.01,
                1.0,
            ),
            trust_level=rng.uniform(
                0.0,
                1.0,
            ),
            controls=[],
            enabled=True,
            bidirectional=False,
        )

        try:
            graph.add_edge(edge)
            current_edge_count += 1

        except ValueError:
            # Duplicate edge.
            continue

    return graph


# ============================================================
# GENERIC BENCHMARK
# ============================================================

def benchmark_operation(
    operation,
    runs: int,
) -> dict[str, float]:

    durations: list[float] = []

    # Warm-up
    operation()

    for _ in range(runs):

        start = time.perf_counter()

        operation()

        end = time.perf_counter()

        durations.append(
            milliseconds(
                end - start
            )
        )

    return {
        "mean_ms": round(
            statistics.mean(durations),
            4,
        ),
        "median_ms": round(
            statistics.median(durations),
            4,
        ),
        "min_ms": round(
            min(durations),
            4,
        ),
        "max_ms": round(
            max(durations),
            4,
        ),
        "p95_ms": round(
            percentile(
                durations,
                0.95,
            ),
            4,
        ),
    }


# ============================================================
# RUN BENCHMARKS
# ============================================================

def run_benchmarks() -> list[dict]:

    results: list[dict] = []

    for node_count in GRAPH_SIZES:

        print()
        print("=" * 72)

        print(
            f"Building synthetic CyberShield graph: "
            f"{node_count:,} nodes"
        )

        graph = build_graph(
            node_count=node_count,
            edges_per_node=(
                EDGES_PER_NODE
            ),
        )

        pathfinder = AttackPathfinder(
            graph
        )

        blast_analyzer = (
            BlastRadiusAnalyzer(
                graph
            )
        )

        source_id = "node-0"

        target_id = (
            f"node-{node_count - 1}"
        )

        actual_nodes = len(
            graph.nodes()
        )

        actual_edges = len(
            graph.edges()
        )

        critical_nodes = len(
            graph.critical_nodes()
        )

        print(
            f"Nodes:           {actual_nodes:,}"
        )

        print(
            f"Edges:           {actual_edges:,}"
        )

        print(
            f"Critical assets: {critical_nodes:,}"
        )

        # ----------------------------------------------------
        # BFS
        # ----------------------------------------------------

        print(
            "\nBenchmarking BFS..."
        )

        bfs_metrics = benchmark_operation(
            lambda: (
                pathfinder.shortest_hop_path(
                    source_id,
                    target_id,
                )
            ),
            RUNS_PER_ALGORITHM,
        )

        results.append(
            {
                "algorithm": "BFS",
                "nodes": actual_nodes,
                "edges": actual_edges,
                "critical_assets": (
                    critical_nodes
                ),
                **bfs_metrics,
            }
        )

        # ----------------------------------------------------
        # DIJKSTRA
        # ----------------------------------------------------

        print(
            "Benchmarking Dijkstra..."
        )

        dijkstra_metrics = (
            benchmark_operation(
                lambda: (
                    pathfinder.lowest_resistance_path(
                        source_id,
                        target_id,
                    )
                ),
                RUNS_PER_ALGORITHM,
            )
        )

        results.append(
            {
                "algorithm": "Dijkstra",
                "nodes": actual_nodes,
                "edges": actual_edges,
                "critical_assets": (
                    critical_nodes
                ),
                **dijkstra_metrics,
            }
        )

        # ----------------------------------------------------
        # DFS / BLAST RADIUS
        # ----------------------------------------------------

        print(
            "Benchmarking DFS blast radius..."
        )

        dfs_metrics = benchmark_operation(
            lambda: (
                blast_analyzer.analyse(
                    source_id
                )
            ),
            RUNS_PER_ALGORITHM,
        )

        results.append(
            {
                "algorithm": (
                    "DFS Blast Radius"
                ),
                "nodes": actual_nodes,
                "edges": actual_edges,
                "critical_assets": (
                    critical_nodes
                ),
                **dfs_metrics,
            }
        )

        # ----------------------------------------------------
        # CURRENT NEAREST CRITICAL ASSET IMPLEMENTATION
        # ----------------------------------------------------

        print(
            "Benchmarking nearest "
            "critical-asset search..."
        )

        nearest_metrics = (
            benchmark_operation(
                lambda: (
                    pathfinder.nearest_critical_asset(
                        source_id
                    )
                ),
                RUNS_PER_ALGORITHM,
            )
        )

        results.append(
            {
                "algorithm": (
                    "Nearest Critical Asset"
                ),
                "nodes": actual_nodes,
                "edges": actual_edges,
                "critical_assets": (
                    critical_nodes
                ),
                **nearest_metrics,
            }
        )

        # ----------------------------------------------------
        # DISPLAY CURRENT GRAPH RESULTS
        # ----------------------------------------------------

        print()
        print(
            f"{'Algorithm':<28}"
            f"{'Mean (ms)':>12}"
            f"{'Median':>12}"
            f"{'P95':>12}"
        )

        print("-" * 64)

        for result in results[-4:]:

            print(
                f"{result['algorithm']:<28}"
                f"{result['mean_ms']:>12.4f}"
                f"{result['median_ms']:>12.4f}"
                f"{result['p95_ms']:>12.4f}"
            )

    return results


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(
    results: list[dict],
) -> Path:

    output_file = (
        ROOT_DIR
        / "evaluation"
        / "graph_algorithm_benchmark_before.csv"
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "algorithm",
        "nodes",
        "edges",
        "critical_assets",
        "mean_ms",
        "median_ms",
        "min_ms",
        "max_ms",
        "p95_ms",
    ]

    with output_file.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(
            results
        )

    return output_file


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print(
        "CyberShield Graph Algorithm Benchmark"
    )

    print(
        "BFS | Dijkstra | DFS | "
        "Critical-Asset Search"
    )

    results = run_benchmarks()

    output_file = save_results(
        results
    )

    print()
    print("=" * 72)

    print(
        "Benchmark complete."
    )

    print(
        f"Results saved to:\n"
        f"{output_file}"
    )