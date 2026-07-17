from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.attack_graph.remediation import RemediationPlan
from app.attack_graph.schemas import (
    AttackPathResult,
    BlastRadiusResult,
    ContainmentComparison,
    CriticalAssetPathResult,
    GraphStatistics,
    InfrastructureTopology,
    PathAlgorithm,
)
from app.attack_graph.service import attack_graph_service


router = APIRouter(
    prefix="/api/attack-graph",
    tags=["Attack Graph Intelligence"],
)


class PathRequest(BaseModel):
    source_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)


class NearestCriticalRequest(BaseModel):
    source_id: str = Field(min_length=1)
    algorithm: PathAlgorithm = PathAlgorithm.DIJKSTRA
    exclude_compromised: bool = False


class BlastRadiusRequest(BaseModel):
    source_id: str = Field(min_length=1)

    maximum_depth: int | None = Field(
        default=None,
        ge=0,
    )

    include_source: bool = True


class ConnectionToDisable(BaseModel):
    source_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)


class ContainmentRequest(BaseModel):
    source_id: str = Field(min_length=1)

    connections: list[ConnectionToDisable] = Field(
        min_length=1,
        max_length=100,
    )

    maximum_depth: int | None = Field(
        default=None,
        ge=0,
    )


class RemediationRequest(BaseModel):
    source_id: str = Field(min_length=1)

    maximum_depth: int | None = Field(
        default=None,
        ge=0,
    )

    maximum_recommendations: int = Field(
        default=10,
        ge=1,
        le=50,
    )


@router.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "module": "attack-graph",
        "topology_loaded": attack_graph_service.is_loaded,
        "algorithms": [
            "adjacency-list graph",
            "breadth-first search",
            "Dijkstra shortest path",
            "depth-first search",
            "priority-queue remediation ranking",
        ],
    }


@router.post(
    "/topology/load-default",
    response_model=InfrastructureTopology,
)
def load_default_topology() -> InfrastructureTopology:
    try:
        return attack_graph_service.load_default_topology()
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load topology: {exc}",
        ) from exc


@router.post(
    "/topology/load",
    response_model=InfrastructureTopology,
)
def load_topology(
    topology: InfrastructureTopology,
) -> InfrastructureTopology:
    try:
        return attack_graph_service.load_topology(
            topology
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@router.get(
    "/topology",
    response_model=InfrastructureTopology,
)
def get_topology() -> InfrastructureTopology:
    try:
        return attack_graph_service.active_topology()
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.get(
    "/statistics",
    response_model=GraphStatistics,
)
def graph_statistics() -> GraphStatistics:
    try:
        return attack_graph_service.statistics()
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.post(
    "/path/bfs",
    response_model=AttackPathResult,
)
def find_bfs_path(
    request: PathRequest,
) -> AttackPathResult:
    try:
        return attack_graph_service.bfs_path(
            source_id=request.source_id,
            target_id=request.target_id,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.post(
    "/path/dijkstra",
    response_model=AttackPathResult,
)
def find_dijkstra_path(
    request: PathRequest,
) -> AttackPathResult:
    try:
        return attack_graph_service.dijkstra_path(
            source_id=request.source_id,
            target_id=request.target_id,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.post(
    "/path/nearest-critical",
    response_model=CriticalAssetPathResult,
)
def find_nearest_critical_asset(
    request: NearestCriticalRequest,
) -> CriticalAssetPathResult:
    try:
        return attack_graph_service.nearest_critical_asset(
            source_id=request.source_id,
            algorithm=request.algorithm,
            exclude_compromised=request.exclude_compromised,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.post(
    "/blast-radius",
    response_model=BlastRadiusResult,
)
def calculate_blast_radius(
    request: BlastRadiusRequest,
) -> BlastRadiusResult:
    try:
        return attack_graph_service.blast_radius(
            source_id=request.source_id,
            maximum_depth=request.maximum_depth,
            include_source=request.include_source,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@router.post(
    "/containment/compare",
    response_model=ContainmentComparison,
)
def compare_containment(
    request: ContainmentRequest,
) -> ContainmentComparison:
    try:
        connections = [
            (
                connection.source_id,
                connection.target_id,
            )
            for connection in request.connections
        ]

        return attack_graph_service.containment_comparison(
            source_id=request.source_id,
            connections_to_disable=connections,
            maximum_depth=request.maximum_depth,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@router.post(
    "/remediation/plan",
    response_model=RemediationPlan,
)
def generate_remediation_plan(
    request: RemediationRequest,
) -> RemediationPlan:
    try:
        return attack_graph_service.remediation_plan(
            source_id=request.source_id,
            maximum_depth=request.maximum_depth,
            maximum_recommendations=(
                request.maximum_recommendations
            ),
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc