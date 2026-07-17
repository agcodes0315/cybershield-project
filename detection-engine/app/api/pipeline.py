from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app.pipeline import (
    ResiliencePipelineRequest,
    ResiliencePipelineResult,
    cyber_resilience_pipeline_service,
)


router = APIRouter(
    prefix="/api/resilience",
    tags=["Cyber Resilience Pipeline"],
)


@router.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "module": "cyber-resilience-pipeline",
        "simulation_only": True,
        "stages": [
            "MITRE mapping",
            "Viterbi attack prediction",
            "attack-graph blast radius",
            "remediation prioritisation",
            "SOAR playbook recommendation",
            "human approval gate",
            "safe response execution",
            "tamper-evident audit logging",
        ],
    }


@router.post(
    "/analyse",
    response_model=ResiliencePipelineResult,
)
def analyse_incident(
    request: ResiliencePipelineRequest,
) -> ResiliencePipelineResult:
    try:
        return (
            cyber_resilience_pipeline_service
            .run(request)
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc