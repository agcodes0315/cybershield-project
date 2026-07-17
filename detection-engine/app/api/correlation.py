from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.correlation.schemas import (
    CorrelatedIncident,
    CorrelationSummary,
)
from app.correlation.service import correlation_service
from app.mitre.schemas import MitreMappingResult
from app.mitre.service import mitre_mapping_service


router = APIRouter(
    prefix="/api/correlation",
    tags=["Attack Correlation"],
)


class CorrelationRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(
        min_length=1,
        max_length=10000,
    )


class CorrelationResponse(BaseModel):
    incidents: List[CorrelatedIncident]
    summary: CorrelationSummary


@router.post(
    "/analyse",
    response_model=CorrelationResponse,
)
def analyse_events(
    request: CorrelationRequest,
) -> CorrelationResponse:
    try:
        incidents, summary = correlation_service.correlate(
            request.events
        )

        return CorrelationResponse(
            incidents=incidents,
            summary=summary,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Correlation failed: {exc}",
        ) from exc


@router.post(
    "/mitre-map",
    response_model=List[MitreMappingResult],
)
def map_events_to_mitre(
    request: CorrelationRequest,
) -> List[MitreMappingResult]:
    return mitre_mapping_service.map_batch(
        request.events
    )


@router.get("/incidents")
def list_incidents() -> Dict[str, Any]:
    incidents = correlation_service.incidents()

    return {
        "count": len(incidents),
        "incidents": [
            incident.model_dump(mode="json")
            for incident in incidents
        ],
    }


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
) -> CorrelatedIncident:
    incident = correlation_service.get_incident(
        incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return incident


@router.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "window_minutes": int(
            correlation_service.window.total_seconds()
            / 60
        ),
        "minimum_events": correlation_service.minimum_events,
        "incident_count": len(
            correlation_service.incidents()
        ),
    }