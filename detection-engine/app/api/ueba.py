from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.ueba.schemas import (
    AnomalyResult,
    UEBATrainingSummary,
)
from app.ueba.service import ueba_service


router = APIRouter(
    prefix="/api/ueba",
    tags=["UEBA"],
)


class TrainingRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(
        min_length=20
    )
    save_model: bool = True


class AnalysisRequest(BaseModel):
    event: Dict[str, Any]


class BatchAnalysisRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(
        min_length=1,
        max_length=5000,
    )


@router.post(
    "/train",
    response_model=UEBATrainingSummary,
)
def train_ueba(
    request: TrainingRequest,
) -> UEBATrainingSummary:
    try:
        return ueba_service.train(
            request.events,
            save_model=request.save_model,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"UEBA training failed: {exc}",
        ) from exc


@router.post(
    "/analyse",
    response_model=AnomalyResult,
)
def analyse_event(
    request: AnalysisRequest,
) -> AnomalyResult:
    try:
        return ueba_service.analyse(
            request.event
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"UEBA analysis failed: {exc}",
        ) from exc


@router.post(
    "/analyse-batch",
    response_model=List[AnomalyResult],
)
def analyse_batch(
    request: BatchAnalysisRequest,
) -> List[AnomalyResult]:
    try:
        return ueba_service.analyse_batch(
            request.events
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"UEBA batch analysis failed: {exc}",
        ) from exc


@router.get("/profiles")
def list_profiles() -> Dict[str, Any]:
    profiles = ueba_service.profiles()

    return {
        "count": len(profiles),
        "profiles": {
            entity_id: profile.model_dump(
                mode="json"
            )
            for entity_id, profile in profiles.items()
        },
    }


@router.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "model_trained": ueba_service.model.is_trained,
        "profile_count": ueba_service.baselines.count(),
        "model_version": "ueba-iforest-v1",
    }