from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.prediction.schemas import (
    AttackPredictionResult,
    PredictionEvaluation,
    TransitionMatrixSummary,
)
from app.prediction.service import (
    predictive_attack_service,
)


router = APIRouter(
    prefix="/api/prediction",
    tags=["Predictive Attack Intelligence"],
)


class PredictionRequest(BaseModel):
    events: list[dict[str, Any]] = Field(
        min_length=1,
        max_length=10000,
    )

    horizon: int = Field(
        default=3,
        ge=1,
        le=10,
    )

    source_node_id: str | None = None


class EvaluationRequest(BaseModel):
    events: list[dict[str, Any]] = Field(
        min_length=2,
        max_length=10000,
    )


@router.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "module": "predictive-attack-intelligence",
        "model_version": "apt-transition-v1",
        "algorithm": "Viterbi dynamic programming",
        "capabilities": [
            "MITRE tactic sequence prediction",
            "Probable target-asset prediction",
            "Architecture-aware defensive actions",
            "Sequence-prefix evaluation",
        ],
    }


@router.get(
    "/transitions",
    response_model=TransitionMatrixSummary,
)
def transition_matrix() -> TransitionMatrixSummary:
    return (
        predictive_attack_service
        .transitions
        .summary()
    )


@router.post(
    "/next-stage",
    response_model=AttackPredictionResult,
)
def predict_next_stage(
    request: PredictionRequest,
) -> AttackPredictionResult:
    try:
        return predictive_attack_service.predict(
            events=request.events,
            horizon=request.horizon,
            source_node_id=request.source_node_id,
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


@router.post(
    "/evaluate",
    response_model=PredictionEvaluation,
)
def evaluate_prediction(
    request: EvaluationRequest,
) -> PredictionEvaluation:
    try:
        return (
            predictive_attack_service
            .evaluate_sequence(
                request.events
            )
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc