from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PredictionMethod(str, Enum):
    VITERBI = "viterbi"
    TRANSITION_RANKING = "transition_ranking"


class PredictedAttackStage(BaseModel):
    sequence_number: int = Field(ge=1)

    tactic: str
    probability: float = Field(
        ge=0.0,
        le=1.0,
    )

    cumulative_probability: float = Field(
        ge=0.0,
        le=1.0,
    )

    likely_target_asset_id: str | None = None
    likely_target_asset_name: str | None = None

    recommended_defensive_actions: list[str] = Field(
        default_factory=list
    )

    explanation: str


class AttackPredictionResult(BaseModel):
    prediction_id: str

    organisation_id: str
    primary_entity_id: str

    observed_event_count: int = Field(ge=0)

    observed_tactics: list[str] = Field(
        default_factory=list
    )

    observed_techniques: list[str] = Field(
        default_factory=list
    )

    current_tactic: str | None = None

    predicted_stages: list[PredictedAttackStage] = Field(
        default_factory=list
    )

    most_likely_next_tactic: str | None = None

    most_likely_target_asset_id: str | None = None
    most_likely_target_asset_name: str | None = None

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    method: PredictionMethod

    model_version: str = "apt-transition-v1"

    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    explanation: str

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class TransitionProbability(BaseModel):
    source_tactic: str
    target_tactic: str

    probability: float = Field(
        ge=0.0,
        le=1.0,
    )


class TransitionMatrixSummary(BaseModel):
    tactic_count: int = Field(ge=0)
    transition_count: int = Field(ge=0)

    transitions: list[TransitionProbability] = Field(
        default_factory=list
    )


class PredictionEvaluation(BaseModel):
    evaluated_prefixes: int = Field(ge=0)
    correct_predictions: int = Field(ge=0)

    top_one_accuracy: float = Field(
        ge=0.0,
        le=1.0,
    )

    mean_confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    predictions: list[dict[str, Any]] = Field(
        default_factory=list
    )