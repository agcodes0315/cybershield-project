from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.attack_graph.remediation import (
    RemediationCandidate,
)
from app.attack_graph.schemas import (
    BlastRadiusResult,
)
from app.prediction.schemas import (
    AttackPredictionResult,
)
from app.response.schemas import (
    ResponseExecution,
    ResponsePlaybook,
    ResponseTarget,
)


class ResiliencePipelineRequest(BaseModel):
    incident_id: str = Field(min_length=1)

    events: list[dict[str, Any]] = Field(
        min_length=1,
        max_length=10000,
    )

    source_node_id: str | None = None

    requested_by: str = Field(
        default="cybershield-pipeline",
        min_length=1,
    )

    prediction_horizon: int = Field(
        default=3,
        ge=1,
        le=10,
    )

    maximum_recommendations: int = Field(
        default=5,
        ge=1,
        le=20,
    )

    auto_create_response: bool = True

    targets: list[ResponseTarget] = Field(
        default_factory=list
    )


class PipelineDecision(BaseModel):
    severity: str

    recommended_playbook_id: str | None = None
    recommended_playbook_name: str | None = None

    rationale: list[str] = Field(
        default_factory=list
    )

    human_approval_required: bool = True
    simulation_only: bool = True


class ResiliencePipelineResult(BaseModel):
    pipeline_run_id: str
    incident_id: str

    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )

    prediction: AttackPredictionResult

    blast_radius: BlastRadiusResult | None = None

    remediation_candidates: list[
        RemediationCandidate
    ] = Field(
        default_factory=list
    )

    recommended_playbooks: list[
        ResponsePlaybook
    ] = Field(
        default_factory=list
    )

    decision: PipelineDecision

    response_execution: (
        ResponseExecution | None
    ) = None

    pipeline_steps: list[str] = Field(
        default_factory=list
    )

    explanation: str