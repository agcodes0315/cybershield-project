from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from app.mitre.schemas import MitreTechnique


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class CorrelatedEvidence(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    source_type: str
    entity_id: str
    asset_id: Optional[str] = None
    anomaly_score: float = Field(ge=0.0, le=1.0)
    contribution: float = Field(ge=0.0, le=1.0)
    description: str
    mitre_techniques: List[MitreTechnique] = Field(
        default_factory=list
    )


class AttackStage(BaseModel):
    order: int
    tactic: str
    technique_id: str
    technique_name: str
    event_id: str
    timestamp: datetime
    confidence: float = Field(ge=0.0, le=1.0)


class CorrelatedIncident(BaseModel):
    incident_id: str = Field(
        default_factory=lambda: (
            f"INC-{uuid4().hex[:12].upper()}"
        )
    )

    title: str
    summary: str

    organisation_id: str
    primary_entity_id: str

    status: IncidentStatus = IncidentStatus.OPEN
    severity: IncidentSeverity

    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)

    first_seen: datetime
    last_seen: datetime
    detection_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    event_count: int
    unique_asset_count: int
    stage_count: int

    evidence: List[CorrelatedEvidence]
    attack_stages: List[AttackStage]

    probable_next_tactic: Optional[str] = None
    critical_assets_at_risk: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)

    correlation_rules: List[str] = Field(default_factory=list)


class CorrelationSummary(BaseModel):
    events_processed: int
    incidents_created: int
    high_or_critical_incidents: int
    correlated_event_count: int
    unmatched_event_count: int