from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class AnomalyLevel(str, Enum):
    NORMAL = "normal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BehaviourFeatureVector(BaseModel):
    login_hour: float = 12.0
    is_off_hours: float = 0.0
    new_device: float = 0.0
    new_location: float = 0.0
    failed_login_count: float = 0.0
    encoded_command: float = 0.0
    privileged_action: float = 0.0
    data_transfer_mb: float = 0.0
    rare_process: float = 0.0
    sensitive_asset_access: float = 0.0
    external_source_ip: float = 0.0
    first_time_asset_access: float = 0.0

    def as_list(self) -> List[float]:
        return [
            self.login_hour,
            self.is_off_hours,
            self.new_device,
            self.new_location,
            self.failed_login_count,
            self.encoded_command,
            self.privileged_action,
            self.data_transfer_mb,
            self.rare_process,
            self.sensitive_asset_access,
            self.external_source_ip,
            self.first_time_asset_access,
        ]


class BehaviourProfile(BaseModel):
    entity_id: str
    entity_type: str = "user"

    event_count: int = 0

    mean_login_hour: float = 12.0
    std_login_hour: float = 0.0

    mean_data_transfer_mb: float = 0.0
    std_data_transfer_mb: float = 0.0

    mean_failed_logins: float = 0.0
    std_failed_logins: float = 0.0

    known_devices: List[str] = Field(default_factory=list)
    known_source_ips: List[str] = Field(default_factory=list)
    known_assets: List[str] = Field(default_factory=list)
    known_event_types: List[str] = Field(default_factory=list)
    known_processes: List[str] = Field(default_factory=list)

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class AnomalyReason(BaseModel):
    code: str
    description: str
    contribution: float = Field(ge=0.0, le=1.0)
    observed_value: Optional[str] = None
    expected_value: Optional[str] = None


class AnomalyResult(BaseModel):
    event_id: str
    entity_id: str

    anomaly_score: float = Field(ge=0.0, le=1.0)
    statistical_score: float = Field(ge=0.0, le=1.0)
    isolation_forest_score: float = Field(ge=0.0, le=1.0)

    anomaly_level: AnomalyLevel
    is_anomalous: bool

    reasons: List[AnomalyReason] = Field(default_factory=list)
    feature_vector: BehaviourFeatureVector

    model_version: str = "ueba-iforest-v1"
    analysed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class UEBATrainingSummary(BaseModel):
    trained: bool
    event_count: int
    entity_count: int
    feature_count: int
    contamination: float
    model_version: str
    model_path: Optional[str] = None
    profile_count: int
    metrics: Dict[str, float] = Field(default_factory=dict)