from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class AssetType(str, Enum):
    USER_DEVICE = "user_device"
    IDENTITY_PROVIDER = "identity_provider"
    APPLICATION_SERVER = "application_server"
    DATABASE = "database"
    FILE_SERVER = "file_server"
    BACKUP_SERVER = "backup_server"
    NETWORK_DEVICE = "network_device"
    SECURITY_TOOL = "security_tool"
    OT_DEVICE = "ot_device"
    CLOUD_RESOURCE = "cloud_resource"


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


CRITICALITY_SCORES: Dict[AssetCriticality, float] = {
    AssetCriticality.LOW: 0.25,
    AssetCriticality.MEDIUM: 0.50,
    AssetCriticality.HIGH: 0.75,
    AssetCriticality.CRITICAL: 1.00,
}


class Asset(BaseModel):
    asset_id: str = Field(min_length=3, max_length=100)
    name: str = Field(min_length=2, max_length=150)
    asset_type: AssetType
    criticality: AssetCriticality

    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    network_zone: str = "internal"

    owner_department: Optional[str] = None
    data_classification: Optional[str] = None

    internet_exposed: bool = False
    contains_sensitive_data: bool = False
    active: bool = True

    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, str] = Field(default_factory=dict)

    @property
    def criticality_score(self) -> float:
        return CRITICALITY_SCORES[self.criticality]
