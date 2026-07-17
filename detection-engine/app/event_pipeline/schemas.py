from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    AUTHENTICATION = "authentication"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    EMAIL = "email"
    URL_SCANNER = "url_scanner"
    VULNERABILITY = "vulnerability"
    THREAT_INTELLIGENCE = "threat_intelligence"
    CLOUD = "cloud"
    OT = "ot"
    SIMULATOR = "simulator"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventStatus(str, Enum):
    NEW = "new"
    ANALYSED = "analysed"
    CORRELATED = "correlated"
    DISMISSED = "dismissed"


class Actor(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None
    device_id: Optional[str] = None
    source_ip: Optional[str] = None
    department: Optional[str] = None


class Target(BaseModel):
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    resource: Optional[str] = None


class MitreMapping(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class SecurityEvent(BaseModel):
    event_id: str = Field(
        default_factory=lambda: f"EVT-{uuid4().hex[:12].upper()}"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    source_type: SourceType
    event_type: str = Field(min_length=2, max_length=100)

    severity: Severity = Severity.INFO
    status: EventStatus = EventStatus.NEW

    actor: Actor = Field(default_factory=Actor)
    target: Target = Field(default_factory=Target)

    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    attributes: Dict[str, Any] = Field(default_factory=dict)
    indicators: List[str] = Field(default_factory=list)
    mitre_mappings: List[MitreMapping] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    organisation_id: str = "ORG-DEMO-001"
    correlation_id: Optional[str] = None
    raw_event_reference: Optional[str] = None

    def entity_keys(self) -> List[str]:
        """
        Return stable keys used by the correlation engine.

        Hash-map indexes will use these keys for near O(1) event lookup.
        """
        keys: List[str] = []

        if self.actor.user_id:
            keys.append(f"user:{self.actor.user_id}")

        if self.actor.device_id:
            keys.append(f"device:{self.actor.device_id}")

        if self.actor.source_ip:
            keys.append(f"source_ip:{self.actor.source_ip}")

        if self.target.asset_id:
            keys.append(f"asset:{self.target.asset_id}")

        if self.target.destination_ip:
            keys.append(f"destination_ip:{self.target.destination_ip}")

        return keys
