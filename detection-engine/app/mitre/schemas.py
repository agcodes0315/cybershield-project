from __future__ import annotations

from enum import Enum
from typing import List

from pydantic import BaseModel, Field


class MitreTactic(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class MitreTechnique(BaseModel):
    tactic: MitreTactic
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    description: str
    recommended_mitigations: List[str] = Field(default_factory=list)


class MitreMappingResult(BaseModel):
    event_id: str
    event_type: str
    matched: bool
    confidence: float = Field(ge=0.0, le=1.0)
    techniques: List[MitreTechnique] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)