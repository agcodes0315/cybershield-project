from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ResponseActionType(str, Enum):
    ISOLATE_ENDPOINT = "isolate_endpoint"
    REVOKE_CREDENTIALS = "revoke_credentials"
    BLOCK_IP = "block_ip"
    DISABLE_CONNECTION = "disable_connection"
    TERMINATE_SESSION = "terminate_session"
    SNAPSHOT_ASSET = "snapshot_asset"
    ENABLE_ENHANCED_MONITORING = "enable_enhanced_monitoring"
    RESTRICT_DATABASE_ACCESS = "restrict_database_access"
    PROTECT_BACKUP = "protect_backup"
    NOTIFY_SOC = "notify_soc"


class ApprovalMode(str, Enum):
    AUTOMATIC = "automatic"
    HUMAN_REQUIRED = "human_required"
    DUAL_APPROVAL_REQUIRED = "dual_approval_required"


class ResponseRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionStatus(str, Enum):
    PROPOSED = "proposed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class PlaybookCategory(str, Enum):
    IDENTITY = "identity"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    DATA_PROTECTION = "data_protection"
    MONITORING = "monitoring"
    COORDINATION = "coordination"


class ResponseTarget(BaseModel):
    target_id: str = Field(min_length=1)
    target_type: str = Field(min_length=1)

    display_name: str | None = None
    ip_address: str | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class ResponseActionDefinition(BaseModel):
    action_id: str = Field(min_length=1)
    name: str = Field(min_length=1)

    action_type: ResponseActionType
    category: PlaybookCategory

    description: str

    default_approval_mode: ApprovalMode
    risk_level: ResponseRiskLevel

    reversible: bool = False
    estimated_execution_seconds: int = Field(
        default=30,
        ge=0,
    )

    required_parameters: list[str] = Field(
        default_factory=list
    )

    expected_effects: list[str] = Field(
        default_factory=list
    )

    rollback_action_type: ResponseActionType | None = None

    enabled: bool = True

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class ResponsePlaybookStep(BaseModel):
    step_number: int = Field(ge=1)

    action_id: str
    action_type: ResponseActionType

    title: str
    description: str

    approval_mode: ApprovalMode
    risk_level: ResponseRiskLevel

    parameters: dict[str, Any] = Field(
        default_factory=dict
    )

    continue_on_failure: bool = False
    reversible: bool = False


class ResponsePlaybook(BaseModel):
    playbook_id: str = Field(min_length=1)
    name: str = Field(min_length=1)

    description: str
    version: str = "1.0.0"

    supported_tactics: list[str] = Field(
        default_factory=list
    )

    supported_severities: list[str] = Field(
        default_factory=list
    )

    steps: list[ResponsePlaybookStep] = Field(
        min_length=1
    )

    enabled: bool = True

    tags: list[str] = Field(
        default_factory=list
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class ResponseExecutionRequest(BaseModel):
    incident_id: str = Field(min_length=1)
    playbook_id: str = Field(min_length=1)

    requested_by: str = Field(min_length=1)

    targets: list[ResponseTarget] = Field(
        min_length=1
    )

    context: dict[str, Any] = Field(
        default_factory=dict
    )

    dry_run: bool = True


class ResponseStepExecution(BaseModel):
    execution_step_id: str

    step_number: int = Field(ge=1)

    action_id: str
    action_type: ResponseActionType

    status: ExecutionStatus

    approval_mode: ApprovalMode
    risk_level: ResponseRiskLevel

    started_at: datetime | None = None
    completed_at: datetime | None = None

    approved_by: list[str] = Field(
        default_factory=list
    )

    target_ids: list[str] = Field(
        default_factory=list
    )

    result: dict[str, Any] = Field(
        default_factory=dict
    )

    error_message: str | None = None


class ResponseExecution(BaseModel):
    execution_id: str
    incident_id: str
    playbook_id: str

    status: ExecutionStatus

    requested_by: str

    requested_at: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )

    started_at: datetime | None = None
    completed_at: datetime | None = None

    dry_run: bool = True

    targets: list[ResponseTarget] = Field(
        default_factory=list
    )

    steps: list[ResponseStepExecution] = Field(
        default_factory=list
    )

    context: dict[str, Any] = Field(
        default_factory=dict
    )

    summary: str = ""


class ApprovalDecision(BaseModel):
    execution_id: str
    execution_step_id: str

    approver_id: str = Field(min_length=1)

    approved: bool

    reason: str | None = None

    decided_at: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )


class PlaybookRegistrySummary(BaseModel):
    action_count: int = Field(ge=0)
    playbook_count: int = Field(ge=0)

    enabled_action_count: int = Field(ge=0)
    enabled_playbook_count: int = Field(ge=0)

    action_types: list[ResponseActionType] = Field(
        default_factory=list
    )

    playbook_ids: list[str] = Field(
        default_factory=list
    )