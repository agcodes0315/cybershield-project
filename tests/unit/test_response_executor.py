from __future__ import annotations

import pytest

from app.response.approval import (
    ApprovalEngine,
)
from app.response.executor import (
    SafeResponseExecutor,
)
from app.response.schemas import (
    ApprovalDecision,
    ApprovalMode,
    ApprovalStatus,
    ExecutionStatus,
    ResponseActionType,
    ResponseExecution,
    ResponseRiskLevel,
    ResponseStepExecution,
    ResponseTarget,
)


def build_execution(
    approval_mode: ApprovalMode,
    action_type: ResponseActionType,
) -> tuple[
    ApprovalEngine,
    ResponseExecution,
]:
    engine = ApprovalEngine()

    step = ResponseStepExecution(
        execution_step_id="STEP-001",
        step_number=1,
        action_id="ACT-TEST",
        action_type=action_type,
        status=ExecutionStatus.PROPOSED,
        approval_mode=approval_mode,
        approval_status=ApprovalStatus.PENDING,
        required_approval_count=0,
        risk_level=ResponseRiskLevel.HIGH,
        target_ids=["DEV-018"],
    )

    execution = ResponseExecution(
        execution_id="EXEC-001",
        incident_id="INC-001",
        playbook_id="PB-TEST",
        status=ExecutionStatus.PROPOSED,
        requested_by="analyst.requester",
        dry_run=True,
        targets=[
            ResponseTarget(
                target_id="DEV-018",
                target_type="workstation",
            )
        ],
        steps=[step],
    )

    return (
        engine,
        engine.register_execution(
            execution
        ),
    )


def test_automatic_step_executes() -> None:
    engine, execution = build_execution(
        ApprovalMode.AUTOMATIC,
        ResponseActionType.SNAPSHOT_ASSET,
    )

    executor = SafeResponseExecutor(engine)

    result = executor.execute(execution)

    assert result.status == (
        ExecutionStatus.COMPLETED
    )

    assert result.steps[0].status == (
        ExecutionStatus.COMPLETED
    )

    assert (
        result.steps[0].result["executed"]
        is True
    )

    assert (
        result.steps[0].result[
            "simulation_only"
        ]
        is True
    )


def test_unapproved_step_does_not_execute() -> None:
    engine, execution = build_execution(
        ApprovalMode.HUMAN_REQUIRED,
        ResponseActionType.ISOLATE_ENDPOINT,
    )

    executor = SafeResponseExecutor(engine)

    result = executor.execute(execution)

    assert result.status == (
        ExecutionStatus.PENDING_APPROVAL
    )

    assert result.steps[0].status == (
        ExecutionStatus.PENDING_APPROVAL
    )


def test_approved_human_step_executes() -> None:
    engine, execution = build_execution(
        ApprovalMode.HUMAN_REQUIRED,
        ResponseActionType.ISOLATE_ENDPOINT,
    )

    engine.submit_decision(
        ApprovalDecision(
            execution_id="EXEC-001",
            execution_step_id="STEP-001",
            approver_id="analyst.one",
            approved=True,
        )
    )

    executor = SafeResponseExecutor(engine)

    result = executor.execute(execution)

    assert result.status == (
        ExecutionStatus.COMPLETED
    )

    assert result.steps[0].result[
        "network_access"
    ] == "restricted"


def test_rejected_step_never_executes() -> None:
    engine, execution = build_execution(
        ApprovalMode.HUMAN_REQUIRED,
        ResponseActionType.ISOLATE_ENDPOINT,
    )

    engine.submit_decision(
        ApprovalDecision(
            execution_id="EXEC-001",
            execution_step_id="STEP-001",
            approver_id="analyst.one",
            approved=False,
        )
    )

    executor = SafeResponseExecutor(engine)

    result = executor.execute(execution)

    assert result.status == (
        ExecutionStatus.REJECTED
    )

    assert result.steps[0].status == (
        ExecutionStatus.REJECTED
    )


def test_direct_execution_of_unapproved_step_fails() -> None:
    engine, execution = build_execution(
        ApprovalMode.HUMAN_REQUIRED,
        ResponseActionType.ISOLATE_ENDPOINT,
    )

    executor = SafeResponseExecutor(engine)

    with pytest.raises(
        PermissionError,
        match="required approval",
    ):
        executor.execute_step(
            execution.steps[0],
            dry_run=True,
        )


@pytest.mark.parametrize(
    "action_type",
    [
        ResponseActionType.BLOCK_IP,
        ResponseActionType.TERMINATE_SESSION,
        ResponseActionType.NOTIFY_SOC,
        ResponseActionType.PROTECT_BACKUP,
        ResponseActionType.RESTRICT_DATABASE_ACCESS,
    ],
)
def test_supported_actions_execute(
    action_type: ResponseActionType,
) -> None:
    engine, execution = build_execution(
        ApprovalMode.AUTOMATIC,
        action_type,
    )

    executor = SafeResponseExecutor(engine)

    result = executor.execute(execution)

    assert result.status == (
        ExecutionStatus.COMPLETED
    )

    assert (
        result.steps[0].result[
            "action_type"
        ]
        == action_type.value
    )