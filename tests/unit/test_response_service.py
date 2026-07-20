from __future__ import annotations

from app.response.approval import (
    ApprovalEngine,
)
from app.response.playbooks import (
    PlaybookRegistry,
    build_default_actions,
    build_default_playbooks,
)
from app.response.schemas import (
    ApprovalDecision,
    ExecutionStatus,
    ResponseExecutionRequest,
    ResponseTarget,
)
from app.response.service import (
    ResponseOrchestrationService,
)


def build_service() -> (
    ResponseOrchestrationService
):
    registry = PlaybookRegistry()

    for action in build_default_actions():
        registry.register_action(action)

    for playbook in build_default_playbooks():
        registry.register_playbook(
            playbook
        )

    return ResponseOrchestrationService(
        registry=registry,
        approval_engine=ApprovalEngine(),
    )


def create_endpoint_request() -> (
    ResponseExecutionRequest
):
    return ResponseExecutionRequest(
        incident_id="INC-001",
        playbook_id=(
            "PB-COMPROMISED-ENDPOINT"
        ),
        requested_by="soc.requester",
        targets=[
            ResponseTarget(
                target_id="DEV-018",
                target_type="workstation",
            ),
            ResponseTarget(
                target_id="USR-104",
                target_type="user",
            ),
        ],
        context={
            "tactic": "Credential Access",
            "severity": "critical",
        },
        dry_run=True,
    )


def test_create_execution_from_playbook() -> None:
    service = build_service()

    execution = service.create_execution(
        create_endpoint_request()
    )

    assert execution.execution_id.startswith(
        "EXEC-"
    )

    assert execution.status == (
        ExecutionStatus.PENDING_APPROVAL
    )

    assert len(execution.steps) == 4

    assert execution.dry_run is True

    assert (
        execution.context[
            "simulation_enforced"
        ]
        is True
    )


def test_automatic_steps_execute_while_gated_steps_wait() -> None:
    service = build_service()

    execution = service.create_execution(
        create_endpoint_request()
    )

    result = service.execute(
        execution.execution_id
    )

    assert result.status == (
        ExecutionStatus.PENDING_APPROVAL
    )

    assert result.steps[0].status == (
        ExecutionStatus.COMPLETED
    )

    assert result.steps[1].status == (
        ExecutionStatus.PENDING_APPROVAL
    )


def test_approvals_allow_execution_to_finish() -> None:
    service = build_service()

    execution = service.create_execution(
        create_endpoint_request()
    )

    human_steps = [
        step
        for step in execution.steps
        if step.required_approval_count > 0
    ]

    for step in human_steps:
        service.submit_approval(
            ApprovalDecision(
                execution_id=(
                    execution.execution_id
                ),
                execution_step_id=(
                    step.execution_step_id
                ),
                approver_id=(
                    f"analyst-{step.step_number}"
                ),
                approved=True,
            )
        )

    result = service.execute(
        execution.execution_id
    )

    assert result.status == (
        ExecutionStatus.COMPLETED
    )

    assert all(
        step.status
        == ExecutionStatus.COMPLETED
        for step in result.steps
    )


def test_rejection_blocks_execution() -> None:
    service = build_service()

    execution = service.create_execution(
        create_endpoint_request()
    )

    human_step = next(
        step
        for step in execution.steps
        if step.required_approval_count > 0
    )

    service.submit_approval(
        ApprovalDecision(
            execution_id=(
                execution.execution_id
            ),
            execution_step_id=(
                human_step.execution_step_id
            ),
            approver_id="analyst.rejector",
            approved=False,
        )
    )

    result = service.execute(
        execution.execution_id
    )

    assert result.status == (
        ExecutionStatus.REJECTED
    )


def test_execution_can_be_retrieved() -> None:
    service = build_service()

    execution = service.create_execution(
        create_endpoint_request()
    )

    stored = service.require_execution(
        execution.execution_id
    )

    assert stored.execution_id == (
        execution.execution_id
    )

    assert len(service.executions()) == 1


def test_reset_clears_executions() -> None:
    service = build_service()

    service.create_execution(
        create_endpoint_request()
    )

    assert service.executions()

    service.reset()

    assert service.executions() == []