from __future__ import annotations

from threading import RLock
from uuid import uuid4

from .approval import ApprovalEngine
from .executor import SafeResponseExecutor
from .playbooks import PlaybookRegistry
from .schemas import (
    ApprovalDecision,
    ApprovalStatus,
    ExecutionStatus,
    ResponseExecution,
    ResponseExecutionRequest,
    ResponseStepExecution,
)


class ResponseOrchestrationService:
    """
    Coordinates playbook creation, approvals and safe execution.
    """

    def __init__(
        self,
        registry: PlaybookRegistry,
        approval_engine: ApprovalEngine,
    ) -> None:
        self.registry = registry
        self.approval_engine = approval_engine
        self.executor = SafeResponseExecutor(
            approval_engine
        )

        self._executions: dict[
            str,
            ResponseExecution,
        ] = {}

        self._lock = RLock()

    def create_execution(
        self,
        request: ResponseExecutionRequest,
    ) -> ResponseExecution:
        with self._lock:
            playbook = self.registry.require_playbook(
                request.playbook_id
            )

            if not playbook.enabled:
                raise ValueError(
                    f"Playbook is disabled: {playbook.playbook_id}"
                )

            execution_id = (
                f"EXEC-{uuid4().hex[:12].upper()}"
            )

            target_ids = [
                target.target_id
                for target in request.targets
            ]

            steps: list[
                ResponseStepExecution
            ] = []

            for step in playbook.steps:
                execution_step_id = (
                    f"{execution_id}-STEP-"
                    f"{step.step_number:02d}"
                )

                approval_status = (
                    ApprovalStatus.NOT_REQUIRED
                    if step.approval_mode.value
                    == "automatic"
                    else ApprovalStatus.PENDING
                )

                steps.append(
                    ResponseStepExecution(
                        execution_step_id=(
                            execution_step_id
                        ),
                        step_number=step.step_number,
                        action_id=step.action_id,
                        action_type=step.action_type,
                        status=ExecutionStatus.PROPOSED,
                        approval_mode=(
                            step.approval_mode
                        ),
                        approval_status=(
                            approval_status
                        ),
                        required_approval_count=0,
                        risk_level=step.risk_level,
                        target_ids=target_ids,
                        result={
                            "playbook_step_title": (
                                step.title
                            ),
                            "continue_on_failure": (
                                step.continue_on_failure
                            ),
                            "reversible": (
                                step.reversible
                            ),
                            "parameters": (
                                step.parameters
                            ),
                        },
                    )
                )

            execution = ResponseExecution(
                execution_id=execution_id,
                incident_id=request.incident_id,
                playbook_id=request.playbook_id,
                status=ExecutionStatus.PROPOSED,
                requested_by=request.requested_by,
                dry_run=True,
                targets=request.targets,
                steps=steps,
                context={
                    **request.context,
                    "requested_dry_run": (
                        request.dry_run
                    ),
                    "simulation_enforced": True,
                },
                summary=(
                    "Response execution created and "
                    "submitted to approval controls."
                ),
            )

            registered = (
                self.approval_engine
                .register_execution(
                    execution
                )
            )

            self._executions[
                execution_id
            ] = registered

            return registered.model_copy(
                deep=True
            )

    def submit_approval(
        self,
        decision: ApprovalDecision,
    ) -> ResponseExecution:
        with self._lock:
            execution = self.require_execution(
                decision.execution_id
            )

            self.approval_engine.submit_decision(
                decision
            )

            updated = (
                self.approval_engine
                .apply_states_to_execution(
                    execution
                )
            )

            self._executions[
                updated.execution_id
            ] = updated

            return updated.model_copy(
                deep=True
            )

    def execute(
        self,
        execution_id: str,
    ) -> ResponseExecution:
        with self._lock:
            execution = self.require_execution(
                execution_id
            )

            updated = self.executor.execute(
                execution
            )

            self._executions[
                execution_id
            ] = updated

            return updated.model_copy(
                deep=True
            )

    def get_execution(
        self,
        execution_id: str,
    ) -> ResponseExecution | None:
        with self._lock:
            execution = self._executions.get(
                execution_id
            )

            if execution is None:
                return None

            return execution.model_copy(
                deep=True
            )

    def require_execution(
        self,
        execution_id: str,
    ) -> ResponseExecution:
        execution = self.get_execution(
            execution_id
        )

        if execution is None:
            raise KeyError(
                "Response execution not found: "
                f"{execution_id}"
            )

        return execution

    def executions(
        self,
    ) -> list[ResponseExecution]:
        with self._lock:
            return [
                execution.model_copy(
                    deep=True
                )
                for execution in sorted(
                    self._executions.values(),
                    key=lambda item: (
                        item.requested_at
                    ),
                    reverse=True,
                )
            ]

    def reset(self) -> None:
        with self._lock:
            self._executions.clear()
            self.approval_engine.clear()


from .approval import approval_engine
from .playbooks import playbook_registry


response_orchestration_service = (
    ResponseOrchestrationService(
        registry=playbook_registry,
        approval_engine=approval_engine,
    )
)