from __future__ import annotations

from threading import RLock
from uuid import uuid4

from .approval import (
    ApprovalEngine,
    approval_engine,
)
from .audit import (
    AuditActorType,
    AuditEventType,
    TamperEvidentAuditLedger,
    audit_ledger,
)
from .executor import SafeResponseExecutor
from .playbooks import (
    PlaybookRegistry,
    playbook_registry,
)
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
    Coordinates playbook creation, approvals, safe execution,
    and tamper-evident audit logging.

    A private audit ledger is created automatically when no ledger
    is supplied. This keeps isolated service instances and unit
    tests independent while allowing the production singleton to
    use the shared application audit ledger.
    """

    def __init__(
        self,
        registry: PlaybookRegistry,
        approval_engine: ApprovalEngine,
        audit_ledger: TamperEvidentAuditLedger | None = None,
    ) -> None:
        self.registry = registry
        self.approval_engine = approval_engine

        self.audit_ledger = (
            audit_ledger
            if audit_ledger is not None
            else TamperEvidentAuditLedger()
        )

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
                    "Playbook is disabled: "
                    f"{playbook.playbook_id}"
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
                .register_execution(execution)
            )

            self._executions[
                execution_id
            ] = registered

            self.audit_ledger.append(
                event_type=(
                    AuditEventType.EXECUTION_CREATED
                ),
                execution_id=execution_id,
                incident_id=request.incident_id,
                actor_id=request.requested_by,
                actor_type=AuditActorType.USER,
                payload={
                    "playbook_id": (
                        request.playbook_id
                    ),
                    "target_ids": target_ids,
                    "dry_run": True,
                    "status": (
                        registered.status.value
                    ),
                },
            )

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

            state = (
                self.approval_engine
                .submit_decision(decision)
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

            event_type = (
                AuditEventType.APPROVAL_GRANTED
                if decision.approved
                else AuditEventType.APPROVAL_REJECTED
            )

            self.audit_ledger.append(
                event_type=event_type,
                execution_id=decision.execution_id,
                incident_id=execution.incident_id,
                execution_step_id=(
                    decision.execution_step_id
                ),
                actor_id=decision.approver_id,
                actor_type=AuditActorType.USER,
                payload={
                    "approved": decision.approved,
                    "reason": decision.reason,
                    "approval_status": (
                        state.status.value
                    ),
                    "approval_count": (
                        state.approval_count
                    ),
                    "remaining_approval_count": (
                        state
                        .remaining_approval_count
                    ),
                },
                timestamp=decision.decided_at,
            )

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

            self.audit_ledger.append(
                event_type=(
                    AuditEventType.EXECUTION_STARTED
                ),
                execution_id=execution_id,
                incident_id=execution.incident_id,
                actor_id=(
                    "response-orchestration-service"
                ),
                actor_type=AuditActorType.SERVICE,
                payload={
                    "status_before": (
                        execution.status.value
                    ),
                    "dry_run": execution.dry_run,
                },
            )

            previous_steps = {
                step.execution_step_id: step
                for step in execution.steps
            }

            updated = self.executor.execute(
                execution
            )

            for step in updated.steps:
                previous = previous_steps.get(
                    step.execution_step_id
                )

                if (
                    previous is not None
                    and previous.status
                    == step.status
                    and step.status
                    != ExecutionStatus.COMPLETED
                ):
                    continue

                if (
                    step.status
                    == ExecutionStatus.COMPLETED
                ):
                    step_event_type = (
                        AuditEventType.STEP_COMPLETED
                    )
                elif (
                    step.status
                    == ExecutionStatus.FAILED
                ):
                    step_event_type = (
                        AuditEventType.STEP_FAILED
                    )
                else:
                    continue

                self.audit_ledger.append(
                    event_type=step_event_type,
                    execution_id=execution_id,
                    incident_id=(
                        updated.incident_id
                    ),
                    execution_step_id=(
                        step.execution_step_id
                    ),
                    actor_id=(
                        "safe-response-executor"
                    ),
                    actor_type=(
                        AuditActorType.SERVICE
                    ),
                    payload={
                        "step_number": (
                            step.step_number
                        ),
                        "action_id": (
                            step.action_id
                        ),
                        "action_type": (
                            step.action_type.value
                        ),
                        "status": (
                            step.status.value
                        ),
                        "target_ids": (
                            step.target_ids
                        ),
                        "result": step.result,
                        "error_message": (
                            step.error_message
                        ),
                    },
                )

            final_event_type = self._final_event_type(
                updated.status
            )

            if final_event_type is not None:
                self.audit_ledger.append(
                    event_type=final_event_type,
                    execution_id=execution_id,
                    incident_id=(
                        updated.incident_id
                    ),
                    actor_id=(
                        "response-orchestration-service"
                    ),
                    actor_type=(
                        AuditActorType.SERVICE
                    ),
                    payload={
                        "status": (
                            updated.status.value
                        ),
                        "summary": (
                            updated.summary
                        ),
                    },
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

    def reset(
        self,
        clear_audit: bool = True,
    ) -> None:
        with self._lock:
            self._executions.clear()
            self.approval_engine.clear()

            if clear_audit:
                self.audit_ledger.clear()

    @staticmethod
    def _final_event_type(
        status: ExecutionStatus,
    ) -> AuditEventType | None:
        mapping = {
            ExecutionStatus.COMPLETED: (
                AuditEventType
                .EXECUTION_COMPLETED
            ),
            ExecutionStatus.FAILED: (
                AuditEventType.EXECUTION_FAILED
            ),
            ExecutionStatus.REJECTED: (
                AuditEventType
                .EXECUTION_REJECTED
            ),
            ExecutionStatus.CANCELLED: (
                AuditEventType
                .EXECUTION_CANCELLED
            ),
        }

        return mapping.get(status)


response_orchestration_service = (
    ResponseOrchestrationService(
        registry=playbook_registry,
        approval_engine=approval_engine,
        audit_ledger=audit_ledger,
    )
)