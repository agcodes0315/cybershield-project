from __future__ import annotations

from uuid import uuid4

from app.attack_graph.service import (
    attack_graph_service,
)
from app.prediction.service import (
    predictive_attack_service,
)
from app.response import (
    ResponseExecutionRequest,
    ResponseTarget,
    playbook_registry,
    response_orchestration_service,
)

from .schemas import (
    PipelineDecision,
    ResiliencePipelineRequest,
    ResiliencePipelineResult,
)


class CyberResiliencePipelineService:
    """
    End-to-end CyberShield decision pipeline.

    This service performs analysis and creates safe, human-gated
    response executions. It never performs live infrastructure
    changes.
    """

    def run(
        self,
        request: ResiliencePipelineRequest,
    ) -> ResiliencePipelineResult:
        pipeline_steps: list[str] = []

        prediction = (
            predictive_attack_service.predict(
                events=request.events,
                horizon=(
                    request.prediction_horizon
                ),
                source_node_id=(
                    request.source_node_id
                ),
            )
        )

        pipeline_steps.append(
            "Mapped observed events to MITRE ATT&CK tactics"
        )
        pipeline_steps.append(
            "Predicted probable next-stage tactics using Viterbi"
        )

        source_node_id = (
            request.source_node_id
            or prediction.metadata.get(
                "source_node_id"
            )
        )

        blast_radius = None
        remediation_candidates = []

        if source_node_id:
            try:
                blast_radius = (
                    attack_graph_service
                    .blast_radius(
                        source_id=source_node_id
                    )
                )

                pipeline_steps.append(
                    "Calculated graph-based compromise blast radius"
                )

                remediation_plan = (
                    attack_graph_service
                    .remediation_plan(
                        source_id=source_node_id,
                        maximum_recommendations=(
                            request
                            .maximum_recommendations
                        ),
                    )
                )

                remediation_candidates = (
                    remediation_plan.candidates
                )

                pipeline_steps.append(
                    "Ranked containment actions by effectiveness"
                )

            except (
                KeyError,
                FileNotFoundError,
                ValueError,
            ):
                blast_radius = None
                remediation_candidates = []

        severity = self._calculate_severity(
            prediction_confidence=(
                prediction.confidence
            ),
            current_tactic=(
                prediction.current_tactic
            ),
            predicted_tactic=(
                prediction
                .most_likely_next_tactic
            ),
            blast_radius_score=(
                blast_radius.blast_radius_score
                if blast_radius
                else 0.0
            ),
            critical_asset_count=(
                blast_radius.critical_node_count
                if blast_radius
                else 0
            ),
        )

        tactic_for_playbook = (
            prediction.current_tactic
            or prediction
            .most_likely_next_tactic
            or "Discovery"
        )

        recommended_playbooks = (
            playbook_registry
            .recommend_playbooks(
                tactic=tactic_for_playbook,
                severity=severity,
            )
        )

        if not recommended_playbooks:
            predicted_tactic = (
                prediction
                .most_likely_next_tactic
            )

            if predicted_tactic:
                recommended_playbooks = (
                    playbook_registry
                    .recommend_playbooks(
                        tactic=predicted_tactic,
                        severity=severity,
                    )
                )

        if not recommended_playbooks:
            recommended_playbooks = (
                playbook_registry
                .recommend_playbooks(
                    tactic="Discovery",
                    severity="medium",
                )
            )

        pipeline_steps.append(
            "Matched incident context to SOAR playbooks"
        )

        selected_playbook = (
            recommended_playbooks[0]
            if recommended_playbooks
            else None
        )

        rationale = [
            (
                "Observed attack stage: "
                f"{prediction.current_tactic}"
            ),
            (
                "Predicted next stage: "
                f"{prediction.most_likely_next_tactic}"
            ),
            (
                "Prediction confidence: "
                f"{prediction.confidence:.4f}"
            ),
        ]

        if blast_radius is not None:
            rationale.extend(
                [
                    (
                        "Reachable assets: "
                        f"{blast_radius.reachable_node_count}"
                    ),
                    (
                        "Critical assets at risk: "
                        f"{blast_radius.critical_node_count}"
                    ),
                    (
                        "Blast-radius score: "
                        f"{blast_radius.blast_radius_score:.4f}"
                    ),
                ]
            )

        decision = PipelineDecision(
            severity=severity,
            recommended_playbook_id=(
                selected_playbook.playbook_id
                if selected_playbook
                else None
            ),
            recommended_playbook_name=(
                selected_playbook.name
                if selected_playbook
                else None
            ),
            rationale=rationale,
            human_approval_required=True,
            simulation_only=True,
        )

        response_execution = None

        if (
            request.auto_create_response
            and selected_playbook is not None
        ):
            targets = (
                request.targets
                or self._build_targets(
                    source_node_id=(
                        source_node_id
                    ),
                    prediction_target_id=(
                        prediction
                        .most_likely_target_asset_id
                    ),
                )
            )

            response_execution = (
                response_orchestration_service
                .create_execution(
                    ResponseExecutionRequest(
                        incident_id=(
                            request.incident_id
                        ),
                        playbook_id=(
                            selected_playbook
                            .playbook_id
                        ),
                        requested_by=(
                            request.requested_by
                        ),
                        targets=targets,
                        context={
                            "pipeline_run": True,
                            "severity": severity,
                            "current_tactic": (
                                prediction
                                .current_tactic
                            ),
                            "predicted_tactic": (
                                prediction
                                .most_likely_next_tactic
                            ),
                            "prediction_confidence": (
                                prediction.confidence
                            ),
                            "source_node_id": (
                                source_node_id
                            ),
                        },
                        dry_run=True,
                    )
                )
            )

            pipeline_steps.append(
                "Created approval-gated SOAR execution"
            )

        explanation = (
            "CyberShield completed predictive analysis, "
            "architecture-aware impact assessment, remediation "
            "ranking, and human-gated response preparation. "
            "No live infrastructure changes were performed."
        )

        return ResiliencePipelineResult(
            pipeline_run_id=(
                f"PIPE-{uuid4().hex[:12].upper()}"
            ),
            incident_id=request.incident_id,
            prediction=prediction,
            blast_radius=blast_radius,
            remediation_candidates=(
                remediation_candidates
            ),
            recommended_playbooks=(
                recommended_playbooks
            ),
            decision=decision,
            response_execution=(
                response_execution
            ),
            pipeline_steps=pipeline_steps,
            explanation=explanation,
        )

    @staticmethod
    def _calculate_severity(
        prediction_confidence: float,
        current_tactic: str | None,
        predicted_tactic: str | None,
        blast_radius_score: float,
        critical_asset_count: int,
    ) -> str:
        severe_tactics = {
            "Credential Access",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        }

        score = (
            0.40 * prediction_confidence
            + 0.35 * blast_radius_score
            + 0.25
            * min(
                critical_asset_count / 3.0,
                1.0,
            )
        )

        if (
            current_tactic in severe_tactics
            or predicted_tactic in severe_tactics
        ):
            score += 0.15

        score = min(score, 1.0)

        if score >= 0.75:
            return "critical"

        if score >= 0.50:
            return "high"

        if score >= 0.25:
            return "medium"

        return "low"

    @staticmethod
    def _build_targets(
        source_node_id: str | None,
        prediction_target_id: str | None,
    ) -> list[ResponseTarget]:
        targets: list[ResponseTarget] = []
        seen: set[str] = set()

        if source_node_id:
            targets.append(
                ResponseTarget(
                    target_id=source_node_id,
                    target_type="source_asset",
                )
            )
            seen.add(source_node_id)

        if (
            prediction_target_id
            and prediction_target_id not in seen
        ):
            targets.append(
                ResponseTarget(
                    target_id=(
                        prediction_target_id
                    ),
                    target_type=(
                        "predicted_target_asset"
                    ),
                )
            )

        if not targets:
            targets.append(
                ResponseTarget(
                    target_id="UNKNOWN-TARGET",
                    target_type="unknown",
                )
            )

        return targets


cyber_resilience_pipeline_service = (
    CyberResiliencePipelineService()
)