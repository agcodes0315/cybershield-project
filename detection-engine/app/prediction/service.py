from __future__ import annotations

from uuid import uuid4
from typing import Any, Iterable, Mapping

from app.attack_graph.pathfinder import AttackPathfinder
from app.attack_graph.schemas import (
    AssetCriticality,
    GraphNodeType,
    PathAlgorithm,
)
from app.attack_graph.service import attack_graph_service
from app.mitre.service import MitreMappingService

from .schemas import (
    AttackPredictionResult,
    PredictedAttackStage,
    PredictionEvaluation,
    PredictionMethod,
)
from .transitions import AttackTransitionModel
from .viterbi import ViterbiAttackPredictor


TACTIC_TARGET_TYPES: dict[
    str,
    set[GraphNodeType],
] = {
    "Initial Access": {
        GraphNodeType.USER,
        GraphNodeType.WORKSTATION,
        GraphNodeType.APPLICATION,
    },
    "Execution": {
        GraphNodeType.WORKSTATION,
        GraphNodeType.SERVER,
        GraphNodeType.APPLICATION,
    },
    "Persistence": {
        GraphNodeType.WORKSTATION,
        GraphNodeType.SERVER,
        GraphNodeType.APPLICATION,
    },
    "Privilege Escalation": {
        GraphNodeType.WORKSTATION,
        GraphNodeType.SERVER,
        GraphNodeType.IDENTITY_PROVIDER,
    },
    "Defense Evasion": {
        GraphNodeType.WORKSTATION,
        GraphNodeType.SERVER,
        GraphNodeType.SECURITY_SYSTEM,
    },
    "Credential Access": {
        GraphNodeType.WORKSTATION,
        GraphNodeType.IDENTITY_PROVIDER,
        GraphNodeType.SERVER,
    },
    "Discovery": {
        GraphNodeType.SERVER,
        GraphNodeType.APPLICATION,
        GraphNodeType.NETWORK_DEVICE,
        GraphNodeType.IDENTITY_PROVIDER,
    },
    "Lateral Movement": {
        GraphNodeType.SERVER,
        GraphNodeType.APPLICATION,
        GraphNodeType.IDENTITY_PROVIDER,
    },
    "Collection": {
        GraphNodeType.DATABASE,
        GraphNodeType.STORAGE,
        GraphNodeType.BACKUP,
    },
    "Command and Control": {
        GraphNodeType.SERVER,
        GraphNodeType.WORKSTATION,
        GraphNodeType.APPLICATION,
    },
    "Exfiltration": {
        GraphNodeType.DATABASE,
        GraphNodeType.STORAGE,
        GraphNodeType.BACKUP,
    },
    "Impact": {
        GraphNodeType.DATABASE,
        GraphNodeType.STORAGE,
        GraphNodeType.BACKUP,
        GraphNodeType.APPLICATION,
        GraphNodeType.IDENTITY_PROVIDER,
    },
}


DEFENSIVE_ACTIONS: dict[str, list[str]] = {
    "Execution": [
        "Block encoded PowerShell and suspicious child processes",
        "Isolate the affected endpoint after analyst approval",
        "Collect process-tree and script-block evidence",
    ],
    "Credential Access": [
        "Protect LSASS and credential stores",
        "Revoke exposed credentials and active sessions",
        "Require phishing-resistant MFA",
    ],
    "Discovery": [
        "Restrict east-west network scanning",
        "Enable internal service-discovery alerts",
        "Segment sensitive application zones",
    ],
    "Lateral Movement": [
        "Block unauthorised RDP, SMB, and SSH access",
        "Disable compromised service accounts",
        "Isolate the current source endpoint",
    ],
    "Collection": [
        "Restrict bulk access to sensitive repositories",
        "Enable database activity monitoring",
        "Apply temporary least-privilege controls",
    ],
    "Command and Control": [
        "Block suspicious outbound destinations",
        "Inspect encrypted beaconing behaviour",
        "Preserve DNS and proxy evidence",
    ],
    "Exfiltration": [
        "Apply egress filtering and transfer-rate limits",
        "Block previously unseen external destinations",
        "Snapshot affected database and storage systems",
    ],
    "Impact": [
        "Protect backups from modification",
        "Activate incident continuity procedures",
        "Require human approval for high-blast-radius containment",
    ],
}


class PredictiveAttackService:
    def __init__(self) -> None:
        self.mitre = MitreMappingService()
        self.transitions = AttackTransitionModel()
        self.viterbi = ViterbiAttackPredictor(
            self.transitions
        )

    def predict(
        self,
        events: Iterable[Mapping[str, Any]],
        horizon: int = 3,
        source_node_id: str | None = None,
    ) -> AttackPredictionResult:
        event_list = sorted(
            list(events),
            key=lambda event: str(
                event.get("timestamp", "")
            ),
        )

        if not event_list:
            raise ValueError(
                "At least one observed event is required"
            )

        if horizon <= 0 or horizon > 10:
            raise ValueError(
                "horizon must be between 1 and 10"
            )

        observed_tactics: list[str] = []
        observed_techniques: list[str] = []

        for event in event_list:
            mapping = self.mitre.map_event(event)

            for technique in mapping.techniques:
                tactic = technique.tactic.value

                if (
                    not observed_tactics
                    or observed_tactics[-1] != tactic
                ):
                    observed_tactics.append(tactic)

                if (
                    technique.technique_id
                    not in observed_techniques
                ):
                    observed_techniques.append(
                        technique.technique_id
                    )

        if not observed_tactics:
            raise ValueError(
                "No MITRE ATT&CK tactics could be mapped "
                "from the observed events"
            )

        current_tactic = observed_tactics[-1]

        predicted_path = self.viterbi.predict(
            current_tactic=current_tactic,
            horizon=horizon,
        )

        entity_id = str(
            event_list[-1].get("user_id")
            or event_list[-1].get("device_id")
            or "UNKNOWN-ENTITY"
        )

        resolved_source_id = (
            source_node_id
            or self._resolve_source_node(event_list)
        )

        cumulative_probability = 1.0
        predicted_stages: list[
            PredictedAttackStage
        ] = []

        for index, tactic in enumerate(
            predicted_path.tactics,
            start=1,
        ):
            stage_probability = (
                predicted_path.probabilities[
                    index - 1
                ]
            )

            cumulative_probability *= (
                stage_probability
            )

            (
                target_id,
                target_name,
            ) = self._predict_target(
                source_node_id=resolved_source_id,
                tactic=tactic,
            )

            predicted_stages.append(
                PredictedAttackStage(
                    sequence_number=index,
                    tactic=tactic,
                    probability=round(
                        stage_probability,
                        6,
                    ),
                    cumulative_probability=round(
                        cumulative_probability,
                        6,
                    ),
                    likely_target_asset_id=target_id,
                    likely_target_asset_name=target_name,
                    recommended_defensive_actions=(
                        DEFENSIVE_ACTIONS.get(
                            tactic,
                            [
                                "Escalate for SOC analyst review",
                                "Preserve relevant telemetry",
                            ],
                        )
                    ),
                    explanation=(
                        f"{tactic} is predicted from the "
                        f"observed {current_tactic} stage using "
                        f"MITRE tactic transition probabilities."
                    ),
                )
            )

        top_stage = (
            predicted_stages[0]
            if predicted_stages
            else None
        )

        evidence_factor = min(
            len(observed_tactics) / 6.0,
            1.0,
        )

        path_probability = (
            top_stage.probability
            if top_stage
            else 0.0
        )

        confidence = min(
            0.55 * path_probability
            + 0.30 * evidence_factor
            + 0.15,
            0.99,
        )

        organisation_id = str(
            event_list[0].get(
                "organisation_id",
                "ORG-DEMO-001",
            )
        )

        explanation = (
            f"CyberShield observed {len(observed_tactics)} "
            f"ordered ATT&CK tactics ending at "
            f"{current_tactic}. Dynamic programming predicted "
            f"{len(predicted_stages)} probable next stages."
        )

        return AttackPredictionResult(
            prediction_id=(
                f"PRED-{uuid4().hex[:12].upper()}"
            ),
            organisation_id=organisation_id,
            primary_entity_id=entity_id,
            observed_event_count=len(event_list),
            observed_tactics=observed_tactics,
            observed_techniques=observed_techniques,
            current_tactic=current_tactic,
            predicted_stages=predicted_stages,
            most_likely_next_tactic=(
                top_stage.tactic
                if top_stage
                else None
            ),
            most_likely_target_asset_id=(
                top_stage.likely_target_asset_id
                if top_stage
                else None
            ),
            most_likely_target_asset_name=(
                top_stage.likely_target_asset_name
                if top_stage
                else None
            ),
            confidence=round(confidence, 6),
            method=PredictionMethod.VITERBI,
            explanation=explanation,
            metadata={
                "prediction_horizon": horizon,
                "source_node_id": resolved_source_id,
                "path_probability": (
                    predicted_path
                    .cumulative_probability
                ),
                "algorithm_complexity": (
                    "O(H × V × E)"
                ),
            },
        )

    def evaluate_sequence(
        self,
        events: Iterable[Mapping[str, Any]],
    ) -> PredictionEvaluation:
        event_list = sorted(
            list(events),
            key=lambda event: str(
                event.get("timestamp", "")
            ),
        )

        mapped: list[
            tuple[Mapping[str, Any], str]
        ] = []

        for event in event_list:
            mapping = self.mitre.map_event(event)

            if not mapping.techniques:
                continue

            tactic = (
                mapping.techniques[0]
                .tactic.value
            )

            mapped.append((event, tactic))

        if len(mapped) < 2:
            raise ValueError(
                "At least two mapped attack stages are "
                "required for evaluation"
            )

        evaluation_rows: list[dict[str, Any]] = []
        correct_predictions = 0
        confidences: list[float] = []

        for index in range(1, len(mapped)):
            prefix_events = [
                item[0]
                for item in mapped[:index]
            ]

            actual_tactic = mapped[index][1]

            prediction = self.predict(
                prefix_events,
                horizon=1,
            )

            predicted_tactic = (
                prediction.most_likely_next_tactic
            )

            correct = (
                predicted_tactic == actual_tactic
            )

            if correct:
                correct_predictions += 1

            confidences.append(
                prediction.confidence
            )

            evaluation_rows.append(
                {
                    "prefix_length": index,
                    "current_tactic": (
                        prediction.current_tactic
                    ),
                    "predicted_tactic": (
                        predicted_tactic
                    ),
                    "actual_tactic": actual_tactic,
                    "correct": correct,
                    "confidence": (
                        prediction.confidence
                    ),
                }
            )

        evaluated_prefixes = len(
            evaluation_rows
        )

        return PredictionEvaluation(
            evaluated_prefixes=evaluated_prefixes,
            correct_predictions=correct_predictions,
            top_one_accuracy=round(
                correct_predictions
                / evaluated_prefixes,
                6,
            ),
            mean_confidence=round(
                sum(confidences)
                / len(confidences),
                6,
            ),
            predictions=evaluation_rows,
        )

    @staticmethod
    def _resolve_source_node(
        events: list[Mapping[str, Any]],
    ) -> str | None:
        candidates = [
            str(events[-1].get("asset_id") or ""),
            str(events[-1].get("device_id") or ""),
            str(events[-1].get("user_id") or ""),
        ]

        try:
            attack_graph_service.ensure_loaded()
        except (FileNotFoundError, ValueError):
            return None

        for candidate in candidates:
            if (
                candidate
                and attack_graph_service.graph.contains_node(
                    candidate
                )
            ):
                return candidate

        return None

    @staticmethod
    def _criticality_weight(
        criticality: AssetCriticality,
    ) -> float:
        return {
            AssetCriticality.LOW: 0.20,
            AssetCriticality.MEDIUM: 0.40,
            AssetCriticality.HIGH: 0.70,
            AssetCriticality.CRITICAL: 1.00,
        }[criticality]

    def _predict_target(
        self,
        source_node_id: str | None,
        tactic: str,
    ) -> tuple[str | None, str | None]:
        try:
            attack_graph_service.ensure_loaded()
        except (FileNotFoundError, ValueError):
            return None, None

        graph = attack_graph_service.graph

        target_types = TACTIC_TARGET_TYPES.get(
            tactic,
            set(),
        )

        candidates = [
            node
            for node in graph.nodes()
            if node.node_type in target_types
            and node.node_id != source_node_id
        ]

        if not candidates:
            return None, None

        if (
            source_node_id
            and graph.contains_node(source_node_id)
        ):
            pathfinder = AttackPathfinder(graph)

            ranked: list[
                tuple[
                    float,
                    str,
                    str,
                ]
            ] = []

            for node in candidates:
                path = (
                    pathfinder.lowest_resistance_path(
                        source_node_id,
                        node.node_id,
                    )
                )

                if not path.found:
                    continue

                traversal_ease = (
                    1.0 / (1.0 + path.total_cost)
                )

                target_score = (
                    0.40
                    * self._criticality_weight(
                        node.criticality
                    )
                    + 0.40
                    * node.business_impact_score
                    + 0.20
                    * traversal_ease
                )

                ranked.append(
                    (
                        target_score,
                        node.node_id,
                        node.name,
                    )
                )

            if ranked:
                _, node_id, node_name = max(
                    ranked,
                    key=lambda item: (
                        item[0],
                        item[1],
                    ),
                )

                return node_id, node_name

        best_node = max(
            candidates,
            key=lambda node: (
                self._criticality_weight(
                    node.criticality
                ),
                node.business_impact_score,
                node.risk_score,
                node.node_id,
            ),
        )

        return (
            best_node.node_id,
            best_node.name,
        )


predictive_attack_service = PredictiveAttackService()