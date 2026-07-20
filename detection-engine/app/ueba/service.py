from __future__ import annotations

from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterable, List, Mapping

from .baseline import BehaviourBaselineService
from .feature_extractor import extract_features
from .model import IsolationForestBehaviourModel
from .schemas import (
    AnomalyLevel,
    AnomalyResult,
    BehaviourProfile,
    UEBATrainingSummary,
)


DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parents[2]
    / "models"
    / "ueba_isolation_forest.joblib"
)


class UEBAService:
    """
    Hybrid User and Entity Behaviour Analytics service.

    Final score:
    60% Isolation Forest
    40% explainable statistical deviations
    """

    def __init__(
        self,
        contamination: float = 0.05,
        model_path: Path = DEFAULT_MODEL_PATH,
    ) -> None:
        self.baselines = BehaviourBaselineService()

        self.model = IsolationForestBehaviourModel(
            contamination=contamination,
            random_state=42,
        )

        self.model_path = model_path
        self._lock = RLock()

    def train(
        self,
        events: Iterable[Mapping[str, Any]],
        save_model: bool = True,
    ) -> UEBATrainingSummary:
        event_list = list(events)

        normal_events = [
            event
            for event in event_list
            if str(event.get("label", "normal")).lower()
            == "normal"
        ]

        if len(normal_events) < 20:
            raise ValueError(
                "At least 20 normal events are required for UEBA training"
            )

        profiles = self.baselines.fit(normal_events)

        vectors = []

        for event in normal_events:
            entity_id = self._entity_id(event)
            profile = profiles.get(entity_id)

            vectors.append(
                extract_features(
                    event,
                    profile=profile,
                )
            )

        with self._lock:
            self.model.fit(vectors)

            saved_path = None

            if save_model:
                saved_path = str(
                    self.model.save(self.model_path)
                )

        return UEBATrainingSummary(
            trained=True,
            event_count=len(normal_events),
            entity_count=len(profiles),
            feature_count=len(vectors[0].as_list()),
            contamination=self.model.contamination,
            model_version="ueba-iforest-v1",
            model_path=saved_path,
            profile_count=self.baselines.count(),
        )

    def analyse(
        self,
        event: Mapping[str, Any],
    ) -> AnomalyResult:
        if not self.model.is_trained:
            if self.model_path.exists():
                self.model.load(self.model_path)
            else:
                raise RuntimeError(
                    "UEBA must be trained before events can be analysed"
                )

        entity_id = self._entity_id(event)
        profile = self.baselines.get_profile(entity_id)

        if profile is None:
            profile = BehaviourProfile(
                entity_id=entity_id,
            )

        feature_vector = extract_features(
            event,
            profile=profile,
        )

        reasons = self.baselines.explain_deviation(
            event,
            profile,
        )

        statistical_score = min(
            sum(reason.contribution for reason in reasons),
            1.0,
        )

        isolation_score = self.model.score(
            feature_vector
        )

        final_score = min(
            (0.60 * isolation_score)
            + (0.40 * statistical_score),
            1.0,
        )

        final_score = round(final_score, 6)

        return AnomalyResult(
            event_id=str(
                event.get("event_id", "UNKNOWN-EVENT")
            ),
            entity_id=entity_id,
            anomaly_score=final_score,
            statistical_score=round(
                statistical_score,
                6,
            ),
            isolation_forest_score=isolation_score,
            anomaly_level=self._level(final_score),
            is_anomalous=final_score >= 0.60,
            reasons=sorted(
                reasons,
                key=lambda reason: reason.contribution,
                reverse=True,
            ),
            feature_vector=feature_vector,
        )

    def analyse_batch(
        self,
        events: Iterable[Mapping[str, Any]],
    ) -> List[AnomalyResult]:
        return [
            self.analyse(event)
            for event in events
        ]

    def profiles(
        self,
    ) -> Dict[str, BehaviourProfile]:
        return self.baselines.all_profiles()

    @staticmethod
    def _entity_id(
        event: Mapping[str, Any],
    ) -> str:
        return str(
            event.get("user_id")
            or event.get("device_id")
            or "UNKNOWN-ENTITY"
        )

    @staticmethod
    def _level(score: float) -> AnomalyLevel:
        if score >= 0.85:
            return AnomalyLevel.CRITICAL

        if score >= 0.70:
            return AnomalyLevel.HIGH

        if score >= 0.55:
            return AnomalyLevel.MEDIUM

        if score >= 0.35:
            return AnomalyLevel.LOW

        return AnomalyLevel.NORMAL


ueba_service = UEBAService()
