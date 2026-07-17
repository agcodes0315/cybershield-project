from __future__ import annotations

import math
from pathlib import Path
from typing import Iterable, List

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .schemas import BehaviourFeatureVector


class IsolationForestBehaviourModel:
    def __init__(
        self,
        contamination: float = 0.05,
        random_state: int = 42,
    ) -> None:
        if not 0.001 <= contamination <= 0.5:
            raise ValueError(
                "contamination must be between 0.001 and 0.5"
            )

        self.contamination = contamination
        self.random_state = random_state

        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )

        self.is_trained = False
        self._training_median = 0.0
        self._training_scale = 1.0

    def fit(
        self,
        feature_vectors: Iterable[BehaviourFeatureVector],
    ) -> None:
        matrix = self._matrix(feature_vectors)

        if len(matrix) < 20:
            raise ValueError(
                "At least 20 normal events are required to train UEBA"
            )

        self.model.fit(matrix)

        raw_scores = -self.model.decision_function(matrix)

        self._training_median = float(np.median(raw_scores))

        mad = float(
            np.median(
                np.abs(raw_scores - self._training_median)
            )
        )

        self._training_scale = max(mad * 1.4826, 0.01)
        self.is_trained = True

    def score(
        self,
        feature_vector: BehaviourFeatureVector,
    ) -> float:
        if not self.is_trained:
            raise RuntimeError("UEBA model has not been trained")

        matrix = np.asarray(
            [feature_vector.as_list()],
            dtype=float,
        )

        raw_score = float(
            -self.model.decision_function(matrix)[0]
        )

        standardised = (
            raw_score - self._training_median
        ) / self._training_scale

        probability = 1.0 / (
            1.0 + math.exp(-standardised)
        )

        return round(
            min(max(probability, 0.0), 1.0),
            6,
        )

    def predict(
        self,
        feature_vector: BehaviourFeatureVector,
    ) -> bool:
        if not self.is_trained:
            raise RuntimeError("UEBA model has not been trained")

        matrix = np.asarray(
            [feature_vector.as_list()],
            dtype=float,
        )

        return int(self.model.predict(matrix)[0]) == -1

    def save(self, model_path: Path) -> Path:
        if not self.is_trained:
            raise RuntimeError("Cannot save an untrained UEBA model")

        model_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        joblib.dump(
            {
                "model": self.model,
                "contamination": self.contamination,
                "random_state": self.random_state,
                "training_median": self._training_median,
                "training_scale": self._training_scale,
            },
            model_path,
        )

        return model_path

    def load(self, model_path: Path) -> None:
        if not model_path.exists():
            raise FileNotFoundError(
                f"UEBA model not found: {model_path}"
            )

        payload = joblib.load(model_path)

        self.model = payload["model"]
        self.contamination = payload["contamination"]
        self.random_state = payload["random_state"]
        self._training_median = payload["training_median"]
        self._training_scale = payload["training_scale"]
        self.is_trained = True

    @staticmethod
    def _matrix(
        feature_vectors: Iterable[BehaviourFeatureVector],
    ) -> np.ndarray:
        rows: List[List[float]] = [
            vector.as_list()
            for vector in feature_vectors
        ]

        return np.asarray(rows, dtype=float)