from __future__ import annotations

import pytest

from app.prediction.transitions import (
    AttackTransitionModel,
)
from app.prediction.viterbi import (
    ViterbiAttackPredictor,
)


def build_predictor() -> ViterbiAttackPredictor:
    return ViterbiAttackPredictor(
        AttackTransitionModel()
    )


def test_predicts_probable_continuation() -> None:
    predictor = build_predictor()

    result = predictor.predict(
        current_tactic="Credential Access",
        horizon=3,
    )

    assert result.tactics == [
        "Discovery",
        "Lateral Movement",
        "Collection",
    ]

    assert result.probabilities == [
        0.50,
        0.60,
        0.55,
    ]

    assert result.cumulative_probability == (
        pytest.approx(0.165)
    )


def test_collection_predicts_exfiltration() -> None:
    predictor = build_predictor()

    result = predictor.predict(
        current_tactic="Collection",
        horizon=1,
    )

    assert result.tactics == [
        "Exfiltration"
    ]

    assert result.probabilities == [
        0.65
    ]


def test_invalid_horizon_is_rejected() -> None:
    predictor = build_predictor()

    with pytest.raises(
        ValueError,
        match="horizon must be greater than zero",
    ):
        predictor.predict(
            current_tactic="Discovery",
            horizon=0,
        )


def test_unknown_tactic_is_rejected() -> None:
    predictor = build_predictor()

    with pytest.raises(
        ValueError,
        match="Unknown current tactic",
    ):
        predictor.predict(
            current_tactic="Unknown Tactic",
            horizon=2,
        )


def test_top_paths_are_ranked() -> None:
    predictor = build_predictor()

    paths = predictor.top_paths(
        current_tactic="Discovery",
        horizon=2,
        limit=3,
    )

    probabilities = [
        path.cumulative_probability
        for path in paths
    ]

    assert probabilities == sorted(
        probabilities,
        reverse=True,
    )