from __future__ import annotations

import math
from dataclasses import dataclass

from .transitions import AttackTransitionModel


@dataclass(frozen=True)
class ViterbiPath:
    tactics: list[str]
    probabilities: list[float]
    cumulative_probability: float


class ViterbiAttackPredictor:
    """
    Predict the most probable future tactic sequence using dynamic
    programming.

    Complexity:
    - Time: O(H × V × E)
    - Space: O(H × V)

    H = prediction horizon
    V = number of tactics
    E = possible tactic transitions
    """

    def __init__(
        self,
        transition_model: AttackTransitionModel,
    ) -> None:
        self.transition_model = transition_model

    def predict(
        self,
        current_tactic: str,
        horizon: int = 3,
    ) -> ViterbiPath:
        if horizon <= 0:
            raise ValueError(
                "horizon must be greater than zero"
            )

        if current_tactic not in (
            self.transition_model.tactics()
        ):
            raise ValueError(
                f"Unknown current tactic: {current_tactic}"
            )

        # state -> (log probability, complete path, edge probabilities)
        current_layer: dict[
            str,
            tuple[float, list[str], list[float]],
        ] = {
            current_tactic: (
                0.0,
                [current_tactic],
                [],
            )
        }

        for _ in range(horizon):
            next_layer: dict[
                str,
                tuple[
                    float,
                    list[str],
                    list[float],
                ],
            ] = {}

            for (
                source_tactic,
                (
                    source_log_probability,
                    source_path,
                    source_probabilities,
                ),
            ) in current_layer.items():
                transitions = (
                    self.transition_model.next_tactics(
                        source_tactic
                    )
                )

                for (
                    target_tactic,
                    transition_probability,
                ) in transitions:
                    if transition_probability <= 0:
                        continue

                    candidate_log_probability = (
                        source_log_probability
                        + math.log(
                            transition_probability
                        )
                    )

                    existing = next_layer.get(
                        target_tactic
                    )

                    if (
                        existing is None
                        or candidate_log_probability
                        > existing[0]
                    ):
                        next_layer[target_tactic] = (
                            candidate_log_probability,
                            source_path
                            + [target_tactic],
                            source_probabilities
                            + [transition_probability],
                        )

            if not next_layer:
                break

            current_layer = next_layer

        if not current_layer:
            return ViterbiPath(
                tactics=[],
                probabilities=[],
                cumulative_probability=0.0,
            )

        (
            best_log_probability,
            best_path,
            best_probabilities,
        ) = max(
            current_layer.values(),
            key=lambda item: item[0],
        )

        return ViterbiPath(
            # Exclude the already observed current tactic.
            tactics=best_path[1:],
            probabilities=best_probabilities,
            cumulative_probability=round(
                math.exp(best_log_probability),
                8,
            ),
        )

    def top_paths(
        self,
        current_tactic: str,
        horizon: int = 3,
        limit: int = 5,
    ) -> list[ViterbiPath]:
        if limit <= 0:
            raise ValueError(
                "limit must be greater than zero"
            )

        paths: list[ViterbiPath] = []

        def explore(
            tactic: str,
            remaining_steps: int,
            path: list[str],
            probabilities: list[float],
            cumulative_probability: float,
        ) -> None:
            if remaining_steps == 0:
                paths.append(
                    ViterbiPath(
                        tactics=path,
                        probabilities=probabilities,
                        cumulative_probability=round(
                            cumulative_probability,
                            8,
                        ),
                    )
                )
                return

            transitions = (
                self.transition_model.next_tactics(
                    tactic
                )
            )

            if not transitions:
                paths.append(
                    ViterbiPath(
                        tactics=path,
                        probabilities=probabilities,
                        cumulative_probability=round(
                            cumulative_probability,
                            8,
                        ),
                    )
                )
                return

            for next_tactic, probability in transitions:
                explore(
                    tactic=next_tactic,
                    remaining_steps=remaining_steps - 1,
                    path=path + [next_tactic],
                    probabilities=(
                        probabilities + [probability]
                    ),
                    cumulative_probability=(
                        cumulative_probability
                        * probability
                    ),
                )

        explore(
            tactic=current_tactic,
            remaining_steps=horizon,
            path=[],
            probabilities=[],
            cumulative_probability=1.0,
        )

        return sorted(
            paths,
            key=lambda item: (
                -item.cumulative_probability,
                item.tactics,
            ),
        )[:limit]