from app.ueba.model import IsolationForestBehaviourModel
from app.ueba.schemas import BehaviourFeatureVector


def test_isolation_forest_scores_anomaly_higher() -> None:
    normal_vectors = [
        BehaviourFeatureVector(
            login_hour=0.45 + (index % 5) * 0.01,
            data_transfer_mb=0.15 + (index % 4) * 0.01,
        )
        for index in range(100)
    ]

    model = IsolationForestBehaviourModel(
        contamination=0.05
    )

    model.fit(normal_vectors)

    normal_score = model.score(
        BehaviourFeatureVector(
            login_hour=0.50,
            data_transfer_mb=0.16,
        )
    )

    anomaly_score = model.score(
        BehaviourFeatureVector(
            login_hour=0.08,
            is_off_hours=1.0,
            new_device=1.0,
            new_location=1.0,
            failed_login_count=1.0,
            encoded_command=1.0,
            privileged_action=1.0,
            data_transfer_mb=1.0,
            rare_process=1.0,
            sensitive_asset_access=1.0,
            external_source_ip=1.0,
            first_time_asset_access=1.0,
        )
    )

    assert anomaly_score > normal_score