from app.assets.schemas import Asset, AssetCriticality, AssetType
from app.assets.service import AssetInventoryService


def test_register_and_lookup_asset() -> None:
    inventory = AssetInventoryService()

    asset = Asset(
        asset_id="EXAM-DB-01",
        name="Examination Records Database",
        asset_type=AssetType.DATABASE,
        criticality=AssetCriticality.CRITICAL,
        ip_address="10.0.4.30",
        contains_sensitive_data=True,
    )

    inventory.register(asset)

    assert inventory.count() == 1
    assert inventory.get("EXAM-DB-01") == asset
    assert inventory.get_by_ip("10.0.4.30") == asset
    assert asset.criticality_score == 1.0


def test_duplicate_asset_is_rejected() -> None:
    inventory = AssetInventoryService()

    asset = Asset(
        asset_id="APP-001",
        name="Application Server",
        asset_type=AssetType.APPLICATION_SERVER,
        criticality=AssetCriticality.HIGH,
    )

    inventory.register(asset)

    try:
        inventory.register(asset)
        assert False, "Expected duplicate asset error"
    except ValueError as exc:
        assert "Asset already exists" in str(exc)


def test_duplicate_ip_is_rejected() -> None:
    inventory = AssetInventoryService()

    inventory.register(
        Asset(
            asset_id="APP-001",
            name="Application Server",
            asset_type=AssetType.APPLICATION_SERVER,
            criticality=AssetCriticality.HIGH,
            ip_address="10.0.0.10",
        )
    )

    try:
        inventory.register(
            Asset(
                asset_id="DB-001",
                name="Database Server",
                asset_type=AssetType.DATABASE,
                criticality=AssetCriticality.CRITICAL,
                ip_address="10.0.0.10",
            )
        )
        assert False, "Expected duplicate IP error"
    except ValueError as exc:
        assert "IP address already assigned" in str(exc)


def test_filter_critical_assets() -> None:
    inventory = AssetInventoryService()

    inventory.register(
        Asset(
            asset_id="LOW-001",
            name="Low Risk Device",
            asset_type=AssetType.USER_DEVICE,
            criticality=AssetCriticality.LOW,
        )
    )

    inventory.register(
        Asset(
            asset_id="CRIT-001",
            name="Critical Database",
            asset_type=AssetType.DATABASE,
            criticality=AssetCriticality.CRITICAL,
            contains_sensitive_data=True,
        )
    )

    critical = inventory.critical_assets()

    assert len(critical) == 1
    assert critical[0].asset_id == "CRIT-001"
