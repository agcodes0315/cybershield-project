from __future__ import annotations

from threading import RLock
from typing import Dict, List, Optional

from .schemas import Asset, AssetCriticality, AssetType


class AssetInventoryService:
    """
    In-memory asset inventory using hash maps for O(1)-average lookup.

    Production storage will later use PostgreSQL, while Redis may cache
    frequently accessed critical assets.
    """

    def __init__(self) -> None:
        self._assets_by_id: Dict[str, Asset] = {}
        self._assets_by_ip: Dict[str, str] = {}
        self._lock = RLock()

    def register(self, asset: Asset) -> Asset:
        with self._lock:
            if asset.asset_id in self._assets_by_id:
                raise ValueError(
                    f"Asset already exists: {asset.asset_id}"
                )

            if asset.ip_address and asset.ip_address in self._assets_by_ip:
                existing_id = self._assets_by_ip[asset.ip_address]
                raise ValueError(
                    f"IP address already assigned to asset: {existing_id}"
                )

            self._assets_by_id[asset.asset_id] = asset

            if asset.ip_address:
                self._assets_by_ip[asset.ip_address] = asset.asset_id

            return asset

    def upsert(self, asset: Asset) -> Asset:
        with self._lock:
            existing = self._assets_by_id.get(asset.asset_id)

            if existing and existing.ip_address:
                self._assets_by_ip.pop(existing.ip_address, None)

            if asset.ip_address:
                conflicting_id = self._assets_by_ip.get(asset.ip_address)

                if conflicting_id and conflicting_id != asset.asset_id:
                    raise ValueError(
                        f"IP address already assigned to asset: {conflicting_id}"
                    )

                self._assets_by_ip[asset.ip_address] = asset.asset_id

            self._assets_by_id[asset.asset_id] = asset
            return asset

    def get(self, asset_id: str) -> Optional[Asset]:
        with self._lock:
            return self._assets_by_id.get(asset_id)

    def get_by_ip(self, ip_address: str) -> Optional[Asset]:
        with self._lock:
            asset_id = self._assets_by_ip.get(ip_address)

            if not asset_id:
                return None

            return self._assets_by_id.get(asset_id)

    def list_assets(
        self,
        asset_type: Optional[AssetType] = None,
        criticality: Optional[AssetCriticality] = None,
        active_only: bool = True,
    ) -> List[Asset]:
        with self._lock:
            assets = list(self._assets_by_id.values())

        if active_only:
            assets = [asset for asset in assets if asset.active]

        if asset_type:
            assets = [
                asset for asset in assets
                if asset.asset_type == asset_type
            ]

        if criticality:
            assets = [
                asset for asset in assets
                if asset.criticality == criticality
            ]

        return assets

    def critical_assets(self) -> List[Asset]:
        with self._lock:
            assets = [
                asset
                for asset in self._assets_by_id.values()
                if asset.active
                and asset.criticality == AssetCriticality.CRITICAL
            ]

        return sorted(
            assets,
            key=lambda asset: (
                not asset.internet_exposed,
                not asset.contains_sensitive_data,
                asset.asset_id,
            ),
        )

    def count(self) -> int:
        with self._lock:
            return len(self._assets_by_id)

    def clear(self) -> None:
        with self._lock:
            self._assets_by_id.clear()
            self._assets_by_ip.clear()


asset_inventory_service = AssetInventoryService()
