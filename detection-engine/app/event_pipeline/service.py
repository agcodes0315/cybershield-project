from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Deque, Dict, List, Optional

from .schemas import SecurityEvent


class EventPipelineService:
    """
    In-memory foundation for development and tests.

    DSA usage:
    - Hash map for O(1)-average event lookup by event ID.
    - Inverted hash-map indexes for entity-based lookup.
    - Deque for efficient sliding-window insertion and eviction.

    PostgreSQL and Redis adapters will replace or complement this service
    during the production-deployment phase.
    """

    def __init__(self, retention_minutes: int = 120) -> None:
        if retention_minutes <= 0:
            raise ValueError("retention_minutes must be greater than zero")

        self.retention_window = timedelta(minutes=retention_minutes)

        self._events_by_id: Dict[str, SecurityEvent] = {}
        self._event_order: Deque[str] = deque()
        self._entity_index: Dict[str, Deque[str]] = defaultdict(deque)

        self._lock = RLock()

    def ingest(self, event: SecurityEvent) -> SecurityEvent:
        with self._lock:
            if event.event_id in self._events_by_id:
                raise ValueError(
                    f"Duplicate event_id received: {event.event_id}"
                )

            self._events_by_id[event.event_id] = event
            self._event_order.append(event.event_id)

            for entity_key in event.entity_keys():
                self._entity_index[entity_key].append(event.event_id)

            self._evict_expired_events(
                reference_time=event.timestamp.astimezone(timezone.utc)
            )

            return event

    def get(self, event_id: str) -> Optional[SecurityEvent]:
        with self._lock:
            return self._events_by_id.get(event_id)

    def get_recent_events(
        self,
        minutes: int = 30,
        limit: int = 500,
    ) -> List[SecurityEvent]:
        if minutes <= 0:
            raise ValueError("minutes must be greater than zero")

        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        threshold = datetime.now(timezone.utc) - timedelta(minutes=minutes)

        with self._lock:
            matched: List[SecurityEvent] = []

            for event_id in reversed(self._event_order):
                event = self._events_by_id.get(event_id)

                if event is None:
                    continue

                event_time = event.timestamp.astimezone(timezone.utc)

                if event_time < threshold:
                    break

                matched.append(event)

                if len(matched) >= limit:
                    break

            return matched

    def get_events_for_entity(
        self,
        entity_key: str,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        with self._lock:
            event_ids = self._entity_index.get(entity_key, deque())

            return [
                self._events_by_id[event_id]
                for event_id in list(event_ids)[-limit:]
                if event_id in self._events_by_id
            ]

    def count(self) -> int:
        with self._lock:
            return len(self._events_by_id)

    def clear(self) -> None:
        with self._lock:
            self._events_by_id.clear()
            self._event_order.clear()
            self._entity_index.clear()

    def _evict_expired_events(self, reference_time: datetime) -> None:
        threshold = reference_time - self.retention_window

        while self._event_order:
            oldest_event_id = self._event_order[0]
            oldest_event = self._events_by_id.get(oldest_event_id)

            if oldest_event is None:
                self._event_order.popleft()
                continue

            oldest_time = oldest_event.timestamp.astimezone(timezone.utc)

            if oldest_time >= threshold:
                break

            self._event_order.popleft()
            self._events_by_id.pop(oldest_event_id, None)

            for entity_key in oldest_event.entity_keys():
                entity_events = self._entity_index.get(entity_key)

                if entity_events is None:
                    continue

                try:
                    entity_events.remove(oldest_event_id)
                except ValueError:
                    pass

                if not entity_events:
                    self._entity_index.pop(entity_key, None)


event_pipeline_service = EventPipelineService()
