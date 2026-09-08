import asyncio
import json
from collections import defaultdict
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any


class EventBus:
    def __init__(self):
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)

    async def publish(self, run_id: str, event: str, data: Any) -> dict[str, Any]:
        history = self._history[run_id]
        item = {
            "id": str(len(history)),
            "event": event,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        history.append(item)
        for queue in list(self._subscribers[run_id]):
            await queue.put(item)
        return item

    async def subscribe(
        self, run_id: str, last_event_id: int = -1
    ) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers[run_id].add(queue)
        try:
            for item in self._history.get(run_id, []):
                if int(item["id"]) > last_event_id:
                    yield item
            while True:
                yield await queue.get()
        finally:
            self._subscribers[run_id].discard(queue)

    def history(self, run_id: str) -> list[dict[str, Any]]:
        return list(self._history.get(run_id, []))


event_bus = EventBus()


def sse_payload(item: dict[str, Any]) -> str:
    return json.dumps(item["data"], ensure_ascii=False, default=str)
