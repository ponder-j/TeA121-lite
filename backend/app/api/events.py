import json

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from sse_starlette.sse import EventSourceResponse, ServerSentEvent

from app.db.session import get_db
from app.services.event_bus import event_bus

from .deps import run_or_404

router = APIRouter(prefix="/api/v1/runs", tags=["events"])


@router.get("/{run_id}/events")
async def events(run_id: str, request: Request, db: Session = Depends(get_db)):
    run_or_404(db, run_id)
    try:
        last = int(request.headers.get("last-event-id", "-1"))
    except ValueError:
        last = -1

    async def stream():
        async for item in event_bus.subscribe(run_id, last):
            if await request.is_disconnected():
                break
            yield ServerSentEvent(
                data=json.dumps(item["data"], ensure_ascii=False, default=str),
                event=item["event"],
                id=item["id"],
            )
            if item["event"] in {"run.completed", "run.failed", "run.cancelled"}:
                break

    return EventSourceResponse(stream())
