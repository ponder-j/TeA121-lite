import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from app import __version__
from app.api import catalog, evaluations, events, projects, results, runs
from app.catalog.detectors import seed as seed_detector
from app.catalog.rule_packs import seed as seed_rule_pack
from app.config import settings
from app.db.session import SessionLocal, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_storage()
    init_db()
    db = SessionLocal()
    try:
        seed_detector(db)
        seed_rule_pack(db)
    finally:
        db.close()
    yield


app = FastAPI(title="tea121-lite backend", version=__version__, lifespan=lifespan)
app.include_router(projects.router)
app.include_router(catalog.router)
app.include_router(runs.router)
app.include_router(results.router)
app.include_router(events.router)
app.include_router(evaluations.router)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    if isinstance(exc, (KeyboardInterrupt, asyncio.CancelledError)):
        raise exc
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_ERROR", "message": str(exc), "details": {}}},
    )


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict) and "code" in detail:
        body = {"error": detail}
    else:
        body = {"error": {"code": "HTTP_ERROR", "message": str(detail), "details": {}}}
    return JSONResponse(status_code=exc.status_code, content=body, headers=exc.headers)


@app.get("/healthz", tags=["system"])
def healthz():
    return {"status": "ok", "version": __version__}


def run():
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)
