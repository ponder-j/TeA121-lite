import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import AnalysisRun, Detector, RulePack, RunFile, SourceFile
from app.db.session import SessionLocal, get_db
from app.schemas.common import Page, RunCreate, RunOut
from app.services.run_service import execute_run, transition

from .deps import json_value, page_params, project_or_404, run_or_404

router = APIRouter(prefix="/api/v1", tags=["runs"])
tasks: dict[str, asyncio.Task] = {}


def serialize(run: AnalysisRun) -> dict:
    return {
        "id": run.id,
        "project_id": run.project_id,
        "status": run.status,
        "detector_id": run.detector_id,
        "detector_version": run.detector_version,
        "rule_pack_id": run.rule_pack_id,
        "rule_pack_version": run.rule_pack_version,
        "analyzer_version": run.analyzer_version,
        "result_schema_version": run.result_schema_version,
        "file_ids": json_value(run.file_ids_json, []),
        "variant": run.variant,
        "mode": run.mode,
        "config": json_value(run.config_json, {}),
        "progress": run.progress,
        "error_message": run.error_message,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
    }


def _bad(code: str, message: str, details: dict | None = None, status_code: int = 400):
    return HTTPException(
        status_code, detail={"code": code, "message": message, "details": details or {}}
    )


@router.get("/projects/{project_id}/runs", response_model=Page[RunOut])
def list_runs(project_id: str, limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    project_or_404(db, project_id)
    limit, offset = page_params(limit, offset)
    q = select(AnalysisRun).where(AnalysisRun.project_id == project_id)
    total = (
        db.scalar(
            select(func.count())
            .select_from(AnalysisRun)
            .where(AnalysisRun.project_id == project_id)
        )
        or 0
    )
    return {
        "items": [
            serialize(x)
            for x in db.scalars(
                q.order_by(AnalysisRun.created_at.desc()).offset(offset).limit(limit)
            ).all()
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/projects/{project_id}/runs", response_model=RunOut, status_code=202)
async def create_run(
    project_id: str, payload: RunCreate, request: Request, db: Session = Depends(get_db)
):
    project_or_404(db, project_id)
    detector = db.get(Detector, payload.detector_id)
    if detector is None:
        raise _bad("DETECTOR_NOT_FOUND", "detector does not exist")
    if not detector.enabled:
        raise _bad("DETECTOR_DISABLED", "detector is disabled")
    pack = db.get(RulePack, payload.rule_pack_id)
    if pack is None or pack.detector_id != detector.id:
        raise _bad("RULE_PACK_NOT_SUPPORTED", "rule pack is not compatible with detector")
    if payload.detector_version and payload.detector_version != detector.version:
        raise _bad("DETECTOR_VERSION_MISMATCH", "requested detector version is unavailable")
    if payload.rule_pack_version and payload.rule_pack_version != pack.version:
        raise _bad("RULE_PACK_NOT_SUPPORTED", "requested rule pack version is unavailable")
    declarations = {
        "cwe_id": json.loads(pack.supported_cwes_json),
        "family": json.loads(pack.supported_families_json),
        "violation_kind": json.loads(pack.supported_violation_kinds_json),
    }
    for key in ("cwe_id", "family", "violation_kind"):
        value = getattr(payload, key)
        if value is not None and value not in declarations[key]:
            raise _bad("RULE_PACK_NOT_SUPPORTED", f"{key} is not declared by rule pack")
    files = (
        db.scalars(
            select(SourceFile).where(
                SourceFile.project_id == project_id, SourceFile.id.in_(payload.file_ids)
            )
        ).all()
        if payload.file_ids
        else []
    )
    if len(files) != len(set(payload.file_ids)):
        raise _bad("FILE_NOT_FOUND", "one or more files do not belong to project")
    config = dict(payload.config)
    config.update(
        {
            k: v
            for k, v in {
                "cwe_id": payload.cwe_id,
                "family": payload.family,
                "violation_kind": payload.violation_kind,
            }.items()
            if v is not None
        }
    )
    run = AnalysisRun(
        project_id=project_id,
        detector_id=detector.id,
        detector_version=detector.version,
        rule_pack_id=pack.id,
        rule_pack_version=pack.version,
        analyzer_version=settings.analyzer_version,
        result_schema_version="1.0.0",
        variant=payload.variant,
        mode=payload.mode,
        config_json=json.dumps(config, sort_keys=True),
        file_ids_json=json.dumps(payload.file_ids),
    )
    db.add(run)
    db.flush()
    for f in files:
        db.add(RunFile(run_id=run.id, source_file_id=f.id, variant=payload.variant))
    db.commit()
    db.refresh(run)
    fixture = config.get("fixture_path")
    fixture_path = None
    if fixture:
        from pathlib import Path

        candidate = Path(fixture)
        if not candidate.is_absolute():
            candidate = Path(__file__).resolve().parents[3] / candidate
        if candidate.exists():
            fixture_path = candidate
    task = asyncio.create_task(execute_run(run.id, SessionLocal, pack, fixture_path))
    tasks[run.id] = task
    task.add_done_callback(lambda _: tasks.pop(run.id, None))
    return serialize(run)


@router.get("/runs/{run_id}", response_model=RunOut)
def get_run(run_id: str, db: Session = Depends(get_db)):
    return serialize(run_or_404(db, run_id))


@router.post("/runs/{run_id}/cancel", response_model=RunOut)
async def cancel_run(run_id: str, db: Session = Depends(get_db)):
    run = run_or_404(db, run_id)
    task = tasks.get(run.id)
    if run.status in {"queued", "running"}:
        if task and not task.done():
            task.cancel()
        else:
            transition(run, "cancelled")
            db.commit()
    return serialize(run)
