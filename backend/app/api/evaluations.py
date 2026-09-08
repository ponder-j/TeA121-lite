import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import (
    Alarm,
    AnalysisRun,
    Detector,
    Evaluation,
    EvaluationCase,
    RulePack,
)
from app.db.session import SessionLocal, get_db
from app.schemas.common import (
    EvaluationCaseOut,
    EvaluationCreate,
    EvaluationOut,
    MatrixOut,
    Page,
)
from app.services.evaluation_service import execute_evaluation
from app.services.juliet_service import materialize_manifest

from .deps import page_params, project_or_404

router = APIRouter(prefix="/api/v1", tags=["evaluations"])
evaluation_tasks: dict[str, asyncio.Task] = {}


def serialize(e: Evaluation) -> dict:
    return {
        "id": e.id,
        "project_id": e.project_id,
        "dataset_name": e.dataset_name,
        "dataset_version": e.dataset_version,
        "detector_id": e.detector_id,
        "detector_version": e.detector_version,
        "rule_pack_id": e.rule_pack_id,
        "rule_pack_version": e.rule_pack_version,
        "status": e.status,
        "filter": json.loads(e.filter_json),
        "summary": json.loads(e.summary_json),
        "created_at": e.created_at,
        "started_at": e.started_at,
        "finished_at": e.finished_at,
    }


def outcome(db: Session, run_id: str | None) -> str:
    if not run_id:
        return "error"
    run = db.get(AnalysisRun, run_id)
    if not run:
        return "error"
    if run.status in {"failed"}:
        return "error"
    if run.status == "cancelled":
        return "unsupported"
    if run.status != "succeeded":
        return "unsupported"
    return (
        "alarm"
        if db.scalar(select(func.count()).select_from(Alarm).where(Alarm.run_id == run_id))
        else "clean"
    )


@router.post("/projects/{project_id}/evaluations", response_model=EvaluationOut, status_code=202)
async def create_evaluation(
    project_id: str, payload: EvaluationCreate, db: Session = Depends(get_db)
):
    project_or_404(db, project_id)
    detector = db.get(Detector, payload.detector_id)
    pack = db.get(RulePack, payload.rule_pack_id)
    if detector is None:
        raise HTTPException(
            400,
            detail={
                "code": "DETECTOR_NOT_FOUND",
                "message": "detector does not exist",
                "details": {},
            },
        )
    if not detector.enabled:
        raise HTTPException(
            400,
            detail={
                "code": "DETECTOR_DISABLED",
                "message": "detector is disabled",
                "details": {},
            },
        )
    if pack is None or pack.detector_id != detector.id:
        raise HTTPException(
            400,
            detail={
                "code": "RULE_PACK_NOT_SUPPORTED",
                "message": "rule pack is not compatible",
                "details": {},
            },
        )
    e = Evaluation(
        project_id=project_id,
        dataset_name=payload.dataset_name,
        dataset_version=payload.dataset_version,
        detector_id=detector.id,
        detector_version=detector.version,
        rule_pack_id=pack.id,
        rule_pack_version=pack.version,
        filter_json=json.dumps(payload.filter, sort_keys=True),
    )
    db.add(e)
    db.flush()
    if payload.manifest_path:
        try:
            materialize_manifest(db, e, payload.manifest_path, payload.max_cases)
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            db.rollback()
            raise HTTPException(
                400,
                detail={"code": "INVALID_EVALUATION_MANIFEST", "message": str(exc), "details": {}},
            ) from exc
    for item in payload.cases:
        bad_id, good_id = item.get("bad_run_id"), item.get("good_run_id")
        db.add(
            EvaluationCase(
                evaluation_id=e.id,
                case_name=item.get("case_name", item.get("name", "case")),
                cwe_id=item.get("cwe_id"),
                family=item.get("family"),
                bad_run_id=bad_id,
                good_run_id=good_id,
                bad_outcome=outcome(db, bad_id),
                good_outcome=outcome(db, good_id),
                classification=_classification(outcome(db, bad_id), outcome(db, good_id)),
            )
        )
    db.commit()
    db.refresh(e)
    task = asyncio.create_task(execute_evaluation(e.id, SessionLocal))
    evaluation_tasks[e.id] = task
    task.add_done_callback(lambda _: evaluation_tasks.pop(e.id, None))
    return serialize(e)


def _classification(bad: str, good: str) -> str:
    return {
        ("alarm", "clean"): "correct",
        ("alarm", "alarm"): "false_positive",
        ("clean", "clean"): "false_negative",
        ("clean", "alarm"): "inverted",
    }.get((bad, good), "unsupported")


@router.get("/projects/{project_id}/evaluations", response_model=Page[EvaluationOut])
def list_evaluations(
    project_id: str, limit: int = 50, offset: int = 0, db: Session = Depends(get_db)
):
    project_or_404(db, project_id)
    limit, offset = page_params(limit, offset)
    q = select(Evaluation).where(Evaluation.project_id == project_id)
    total = (
        db.scalar(
            select(func.count()).select_from(Evaluation).where(Evaluation.project_id == project_id)
        )
        or 0
    )
    return {
        "items": [
            serialize(x)
            for x in db.scalars(
                q.order_by(Evaluation.created_at.desc()).offset(offset).limit(limit)
            ).all()
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/evaluations/{evaluation_id}", response_model=EvaluationOut)
def get_evaluation(evaluation_id: str, db: Session = Depends(get_db)):
    e = db.get(Evaluation, evaluation_id)
    if not e:
        raise HTTPException(
            404,
            detail={
                "code": "EVALUATION_NOT_FOUND",
                "message": "evaluation does not exist",
                "details": {},
            },
        )
    return serialize(e)


@router.post("/evaluations/{evaluation_id}/cancel", response_model=EvaluationOut)
def cancel_evaluation(evaluation_id: str, db: Session = Depends(get_db)):
    e = db.get(Evaluation, evaluation_id)
    if not e:
        raise HTTPException(
            404,
            detail={
                "code": "EVALUATION_NOT_FOUND",
                "message": "evaluation does not exist",
                "details": {},
            },
        )
    if e.status in {"queued", "running"}:
        task = evaluation_tasks.get(e.id)
        if task and not task.done():
            task.cancel()
        else:
            e.status = "cancelled"
            e.finished_at = datetime.now(timezone.utc)
        db.commit()
    return serialize(e)


def _cases_query(evaluation_id, detector_id, rule_pack_id, cwe_id, family, violation_kind, db):
    q = select(EvaluationCase).where(EvaluationCase.evaluation_id == evaluation_id)
    if cwe_id:
        q = q.where(EvaluationCase.cwe_id == cwe_id)
    if family:
        q = q.where(EvaluationCase.family == family)
    if detector_id or rule_pack_id or violation_kind:
        # Detector/rule-pack are snapshots on the associated runs. Violation kind is resolved through alarms.
        ids = db.scalars(
            select(AnalysisRun.id).where(
                *(
                    x
                    for x in [
                        AnalysisRun.detector_id == detector_id if detector_id else None,
                        AnalysisRun.rule_pack_id == rule_pack_id if rule_pack_id else None,
                    ]
                    if x is not None
                )
            )
        ).all()
        if detector_id or rule_pack_id:
            q = q.where(
                (EvaluationCase.bad_run_id.in_(ids)) | (EvaluationCase.good_run_id.in_(ids))
            )
        if violation_kind:
            alarm_runs = db.scalars(
                select(Alarm.run_id).where(Alarm.violation_kind == violation_kind)
            ).all()
            q = q.where(
                (EvaluationCase.bad_run_id.in_(alarm_runs))
                | (EvaluationCase.good_run_id.in_(alarm_runs))
            )
    return q


@router.get("/evaluations/{evaluation_id}/cases", response_model=Page[EvaluationCaseOut])
def cases(
    evaluation_id: str,
    detector_id: str | None = None,
    rule_pack_id: str | None = None,
    cwe_id: str | None = None,
    family: str | None = None,
    violation_kind: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    if not db.get(Evaluation, evaluation_id):
        raise HTTPException(
            404,
            detail={
                "code": "EVALUATION_NOT_FOUND",
                "message": "evaluation does not exist",
                "details": {},
            },
        )
    limit, offset = page_params(limit, offset)
    q = _cases_query(evaluation_id, detector_id, rule_pack_id, cwe_id, family, violation_kind, db)
    rows = db.scalars(q.offset(offset).limit(limit)).all()
    count_q = (
        _cases_query(evaluation_id, detector_id, rule_pack_id, cwe_id, family, violation_kind, db)
        .with_only_columns(func.count())
        .order_by(None)
    )
    return {
        "items": rows,
        "total": db.scalar(count_q) or 0,
        "limit": limit,
        "offset": offset,
    }


@router.get("/evaluations/{evaluation_id}/matrix", response_model=MatrixOut)
def matrix(
    evaluation_id: str,
    cwe_id: str | None = None,
    family: str | None = None,
    db: Session = Depends(get_db),
):
    e = db.get(Evaluation, evaluation_id)
    if not e:
        raise HTTPException(
            404,
            detail={
                "code": "EVALUATION_NOT_FOUND",
                "message": "evaluation does not exist",
                "details": {},
            },
        )
    q = select(EvaluationCase).where(EvaluationCase.evaluation_id == e.id)
    if cwe_id:
        q = q.where(EvaluationCase.cwe_id == cwe_id)
    if family:
        q = q.where(EvaluationCase.family == family)
    rows = db.scalars(q).all()
    counts = {
        key: sum(c.classification == key for c in rows)
        for key in ("correct", "false_positive", "false_negative", "inverted")
    }
    unsupported = sum(
        c.bad_outcome in {"unsupported", "error"} or c.good_outcome in {"unsupported", "error"}
        for c in rows
    )
    errors = sum(c.bad_outcome == "error" or c.good_outcome == "error" for c in rows)
    total = len(rows)
    return {
        "detector_id": e.detector_id,
        "rule_pack_id": e.rule_pack_id,
        "cwe_id": cwe_id,
        "family": family,
        **counts,
        "unsupported": unsupported,
        "error": errors,
        "total": total,
        "bad_recall": (counts["correct"] + counts["false_positive"]) / total if total else None,
        "good_specificity": (counts["correct"] + counts["false_negative"]) / total
        if total
        else None,
        "file_accuracy": (counts["correct"] / total) if total else None,
    }
