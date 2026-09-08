import asyncio
import json
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Alarm, AnalysisRun, Evaluation, EvaluationCase, RulePack

from .run_service import execute_run


def _outcome(db: Session, run_id: str | None) -> str:
    if not run_id:
        return "error"
    run = db.get(AnalysisRun, run_id)
    if run is None or run.status == "failed":
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


def _classification(bad: str, good: str) -> str:
    return {
        ("alarm", "clean"): "correct",
        ("alarm", "alarm"): "false_positive",
        ("clean", "clean"): "false_negative",
        ("clean", "alarm"): "inverted",
    }.get((bad, good), "unsupported")


async def execute_evaluation(evaluation_id: str, db_factory) -> None:
    db: Session = db_factory()
    evaluation = db.get(Evaluation, evaluation_id)
    if not evaluation or evaluation.status != "queued":
        db.close()
        return
    try:
        evaluation.status = "running"
        evaluation.started_at = datetime.now(timezone.utc)
        db.commit()
        queued = db.scalars(
            select(AnalysisRun).where(
                AnalysisRun.project_id == evaluation.project_id,
                AnalysisRun.status == "queued",
                AnalysisRun.config_json.like(f'%"evaluation_id": "{evaluation.id}"%'),
            )
        ).all()
        pack = db.get(RulePack, evaluation.rule_pack_id)
        if pack:
            await asyncio.gather(*(execute_run(run.id, db_factory, pack) for run in queued))
        cases = db.scalars(
            select(EvaluationCase).where(EvaluationCase.evaluation_id == evaluation.id)
        ).all()
        counts = {
            key: 0
            for key in (
                "correct",
                "false_positive",
                "false_negative",
                "inverted",
                "unsupported",
                "error",
            )
        }
        for case in cases:
            case.bad_outcome = _outcome(db, case.bad_run_id)
            case.good_outcome = _outcome(db, case.good_run_id)
            case.classification = _classification(case.bad_outcome, case.good_outcome)
            if case.bad_outcome == "error" or case.good_outcome == "error":
                counts["error"] += 1
            elif case.classification in counts:
                counts[case.classification] += 1
            else:
                counts["unsupported"] += 1
        counts["total"] = len(cases)
        evaluation.summary_json = json.dumps(counts, sort_keys=True)
        evaluation.status = "succeeded"
        evaluation.finished_at = datetime.now(timezone.utc)
        db.commit()
    except asyncio.CancelledError:
        db.rollback()
        evaluation = db.get(Evaluation, evaluation_id)
        if evaluation and evaluation.status in {"queued", "running"}:
            evaluation.status = "cancelled"
            evaluation.finished_at = datetime.now(timezone.utc)
            db.commit()
    except Exception as exc:
        db.rollback()
        evaluation = db.get(Evaluation, evaluation_id)
        if evaluation:
            evaluation.status = "failed"
            evaluation.summary_json = json.dumps({"error": str(exc)})
            evaluation.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
