import json

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.models import AnalysisRun, Project


def project_or_404(db: Session, project_id: str) -> Project:
    row = db.get(Project, project_id)
    if not row:
        raise HTTPException(
            404,
            detail={
                "code": "PROJECT_NOT_FOUND",
                "message": "project does not exist",
                "details": {},
            },
        )
    return row


def run_or_404(db: Session, run_id: str) -> AnalysisRun:
    row = db.get(AnalysisRun, run_id)
    if not row:
        raise HTTPException(
            404,
            detail={
                "code": "RUN_NOT_FOUND",
                "message": "analysis run does not exist",
                "details": {},
            },
        )
    return row


def json_value(value: str | None, fallback):
    try:
        return json.loads(value) if value is not None else fallback
    except (TypeError, ValueError):
        return fallback


def page_params(limit: int = 50, offset: int = 0):
    return min(max(limit, 1), 500), max(offset, 0)
