"""Materialize a deterministic Juliet manifest into project runs."""

import hashlib
import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import AnalysisRun, Evaluation, RunFile, SourceFile


def materialize_manifest(
    db: Session, evaluation: Evaluation, manifest_path: str, max_cases: int | None = None
) -> int:
    path = Path(manifest_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[3] / path
    if not path.is_file():
        raise ValueError(f"manifest does not exist: {manifest_path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise TypeError("manifest cases must be an array")
    if max_cases:
        cases = cases[:max_cases]
    for item in cases:
        name = item.get("case_name") or item.get("name")
        if not name:
            raise ValueError("manifest case is missing case_name")
        bad = _paths(item.get("bad_files"), item.get("files"), role="bad")
        good = _paths(item.get("good_files"), item.get("files"), role="good")
        bad_ids = [_source(db, evaluation.project_id, p) for p in bad]
        good_ids = [_source(db, evaluation.project_id, p) for p in good]
        bad_run = _run(db, evaluation, bad_ids, f"{name}:bad")
        good_run = _run(db, evaluation, good_ids, f"{name}:good")
        from app.db.models import EvaluationCase

        db.add(
            EvaluationCase(
                evaluation_id=evaluation.id,
                case_name=name,
                cwe_id=item.get("cwe_id", "CWE-121"),
                family=item.get("family"),
                bad_run_id=bad_run.id,
                good_run_id=good_run.id,
                bad_outcome="unsupported",
                good_outcome="unsupported",
            )
        )
    return len(cases)


def _paths(primary, fallback, role: str) -> list[Path]:
    values = (
        primary if isinstance(primary, list) else fallback if isinstance(fallback, list) else []
    )
    selected = []
    for value in values:
        raw = value.get("path") if isinstance(value, dict) else value
        if not raw:
            continue
        if primary is None and isinstance(value, dict):
            filename = Path(raw).name
            if role == "bad" and "_good" in filename:
                continue
            if role == "good" and "_bad" in filename:
                continue
        selected.append(Path(raw))
    return selected


def _source(db: Session, project_id: str, path: Path) -> str:
    if path.is_absolute():
        resolved = path
    else:
        resolved = Path.cwd() / path
        if not resolved.is_file():
            resolved = Path(__file__).resolve().parents[3] / path
    if not resolved.is_file():
        raise ValueError(f"manifest source does not exist: {path}")
    content = resolved.read_bytes()
    relative = str(path).replace("\\", "/")
    digest = hashlib.sha256(content).hexdigest()
    stored_path = f"juliet/{relative}"
    existing = db.scalar(
        select(SourceFile).where(
            SourceFile.project_id == project_id,
            SourceFile.path == stored_path,
            SourceFile.sha256 == digest,
        )
    )
    if existing:
        return existing.id
    row = SourceFile(
        project_id=project_id,
        path=stored_path,
        language=resolved.suffix.lstrip(".") or "c",
        content=content.decode("utf-8", errors="replace"),
        sha256=digest,
        size_bytes=len(content),
    )
    db.add(row)
    db.flush()
    return row.id


def _run(db: Session, evaluation: Evaluation, file_ids: list[str], variant: str) -> AnalysisRun:
    row = AnalysisRun(
        project_id=evaluation.project_id,
        detector_id=evaluation.detector_id,
        detector_version=evaluation.detector_version,
        rule_pack_id=evaluation.rule_pack_id,
        rule_pack_version=evaluation.rule_pack_version,
        analyzer_version=settings.analyzer_version,
        result_schema_version="1.0.0",
        variant=variant,
        mode="normal",
        config_json=json.dumps({"evaluation_id": evaluation.id}, sort_keys=True),
        file_ids_json=json.dumps(file_ids),
    )
    db.add(row)
    db.flush()
    for file_id in file_ids:
        db.add(RunFile(run_id=row.id, source_file_id=file_id, variant=variant))
    return row
