import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import (
    Alarm,
    CfgEdge,
    CfgNode,
    DiagnosticRow,
    RunArtifact,
    SourceFile,
    TraceEvent,
)
from app.db.session import get_db
from app.schemas.common import AlarmOut, DiagnosticOut, Page, SummaryOut

from .deps import json_value, page_params, run_or_404

router = APIRouter(prefix="/api/v1/runs", tags=["results"])


def alarm_out(a: Alarm) -> dict:
    return {
        "id": a.id,
        "run_id": a.run_id,
        "alarm_key": a.alarm_key,
        "detector_id": a.detector_id,
        "detector_version": a.detector_version,
        "rule_pack_id": a.rule_pack_id,
        "rule_pack_version": a.rule_pack_version,
        "cwe_id": a.cwe_id,
        "family": a.family,
        "violation_kind": a.violation_kind,
        "severity": a.severity,
        "function_name": a.function_name,
        "block_id": a.block_id,
        "instruction_id": a.instruction_id,
        "instruction_text": a.instruction_text,
        "source_file_id": a.source_file_id,
        "source_line": a.source_line,
        "memory_object_id": a.memory_object_id,
        "object_name": a.object_name,
        "object_size": {
            "lower": a.object_size_lower,
            "upper": a.object_size_upper,
            "is_bottom": False,
        },
        "offset": {
            "lower": a.offset_lower,
            "upper": a.offset_upper,
            "is_bottom": False,
        },
        "access_size_bytes": a.access_size,
        "safe_condition": a.safe_condition,
        "message": a.message,
        "reason": json_value(a.reason_json, []),
        "evidence": json_value(a.evidence_json, {}),
    }


def diagnostic_out(d: DiagnosticRow) -> dict:
    return {
        "id": d.id,
        "run_id": d.run_id,
        "diagnostic_id": d.diagnostic_id,
        "code": d.code,
        "severity": d.severity,
        "message": d.message,
        "location": json_value(d.location_json, None),
        "impact": d.impact,
        "function_name": d.function_name,
        "block_id": d.block_id,
        "instruction_id": d.instruction_id,
        "source_file_id": d.source_file_id,
        "source_line": d.source_line,
    }


def filters(q, detector_id, rule_pack_id, cwe_id, family, violation_kind, severity, function):
    for col, value in (
        (Alarm.detector_id, detector_id),
        (Alarm.rule_pack_id, rule_pack_id),
        (Alarm.cwe_id, cwe_id),
        (Alarm.family, family),
        (Alarm.violation_kind, violation_kind),
        (Alarm.severity, severity),
        (Alarm.function_name, function),
    ):
        if value is not None:
            q = q.where(col == value)
    return q


@router.get("/{run_id}/summary", response_model=SummaryOut)
def summary(run_id: str, db: Session = Depends(get_db)):
    run = run_or_404(db, run_id)
    alarms = db.scalars(select(Alarm).where(Alarm.run_id == run_id)).all()
    diagnostics = db.scalars(select(DiagnosticRow).where(DiagnosticRow.run_id == run_id)).all()
    duration = (
        int((run.finished_at - run.started_at).total_seconds() * 1000)
        if run.started_at and run.finished_at
        else None
    )
    funcs = {a.function_name for a in alarms if a.function_name} | {
        d.function_name for d in diagnostics if d.function_name
    }
    return {
        "run_id": run.id,
        "status": run.status,
        "detector_id": run.detector_id,
        "rule_pack_id": run.rule_pack_id,
        "alarm_count": len(alarms),
        "definite_count": sum(a.severity == "definite" for a in alarms),
        "possible_count": sum(a.severity == "possible" for a in alarms),
        "diagnostic_count": len(diagnostics),
        "unsupported_count": sum(d.severity == "unsupported" for d in diagnostics),
        "error_count": sum(d.severity == "error" for d in diagnostics),
        "duration_ms": duration,
        "functions_analyzed": len(funcs),
    }


@router.get("/{run_id}/alarms", response_model=Page[AlarmOut])
def alarms(
    run_id: str,
    detector_id: str | None = None,
    rule_pack_id: str | None = None,
    cwe_id: str | None = None,
    family: str | None = None,
    violation_kind: str | None = None,
    severity: str | None = None,
    function: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    run_or_404(db, run_id)
    limit, offset = page_params(limit, offset)
    q = filters(
        select(Alarm).where(Alarm.run_id == run_id),
        detector_id,
        rule_pack_id,
        cwe_id,
        family,
        violation_kind,
        severity,
        function,
    )
    count_q = filters(
        select(func.count()).select_from(Alarm).where(Alarm.run_id == run_id),
        detector_id,
        rule_pack_id,
        cwe_id,
        family,
        violation_kind,
        severity,
        function,
    )
    rows = db.scalars(q.order_by(Alarm.created_at).offset(offset).limit(limit)).all()
    return {
        "items": [alarm_out(a) for a in rows],
        "total": db.scalar(count_q) or 0,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{run_id}/alarms/{alarm_id}", response_model=AlarmOut)
def alarm(run_id: str, alarm_id: str, db: Session = Depends(get_db)):
    run_or_404(db, run_id)
    row = db.scalar(select(Alarm).where(Alarm.id == alarm_id, Alarm.run_id == run_id))
    if not row:
        raise HTTPException(
            404,
            detail={
                "code": "ALARM_NOT_FOUND",
                "message": "alarm does not exist",
                "details": {},
            },
        )
    return alarm_out(row)


@router.get("/{run_id}/diagnostics", response_model=Page[DiagnosticOut])
def diagnostics(
    run_id: str,
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    db: Session = Depends(get_db),
):
    run_or_404(db, run_id)
    limit, offset = page_params(limit, offset)
    q = select(DiagnosticRow).where(DiagnosticRow.run_id == run_id)
    cq = select(func.count()).select_from(DiagnosticRow).where(DiagnosticRow.run_id == run_id)
    if severity:
        q = q.where(DiagnosticRow.severity == severity)
        cq = cq.where(DiagnosticRow.severity == severity)
    rows = db.scalars(q.order_by(DiagnosticRow.id).offset(offset).limit(limit)).all()
    return {
        "items": [diagnostic_out(x) for x in rows],
        "total": db.scalar(cq) or 0,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{run_id}/cfg")
def cfg(run_id: str, function: str | None = None, db: Session = Depends(get_db)):
    run_or_404(db, run_id)
    nq = select(CfgNode).where(CfgNode.run_id == run_id)
    eq = select(CfgEdge).where(CfgEdge.run_id == run_id)
    if function:
        nq = nq.where(CfgNode.function_name == function)
        eq = eq.where(CfgEdge.function_name == function)
    nodes = db.scalars(nq).all()
    edges = db.scalars(eq).all()
    return {
        "nodes": [
            {
                "id": n.block_id,
                "label": n.label or n.block_id,
                "function": n.function_name,
                "entry_state": json_value(n.entry_state_json, {}),
                "exit_state": json_value(n.exit_state_json, {}),
            }
            for n in nodes
        ],
        "edges": [
            {
                "source": e.source_block,
                "target": e.target_block,
                "function": e.function_name,
                "condition": e.condition,
                "polarity": e.polarity,
            }
            for e in edges
        ],
    }


@router.get("/{run_id}/states")
def states(
    run_id: str,
    function: str | None = None,
    block_id: str | None = None,
    db: Session = Depends(get_db),
):
    run_or_404(db, run_id)
    q = select(CfgNode).where(CfgNode.run_id == run_id)
    if function:
        q = q.where(CfgNode.function_name == function)
    if block_id:
        q = q.where(CfgNode.block_id == block_id)
    return {
        "items": [
            {
                "function_name": n.function_name,
                "block_id": n.block_id,
                "entry_state": json_value(n.entry_state_json, {}),
                "exit_state": json_value(n.exit_state_json, {}),
            }
            for n in db.scalars(q).all()
        ]
    }


@router.get("/{run_id}/ir")
def ir(run_id: str, function: str | None = None, db: Session = Depends(get_db)):
    run = run_or_404(db, run_id)
    q = select(RunArtifact).where(
        RunArtifact.run_id == run_id,
        RunArtifact.kind.in_(["ir", "normalized_ir", "source"]),
    )
    if function:
        q = q.where(RunArtifact.function_name == function)
    return {
        "items": [
            {
                "id": a.id,
                "kind": a.kind,
                "source_file_id": a.source_file_id,
                "source_file_path": (
                    source.path
                    if (source := db.get(SourceFile, a.source_file_id)) is not None
                    else None
                ),
                "function_name": a.function_name,
                "content": a.content,
                "sha256": a.sha256,
            }
            for a in db.scalars(q).all()
        ],
        "source_file_path": (
            source.path
            if json.loads(run.file_ids_json or "[]")
            and (source := db.get(SourceFile, json.loads(run.file_ids_json or "[]")[0])) is not None
            else None
        ),
    }


@router.get("/{run_id}/trace")
def trace(
    run_id: str,
    function: str | None = None,
    block_id: str | None = None,
    after: int = -1,
    limit: int = 500,
    db: Session = Depends(get_db),
):
    run_or_404(db, run_id)
    q = select(TraceEvent).where(TraceEvent.run_id == run_id, TraceEvent.sequence_no > after)
    if function:
        q = q.where(TraceEvent.function_name == function)
    if block_id:
        q = q.where(TraceEvent.block_id == block_id)
    rows = db.scalars(q.order_by(TraceEvent.sequence_no).limit(min(max(limit, 1), 5000))).all()
    return {
        "items": [
            {
                "id": e.id,
                "sequence_no": e.sequence_no,
                "event_type": e.event_type,
                "function_name": e.function_name,
                "block_id": e.block_id,
                "instruction_id": e.instruction_id,
                "before_state": json_value(e.before_state_json, {}),
                "after_state": json_value(e.after_state_json, {}),
                "explanation": e.explanation,
            }
            for e in rows
        ]
    }
