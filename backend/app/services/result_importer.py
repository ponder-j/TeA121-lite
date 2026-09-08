import json
from pathlib import Path
from typing import Any

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.db.models import (
    Alarm,
    AnalysisRun,
    CfgEdge,
    CfgNode,
    DiagnosticRow,
    RunArtifact,
    TraceEvent,
)


class ImportErrorValue(ValueError):
    pass


def _interval(value: dict[str, Any] | None) -> tuple[int | None, int | None]:
    value = value or {}
    if value.get("is_bottom"):
        return None, None
    return value.get("lower"), value.get("upper")


def validate_result(result: dict[str, Any], run: AnalysisRun, rule_pack: Any | None = None) -> None:
    try:
        from jsonschema import Draft202012Validator

        schema_path = (
            Path(__file__).resolve().parents[3]
            / "contracts"
            / "schemas"
            / "analyzer-result.schema.json"
        )
        if schema_path.exists():
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            errors = sorted(
                Draft202012Validator(schema).iter_errors(result),
                key=lambda e: list(e.path),
            )
            if errors:
                raise ImportErrorValue("analyzer result violates schema: " + errors[0].message)
    except ImportErrorValue:
        raise
    except Exception as exc:
        raise ImportErrorValue(f"analyzer result validation failed: {exc}") from exc
    required = {
        "schema_version",
        "run_id",
        "analyzer_version",
        "detector_id",
        "rule_pack_id",
        "status",
        "summary",
        "alarms",
        "diagnostics",
        "cfg",
        "block_states",
        "trace",
    }
    missing = required.difference(result)
    if missing:
        raise ImportErrorValue(f"result missing fields: {', '.join(sorted(missing))}")
    expected = {
        "run_id": run.id,
        "detector_id": run.detector_id,
        "rule_pack_id": run.rule_pack_id,
        "analyzer_version": run.analyzer_version,
        "schema_version": run.result_schema_version,
    }
    for key, value in expected.items():
        if str(result.get(key)) != str(value):
            raise ImportErrorValue(f"result {key} does not match run snapshot")
    if result.get("detector_version") and result["detector_version"] != run.detector_version:
        raise ImportErrorValue("result detector_version does not match run snapshot")
    if result.get("rule_pack_version") and result["rule_pack_version"] != run.rule_pack_version:
        raise ImportErrorValue("result rule_pack_version does not match run snapshot")
    if result["status"] not in {"succeeded", "unsupported", "error"}:
        raise ImportErrorValue("invalid result status")
    if rule_pack is not None:
        families = set(json.loads(rule_pack.supported_families_json))
        cwes = set(json.loads(rule_pack.supported_cwes_json))
        kinds = set(json.loads(rule_pack.supported_violation_kinds_json))
        for alarm in result.get("alarms", []):
            if (
                alarm.get("detector_id") != run.detector_id
                or alarm.get("rule_pack_id") != run.rule_pack_id
            ):
                raise ImportErrorValue("alarm detector/rule pack mismatch")
            if (
                alarm.get("cwe_id") not in cwes
                or (alarm.get("family") is not None and alarm.get("family") not in families)
                or alarm.get("violation_kind") not in kinds
            ):
                raise ImportErrorValue("alarm value is outside rule pack declaration")
            if (
                alarm.get("severity") not in {"definite", "possible"}
                or int(alarm.get("access_size", 0)) < 0
            ):
                raise ImportErrorValue("invalid alarm severity or access size")
        for diagnostic in result.get("diagnostics", []):
            if diagnostic.get("severity") not in {
                "unknown_effect",
                "unsupported",
                "error",
            }:
                raise ImportErrorValue("invalid diagnostic severity")


def import_result(
    db: Session, run: AnalysisRun, result: dict[str, Any], rule_pack: Any | None = None
) -> None:
    validate_result(result, run, rule_pack)
    run_file_ids = json.loads(run.file_ids_json or "[]")
    default_source_file_id = run_file_ids[0] if len(run_file_ids) == 1 else None
    # Removing only this run's children makes retries deterministic and atomic.
    for model in (Alarm, DiagnosticRow, RunArtifact, CfgNode, CfgEdge, TraceEvent):
        db.execute(delete(model).where(model.run_id == run.id))
    for item in result.get("alarms", []):
        ol, ou = _interval(item.get("object_size"))
        pl, pu = _interval(item.get("offset"))
        db.add(
            Alarm(
                run_id=run.id,
                alarm_key=item.get("alarm_key", ""),
                detector_id=item.get("detector_id", run.detector_id),
                detector_version=item.get("detector_version", run.detector_version),
                rule_pack_id=item.get("rule_pack_id", run.rule_pack_id),
                rule_pack_version=item.get("rule_pack_version", run.rule_pack_version),
                cwe_id=item["cwe_id"],
                family=item.get("family"),
                violation_kind=item["violation_kind"],
                severity=item["severity"],
                function_name=item.get("function_name"),
                block_id=item.get("block_id"),
                instruction_id=item.get("instruction_id"),
                instruction_text=item.get("instruction_text"),
                source_file_id=item.get("source_file_id") or default_source_file_id,
                source_line=(item.get("source_location") or {}).get("line")
                if isinstance(item.get("source_location"), dict)
                else item.get("source_line"),
                memory_object_id=item["memory_object_id"],
                object_name=item.get("object_name"),
                object_size_lower=ol,
                object_size_upper=ou,
                offset_lower=pl,
                offset_upper=pu,
                access_size=item.get("access_size", item.get("access_size_bytes", 0)),
                safe_condition=item.get("safe_condition", ""),
                message=item.get("message", ""),
                reason_json=json.dumps(item.get("reason", []), ensure_ascii=False),
                evidence_json=json.dumps(item.get("evidence", {}), ensure_ascii=False),
            )
        )
    for item in result.get("diagnostics", []):
        location = item.get("location")
        db.add(
            DiagnosticRow(
                run_id=run.id,
                diagnostic_id=item.get("diagnostic_id"),
                code=item["code"],
                severity=item["severity"],
                message=item["message"],
                impact=item["impact"],
                location_json=json.dumps(location, ensure_ascii=False),
                function_name=item.get("function_name"),
                block_id=item.get("block_id"),
                instruction_id=item.get("instruction_id"),
                source_file_id=item.get("source_file_id"),
                source_line=(location or {}).get("line")
                if isinstance(location, dict)
                else item.get("source_line"),
            )
        )
    cfg = result.get("cfg", [])
    if isinstance(cfg, dict):
        nodes, edges = cfg.get("nodes", []), cfg.get("edges", [])
    else:
        nodes, edges = [], cfg
    for item in nodes:
        db.add(
            CfgNode(
                run_id=run.id,
                function_name=item.get("function_name", item.get("function", "")),
                block_id=str(item.get("block_id", item.get("id", ""))),
                label=item.get("label"),
                entry_state_json=json.dumps(item.get("entry_state", {}), ensure_ascii=False),
                exit_state_json=json.dumps(item.get("exit_state", {}), ensure_ascii=False),
            )
        )
    for item in edges:
        db.add(
            CfgEdge(
                run_id=run.id,
                function_name=item.get("function_name", item.get("function", "")),
                source_block=str(item.get("source_block", item.get("source", ""))),
                target_block=str(item.get("target_block", item.get("target", ""))),
                condition=str(item.get("condition")) if item.get("condition") is not None else None,
                polarity=item.get("polarity"),
            )
        )
    for item in result.get("block_states", []):
        db.add(
            CfgNode(
                run_id=run.id,
                function_name=item.get("function_name", ""),
                block_id=str(item.get("block_id", "")),
                label=None,
                entry_state_json=json.dumps(item.get("entry_state", {}), ensure_ascii=False),
                exit_state_json=json.dumps(item.get("exit_state", {}), ensure_ascii=False),
            )
        )
    for item in result.get("trace", []):
        db.add(
            TraceEvent(
                run_id=run.id,
                sequence_no=int(item.get("sequence_no", 0)),
                event_type=item.get("event_type", "instruction"),
                function_name=item.get("function_name"),
                block_id=item.get("block_id"),
                instruction_id=item.get("instruction_id"),
                before_state_json=json.dumps(item.get("before_state", {}), ensure_ascii=False),
                after_state_json=json.dumps(item.get("after_state", {}), ensure_ascii=False),
                explanation=item.get("explanation"),
            )
        )
    for item in result.get("artifacts", []):
        content = item.get("content", "")
        db.add(
            RunArtifact(
                run_id=run.id,
                kind=item.get("kind", "ir"),
                source_file_id=item.get("source_file_id"),
                function_name=item.get("function_name"),
                content=content,
                sha256=item.get("sha256", ""),
            )
        )
    db.commit()
