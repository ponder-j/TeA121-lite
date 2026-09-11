from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from tea121 import __version__
from tea121.analysis.models import (
    DETECTOR_ID,
    DETECTOR_VERSION,
    RULE_PACK_ID,
    RULE_PACK_VERSION,
)
from tea121.analysis.solver import AnalysisOutput


def build_result(output: AnalysisOutput, *, run_id: str | None = None, input_path: str | None = None, config: dict[str, Any] | None = None, status: str | None = None) -> dict[str, Any]:
    if status is None:
        status = "error" if any(d["severity"] == "error" for d in output.diagnostics) else "unsupported" if any(d["severity"] == "unsupported" for d in output.diagnostics) else "succeeded"
    return {
        "schema_version": "1.0.0",
        "run_id": run_id or str(uuid4()),
        "analyzer_version": __version__,
        "detector_id": DETECTOR_ID,
        "detector_version": DETECTOR_VERSION,
        "rule_pack_id": RULE_PACK_ID,
        "rule_pack_version": RULE_PACK_VERSION,
        "status": status,
        "summary": {"alarm_count": len(output.alarms), "diagnostic_count": len(output.diagnostics), "unsupported_count": sum(d["severity"] == "unsupported" for d in output.diagnostics), "error_count": sum(d["severity"] == "error" for d in output.diagnostics)},
        "inputs": [{"path": input_path}] if input_path else [],
        "config": config or {},
        "alarms": output.alarms,
        "diagnostics": output.diagnostics,
        "artifacts": [],
        "cfg": output.cfg,
        "cfg_nodes": output.cfg_nodes,
        "block_states": output.block_states,
        "trace": output.trace,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def result_to_text(result: dict[str, Any]) -> str:
    lines = [f"tea121 {result['status']} | alarms={result['summary']['alarm_count']} diagnostics={result['summary']['diagnostic_count']}"]
    for alarm in result["alarms"]:
        kind = alarm["violation_kind"]
        target = f"{alarm['function_name']} {alarm['instruction_id'] or '<instruction>'}"
        if kind == "integer_overflow":
            lines.append(f"{alarm['severity'].upper()}: {target} value={_fmt(alarm['offset'])} type_range={_fmt(alarm['object_size'])} width={alarm['access_size']} ({kind}, {alarm['cwe_id']})")
        else:
            obj = alarm["memory_object_id"]
            lines.append(f"{alarm['severity'].upper()}: {target} object={obj} offset={_fmt(alarm['offset'])} size={_fmt(alarm['object_size'])} width={alarm['access_size']} ({kind})")
    for diagnostic in result["diagnostics"]:
        lines.append(f"{diagnostic['severity'].upper()}: {diagnostic['code']} {diagnostic['message']}")
    return "\n".join(lines)


def _fmt(interval: dict[str, Any]) -> str:
    if interval.get("is_bottom"):
        return "Bottom"
    return f"[{interval.get('lower', '-inf')},{interval.get('upper', '+inf')}]"
