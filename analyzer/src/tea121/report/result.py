from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from tea121 import __version__
from tea121.analysis.solver import AnalysisOutput


def build_result(output: AnalysisOutput, *, run_id: str | None = None, input_path: str | None = None, config: dict[str, Any] | None = None, status: str | None = None) -> dict[str, Any]:
    if status is None:
        status = "error" if any(d["severity"] == "error" for d in output.diagnostics) else "unsupported" if any(d["severity"] == "unsupported" for d in output.diagnostics) else "succeeded"
    return {
        "schema_version": "1.0.0",
        "run_id": run_id or str(uuid4()),
        "analyzer_version": __version__,
        "detector_id": "stack-bounds",
        "detector_version": "0.1.0",
        "rule_pack_id": "cwe121-core",
        "rule_pack_version": "0.1.0",
        "status": status,
        "summary": {"alarm_count": len(output.alarms), "diagnostic_count": len(output.diagnostics), "unsupported_count": sum(d["severity"] == "unsupported" for d in output.diagnostics), "error_count": sum(d["severity"] == "error" for d in output.diagnostics)},
        "inputs": [{"path": input_path}] if input_path else [],
        "config": config or {},
        "alarms": output.alarms,
        "diagnostics": output.diagnostics,
        "artifacts": [],
        "cfg": output.cfg,
        "block_states": output.block_states,
        "trace": output.trace,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def result_to_text(result: dict[str, Any]) -> str:
    lines = [f"tea121 {result['status']} | alarms={result['summary']['alarm_count']} diagnostics={result['summary']['diagnostic_count']}"]
    for alarm in result["alarms"]:
        obj = alarm["memory_object_id"]
        lines.append(f"{alarm['severity'].upper()}: {alarm['function_name']} {alarm['instruction_id'] or '<instruction>'} object={obj} offset={_fmt(alarm['offset'])} size={_fmt(alarm['object_size'])} width={alarm['access_size']} ({alarm['violation_kind']})")
    for diagnostic in result["diagnostics"]:
        lines.append(f"{diagnostic['severity'].upper()}: {diagnostic['code']} {diagnostic['message']}")
    return "\n".join(lines)


def _fmt(interval: dict[str, Any]) -> str:
    if interval.get("is_bottom"):
        return "Bottom"
    return f"[{interval.get('lower', '-inf')},{interval.get('upper', '+inf')}]"
