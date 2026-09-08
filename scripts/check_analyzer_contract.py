"""Dependency-free sanity checks for the shared analyzer fixtures."""

from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    examples = sorted((root / "contracts" / "examples").glob("analyzer-result.*.json"))
    required = {"schema_version", "run_id", "analyzer_version", "detector_id", "rule_pack_id", "status", "summary", "alarms", "diagnostics", "cfg", "block_states", "trace"}
    for path in examples:
        value = json.loads(path.read_text(encoding="utf-8"))
        missing = required - value.keys()
        if missing:
            raise SystemExit(f"{path}: missing {sorted(missing)}")
        if value["status"] not in {"succeeded", "unsupported", "error"}:
            raise SystemExit(f"{path}: invalid status")
        for alarm in value["alarms"]:
            if alarm.get("severity") not in {"definite", "possible"}:
                raise SystemExit(f"{path}: invalid alarm severity")
        for diagnostic in value["diagnostics"]:
            if diagnostic.get("severity") not in {"unknown_effect", "unsupported", "error"}:
                raise SystemExit(f"{path}: invalid diagnostic severity")
    print(f"checked {len(examples)} analyzer result fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
