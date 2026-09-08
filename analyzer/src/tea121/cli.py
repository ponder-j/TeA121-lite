from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tea121 import __version__
from tea121.analysis import AnalysisConfig, AnalysisEngine
from tea121.frontend import FrontendError, load_input
from tea121.ir import load_module
from tea121.report import build_result, result_to_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tea121", description="Explainable CWE-121 MiniIR analyzer")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="analyze a MiniIR JSON module")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--format", choices=("text", "json"), default="text")
    analyze.add_argument("--output", type=Path)
    analyze.add_argument("--mode", choices=("normal", "trace"), default="normal")
    analyze.add_argument("--widen-after", type=int, default=3)
    args = parser.parse_args(argv)
    if args.command == "analyze":
        try:
            module = load_input(args.input)
        except FrontendError as exc:
            result = build_result(AnalysisEngine({"schema_version": "1.0.0", "functions": []}).run(), input_path=str(args.input), status="error")
            result["diagnostics"] = [{"diagnostic_id": "d-1", "code": exc.code, "severity": exc.severity, "message": str(exc), "impact": exc.impact, "location": None}]
            result["status"] = exc.severity if exc.severity in {"unsupported", "error"} else "error"
            result["summary"].update(alarm_count=0, diagnostic_count=1, unsupported_count=int(exc.severity == "unsupported"), error_count=int(exc.severity == "error"))
            return _emit(result, args)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            result = build_result(AnalysisEngine({"schema_version": "1.0.0", "functions": []}).run(), input_path=str(args.input), status="error")
            result["diagnostics"] = [{"diagnostic_id": "d-1", "code": "INVALID_INPUT", "severity": "error", "message": str(exc), "impact": "MiniIR could not be loaded", "location": None}]
            result["summary"].update(alarm_count=0, diagnostic_count=1, error_count=1)
            return _emit(result, args)
        config = AnalysisConfig(mode=args.mode, widen_after=max(1, args.widen_after))
        result = build_result(AnalysisEngine(module, config).run(), input_path=str(args.input), config={"mode": args.mode, "widen_after": config.widen_after})
        result["artifacts"] = module.get("_artifacts", [])
        return _emit(result, args)
    return 2


def _emit(result, args) -> int:
    rendered = json.dumps(result, ensure_ascii=False, indent=2) if args.format == "json" else result_to_text(result)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        sys.stdout.write(rendered + "\n")
    return 0 if result["status"] != "error" else 1


if __name__ == "__main__":
    raise SystemExit(main())
