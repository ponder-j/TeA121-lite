"""Batch-evaluate every Juliet CWE-121 suite under a dataset root.

The legacy ``evaluate_juliet.py`` runner intentionally evaluates one suite
directory at a time. This wrapper keeps that runner as the single source of
truth for compilation, extraction, analysis, and pair classification, while
adding deterministic suite discovery and aggregate TP/FP/FN/TN metrics.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable

# ``evaluate_juliet`` is a sibling tool module, not an installed package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_juliet import (  # noqa: E402
    CaseFiles,
    _evaluate_case,
    _summary,
    discover_cases,
)

CWE_DIR = "CWE121_Stack_Based_Buffer_Overflow"
SUITE_NAME = re.compile(r"^s\d{2}$")


def discover_suites(root: Path, selected: Iterable[str] = ()) -> list[Path]:
    """Return deterministic CWE-121 suite directories.

    Accepted roots are the Juliet ``testcases`` directory, the CWE-121
    directory itself, or one concrete ``sNN`` directory.
    """
    root = root.resolve()
    if root.is_dir() and SUITE_NAME.fullmatch(root.name):
        candidates = [root]
    else:
        cwe_root = root / CWE_DIR if (root / CWE_DIR).is_dir() else root
        candidates = sorted(
            path for path in cwe_root.iterdir()
            if path.is_dir() and SUITE_NAME.fullmatch(path.name)
        )
    wanted = set(selected)
    if wanted:
        candidates = [path for path in candidates if path.name in wanted]
    missing = wanted - {path.name for path in candidates}
    if missing:
        raise ValueError(f"unknown suite(s): {', '.join(sorted(missing))}")
    if not candidates:
        raise ValueError(f"no sNN suites found under {root}")
    return candidates


def collect_cases(suites: Iterable[Path], flow: str | None = None) -> list[tuple[str, CaseFiles]]:
    collected: list[tuple[str, CaseFiles]] = []
    for suite in suites:
        collected.extend((suite.name, case) for case in discover_cases(suite, flow))
    return sorted(collected, key=lambda item: (item[0], item[1].case_name))


def score_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Return aggregate and supported-only TP/FP/FN/TN metrics."""
    summary = _summary(cases)
    tp = sum(case["bad"]["outcome"] == "alarm" for case in cases)
    tn = sum(case["good"]["outcome"] == "clean" for case in cases)
    fp = sum(case["good"]["outcome"] == "alarm" for case in cases)
    fn = sum(case["bad"]["outcome"] == "clean" for case in cases)
    unsupported_sides = sum(
        outcome == "unsupported"
        for case in cases
        for outcome in (case["bad"]["outcome"], case["good"]["outcome"])
    )
    error_sides = sum(
        outcome == "error"
        for case in cases
        for outcome in (case["bad"]["outcome"], case["good"]["outcome"])
    )
    supported_positive = tp + fn
    supported_negative = tn + fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    supported_recall = tp / supported_positive if supported_positive else 0.0
    supported_specificity = tn / supported_negative if supported_negative else 0.0

    def rounded(value: float) -> float:
        return round(value, 6)

    summary["binary_confusion"] = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "unsupported": unsupported_sides,
        "error": error_sides,
    }
    summary["binary_metrics"] = {
        "precision": rounded(precision),
        "supported_recall": rounded(supported_recall),
        "supported_specificity": rounded(supported_specificity),
        "supported_balanced_accuracy": rounded((supported_recall + supported_specificity) / 2),
        "conservative_recall": rounded(tp / len(cases) if cases else 0.0),
        "conservative_specificity": rounded(tn / len(cases) if cases else 0.0),
    }
    by_suite: dict[str, Any] = {}
    for suite in sorted({case["suite"] for case in cases}):
        by_suite[suite] = score_summary_without_suites(
            [case for case in cases if case["suite"] == suite]
        )
    summary["by_suite"] = by_suite
    return summary


def score_summary_without_suites(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Score a subset without recursively embedding another by_suite matrix."""
    summary = _summary(cases)
    tp = sum(case["bad"]["outcome"] == "alarm" for case in cases)
    tn = sum(case["good"]["outcome"] == "clean" for case in cases)
    fp = sum(case["good"]["outcome"] == "alarm" for case in cases)
    fn = sum(case["bad"]["outcome"] == "clean" for case in cases)
    unsupported_sides = sum(
        outcome == "unsupported"
        for case in cases
        for outcome in (case["bad"]["outcome"], case["good"]["outcome"])
    )
    error_sides = sum(
        outcome == "error"
        for case in cases
        for outcome in (case["bad"]["outcome"], case["good"]["outcome"])
    )
    supported_positive = tp + fn
    supported_negative = tn + fp
    recall = tp / supported_positive if supported_positive else 0.0
    specificity = tn / supported_negative if supported_negative else 0.0
    summary["binary_confusion"] = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "unsupported": unsupported_sides,
        "error": error_sides,
    }
    summary["binary_metrics"] = {
        "precision": round(tp / (tp + fp), 6) if tp + fp else 0.0,
        "supported_recall": round(recall, 6),
        "supported_specificity": round(specificity, 6),
        "supported_balanced_accuracy": round((recall + specificity) / 2, 6),
        "conservative_recall": round(tp / len(cases), 6) if cases else 0.0,
        "conservative_specificity": round(tn / len(cases), 6) if cases else 0.0,
    }
    return summary


def write_csv(path: Path, cases: list[dict[str, Any]]) -> None:
    fields = [
        "suite",
        "case_name",
        "family",
        "variant",
        "classification",
        "bad_outcome",
        "good_outcome",
        "bad_severity",
        "good_severity",
        "bad_diagnostic_code",
        "good_diagnostic_code",
        "bad_duration_ms",
        "good_duration_ms",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for case in cases:
            bad_codes = sorted({
                str(item.get("code")) for item in (case["bad"].get("result") or {}).get("diagnostics") or []
                if item.get("code")
            })
            good_codes = sorted({
                str(item.get("code")) for item in (case["good"].get("result") or {}).get("diagnostics") or []
                if item.get("code")
            })
            writer.writerow({
                "suite": case["suite"],
                "case_name": case["case_name"],
                "family": case.get("family"),
                "variant": case.get("variant"),
                "classification": case["classification"],
                "bad_outcome": case["bad"]["outcome"],
                "good_outcome": case["good"]["outcome"],
                "bad_severity": case["bad"].get("analyzer_status"),
                "good_severity": case["good"].get("analyzer_status"),
                "bad_diagnostic_code": "|".join(bad_codes),
                "good_diagnostic_code": "|".join(good_codes),
                "bad_duration_ms": case["bad"].get("duration_ms"),
                "good_duration_ms": case["good"].get("duration_ms"),
            })


def evaluate_case(case: CaseFiles, suite: str, temp_root: Path, include_dirs: tuple[Path, ...], defines: tuple[str, ...], timeout: float, keep_artifacts: bool) -> dict[str, Any]:
    record = _evaluate_case(case, temp_root, include_dirs, defines, timeout, keep_artifacts, include_raw_result=False)
    record["suite"] = suite
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Juliet testcases root, CWE-121 root, or one sNN directory")
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path)
    parser.add_argument("--suite", action="append", default=[], help="restrict to a suite such as s01 (repeatable)")
    parser.add_argument("--flow", help="only evaluate one flow variant, e.g. 01 or 51")
    parser.add_argument("--limit", type=int, help="evaluate at most N sorted cases across all suites")
    parser.add_argument("--include-dir", type=Path, action="append", default=[])
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--jobs", type=int, default=1, help="parallel case workers")
    args = parser.parse_args(argv)

    try:
        suites = discover_suites(args.root, args.suite)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    cases = collect_cases(suites, args.flow)
    if args.limit is not None:
        cases = cases[: max(0, args.limit)]

    run_id = f"juliet-cwe121-{uuid.uuid4().hex}"
    temporary = None
    if args.keep_artifacts:
        temp_root = args.artifact_dir or args.output.with_suffix(".artifacts")
        temp_root.mkdir(parents=True, exist_ok=True)
    else:
        temporary = tempfile.TemporaryDirectory(prefix="tea121-cwe121-")
        temp_root = Path(temporary.name)

    include_dirs = tuple(args.include_dir)
    defines = tuple(args.define)
    evaluated: list[dict[str, Any]] = []
    try:
        worker_count = max(1, args.jobs)
        if worker_count == 1:
            evaluated.extend(
                evaluate_case(case, suite, temp_root, include_dirs, defines, args.timeout, args.keep_artifacts)
                for suite, case in cases
            )
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                evaluated.extend(executor.map(
                    lambda item: evaluate_case(item[1], item[0], temp_root, include_dirs, defines, args.timeout, args.keep_artifacts),
                    cases,
                ))
    finally:
        if temporary is not None:
            temporary.cleanup()

    result = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "dataset": "Juliet CWE-121 all suites",
        "root": str(args.root),
        "config": {
            "suites": [suite.name for suite in suites],
            "flow": args.flow,
            "limit": args.limit,
            "timeout": args.timeout,
            "jobs": max(1, args.jobs),
            "include_dirs": [str(path) for path in include_dirs],
            "defines": list(defines),
            "keep_artifacts": args.keep_artifacts,
            "artifact_dir": str(args.artifact_dir or args.output.with_suffix(".artifacts")) if args.keep_artifacts else None,
        },
        "cases": evaluated,
        "summary": score_summary(evaluated),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.csv_output:
        write_csv(args.csv_output, evaluated)
    print(json.dumps({
        "status": "succeeded",
        "run_id": run_id,
        "total_cases": len(evaluated),
        "output": str(args.output),
        "summary": result["summary"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
