"""Run a reproducible four-state evaluation over a Juliet flow variant.

Dataset naming is used only at the manifest boundary to find files belonging to
one flow variant. It never changes analyzer semantics.
"""

from __future__ import annotations

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
NAME = re.compile(
    r"^(?P<base>.+)_(?P<flow>\d{2})(?P<part>[a-z])?(?P<role>_(?:bad|goodB2G|goodG2B))?\.(?P<ext>c|cc|cpp|cxx|h)$"
)
OUTCOMES = ("alarm", "clean", "unsupported", "error")


@dataclass(frozen=True)
class CaseFiles:
    case_name: str
    family: str | None
    variant: str
    files: tuple[Path, ...]
    bad_files: tuple[Path, ...]
    good_files: tuple[Path, ...]


def _parse(path: Path) -> tuple[str, str, str, str | None] | None:
    match = NAME.match(path.name)
    if not match:
        return None
    return match.group("base"), match.group("flow"), match.group("part") or "", match.group("role")


def discover_cases(root: Path, flow: str | None = None) -> list[CaseFiles]:
    """Discover cases from either an s01 directory or its parent."""
    source_root = root / "s01" if (root / "s01").is_dir() else root
    parsed: dict[tuple[str, str], list[tuple[Path, str, str | None]]] = {}
    for path in sorted(source_root.iterdir() if source_root.exists() else ()):
        if not path.is_file():
            continue
        item = _parse(path)
        if not item:
            continue
        base, number, part, role = item
        if flow and number != flow:
            continue
        parsed.setdefault((base, number), []).append((path, part, role))

    cases: list[CaseFiles] = []
    for (base, number), entries in sorted(parsed.items()):
        files = tuple(item[0] for item in entries)
        source_entries = [item for item in entries if item[0].suffix.lower() in SOURCE_SUFFIXES]
        role_entries = [item for item in source_entries if item[2]]
        if role_entries:
            bad = tuple(item[0] for item in source_entries if item[2] == "_bad" or not item[2])
            good = tuple(item[0] for item in source_entries if item[2] in {"_goodB2G", "_goodG2B"} or not item[2])
        else:
            bad = good = tuple(item[0] for item in source_entries)
        family = base.rsplit("__", 1)[-1] if "__" in base else None
        cases.append(CaseFiles(f"{base}_{number}", family, number, files, bad, good))
    return cases


def classify_result(result: dict[str, Any] | None, process_error: bool = False) -> str:
    """Map one analyzer result to alarm/clean/unsupported/error."""
    if process_error or not result:
        return "error"
    diagnostics = result.get("diagnostics") or []
    severities = {item.get("severity") for item in diagnostics}
    if result.get("status") == "error" or "error" in severities:
        return "error"
    # Unknown effects cannot establish that a side is clean.
    if result.get("status") == "unsupported" or severities & {"unsupported", "unknown_effect"}:
        return "unsupported"
    return "alarm" if result.get("alarms") else "clean"


def classify_pair(bad: str, good: str) -> str:
    if bad == "error" or good == "error":
        return "error"
    if bad == "unsupported" or good == "unsupported":
        return "unsupported"
    if bad == "alarm" and good == "clean":
        return "correct"
    if bad == "clean" and good == "alarm":
        return "inverted"
    if bad == "clean" and good == "clean":
        return "false_negative"
    if bad == "alarm" and good == "alarm":
        return "false_positive"
    return "unsupported"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tool(name: str, fallback: str | None = None) -> str | None:
    return os.environ.get(name) or shutil.which(fallback or name.lower())


def _run(command: list[str], timeout: float) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    try:
        return subprocess.run(command, text=True, capture_output=True, check=False, timeout=timeout), None
    except subprocess.TimeoutExpired as exc:
        return None, f"timeout after {timeout:g}s: {exc}"
    except OSError as exc:
        return None, str(exc)


def analyze_side(
    files: Iterable[Path], macro: str, workdir: Path, include_dirs: tuple[Path, ...],
    defines: tuple[str, ...], timeout: float, keep_artifacts: bool,
    input_files: Iterable[Path] | None = None,
) -> dict[str, Any]:
    """Compile, normalize, extract, and analyze one side."""
    sources = tuple(files)
    started = time.monotonic()
    workdir.mkdir(parents=True, exist_ok=True)
    clang = _tool("TEA121_CLANG", "clang-15") or _tool("TEA121_CLANG", "clang")
    opt = _tool("TEA121_OPT", "opt-15") or _tool("TEA121_OPT", "opt")
    extractor = _tool("TEA121_EXTRACTOR", "tea121-extract")
    tea121 = shutil.which("tea121")
    metadata: dict[str, Any] = {
        "outcome": "error", "sources": [str(path) for path in sources],
        "inputs": [{"path": str(path), "sha256": _sha256(path)} for path in (input_files or sources)],
        "macro": macro, "command": [], "duration_ms": 0,
    }
    if not sources:
        metadata.update(outcome="unsupported", code="NO_SOURCE_FILES", message="case has no compilable sources")
        return metadata
    if not clang or not extractor or not tea121:
        metadata.update(outcome="unsupported", code="LLVM_TOOLCHAIN_MISSING", message="clang, tea121-extract, or tea121 is unavailable")
        return metadata
    try:
        raw_modules: list[Path] = []
        for index, source in enumerate(sources):
            output = workdir / f"unit-{index}.ll"
            command = [clang, "-S", "-emit-llvm", "-O0", "-Xclang", "-disable-O0-optnone", "-g", f"-D{macro}"]
            command.extend(f"-D{value}" for value in defines)
            command.extend(f"-I{directory}" for directory in include_dirs)
            command.extend([str(source), "-o", str(output)])
            completed, failure = _run(command, timeout)
            metadata["command"].append(command)
            if failure or completed is None or completed.returncode:
                metadata.update(outcome="error", code="COMPILE_FAILED", message=failure or (completed.stderr.strip() if completed else "clang failed"), returncode=completed.returncode if completed else None)
                return metadata
            raw_modules.append(output)

        module = raw_modules[0]
        if len(raw_modules) > 1:
            linker = _tool("TEA121_LLVM_LINK", "llvm-link-15") or _tool("TEA121_LLVM_LINK", "llvm-link")
            if not linker:
                metadata.update(outcome="unsupported", code="LLVM_LINK_MISSING", message="llvm-link-15/llvm-link is unavailable")
                return metadata
            linked = workdir / "linked.ll"
            command = [linker, "-S", *map(str, raw_modules), "-o", str(linked)]
            completed, failure = _run(command, timeout)
            metadata["command"].append(command)
            if failure or completed is None or completed.returncode:
                metadata.update(outcome="error", code="LINK_FAILED", message=failure or (completed.stderr.strip() if completed else "llvm-link failed"), returncode=completed.returncode if completed else None)
                return metadata
            module = linked
        normalized = workdir / "normalized.ll"
        if opt:
            command = [opt, "-S", "-passes=mem2reg", str(module), "-o", str(normalized)]
            completed, failure = _run(command, timeout)
            metadata["command"].append(command)
            if failure or completed is None or completed.returncode:
                metadata.update(outcome="error", code="NORMALIZATION_FAILED", message=failure or (completed.stderr.strip() if completed else "opt failed"), returncode=completed.returncode if completed else None)
                return metadata
        else:
            normalized = module
        miniir = workdir / "module.json"
        command = [extractor, str(normalized), "-o", str(miniir)]
        completed, failure = _run(command, timeout)
        metadata["command"].append(command)
        if failure or completed is None or completed.returncode:
            metadata.update(outcome="error", code="EXTRACTION_FAILED", message=failure or (completed.stderr.strip() if completed else "extractor failed"), returncode=completed.returncode if completed else None)
            return metadata
        command = [tea121, "analyze", str(miniir), "--format", "json"]
        completed, failure = _run(command, timeout)
        metadata["command"].append(command)
        if failure or completed is None or completed.returncode not in {0, 1}:
            metadata.update(outcome="error", code="ANALYSIS_FAILED", message=failure or (completed.stderr.strip() if completed else "tea121 failed"), returncode=completed.returncode if completed else None)
            return metadata
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            metadata.update(outcome="error", code="INVALID_ANALYZER_RESULT", message=str(exc), stdout_tail=completed.stdout[-1000:])
            return metadata
        metadata.update(outcome=classify_result(result), analyzer_status=result.get("status"), alarm_count=len(result.get("alarms") or []), diagnostic_count=len(result.get("diagnostics") or []), result=result)
        if keep_artifacts:
            metadata["artifacts"] = {"module": str(miniir), "normalized_ir": str(normalized)}
        return metadata
    finally:
        metadata["duration_ms"] = round((time.monotonic() - started) * 1000, 2)


def _summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    side_counts = {outcome: 0 for outcome in OUTCOMES}
    pair_counts = {name: 0 for name in ("correct", "false_positive", "false_negative", "inverted", "unsupported", "error")}
    for case in cases:
        side_counts[case["bad"]["outcome"]] += 1
        side_counts[case["good"]["outcome"]] += 1
        pair_counts[case["classification"]] += 1
    total = len(cases)
    bad_alarm = sum(case["bad"]["outcome"] == "alarm" for case in cases)
    good_clean = sum(case["good"]["outcome"] == "clean" for case in cases)
    valid_cases = [case for case in cases if case["classification"] not in {"unsupported", "error"}]
    valid_total = len(valid_cases)
    valid_bad_alarm = sum(case["bad"]["outcome"] == "alarm" for case in valid_cases)
    valid_good_clean = sum(case["good"]["outcome"] == "clean" for case in valid_cases)
    correct_files = bad_alarm + good_clean
    def grouped(field: str) -> dict[str, Any]:
        groups: dict[str, list[dict[str, Any]]] = {}
        for case in cases:
            key = str(case.get(field) or "unclassified")
            groups.setdefault(key, []).append(case)
        output: dict[str, Any] = {}
        for key, items in sorted(groups.items()):
            counts = {name: 0 for name in pair_counts}
            for item in items:
                counts[item["classification"]] += 1
            output[key] = {"total_cases": len(items), "pair_classification": counts}
        return output
    return {
        "total_cases": total, "side_outcomes": side_counts, "pair_classification": pair_counts,
        "valid_pairs": total - pair_counts["unsupported"] - pair_counts["error"],
        "bad_recall": round(bad_alarm / total, 6) if total else 0.0,
        "good_silence_rate": round(good_clean / total, 6) if total else 0.0,
        "effective_bad_recall": round(valid_bad_alarm / valid_total, 6) if valid_total else 0.0,
        "effective_good_silence_rate": round(valid_good_clean / valid_total, 6) if valid_total else 0.0,
        "file_accuracy": round(correct_files / (2 * total), 6) if total else 0.0,
        "pair_accuracy": round(pair_counts["correct"] / total, 6) if total else 0.0,
        "conservative_bad_recall": round(bad_alarm / total, 6) if total else 0.0,
        "conservative_pair_accuracy": round(pair_counts["correct"] / total, 6) if total else 0.0,
        "by_family": grouped("family"),
        "by_variant": grouped("variant"),
    }


def write_csv(path: Path, cases: list[dict[str, Any]]) -> None:
    fields = ["case_name", "family", "variant", "classification", "bad_outcome", "good_outcome", "bad_duration_ms", "good_duration_ms"]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for case in cases:
            writer.writerow({"case_name": case["case_name"], "family": case.get("family"), "variant": case.get("variant"), "classification": case["classification"], "bad_outcome": case["bad"]["outcome"], "good_outcome": case["good"]["outcome"], "bad_duration_ms": case["bad"].get("duration_ms"), "good_duration_ms": case["good"].get("duration_ms")})


def _evaluate_case(case: CaseFiles, temp_root: Path, include_dirs: tuple[Path, ...], defines: tuple[str, ...], timeout: float, keep_artifacts: bool) -> dict[str, Any]:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", case.case_name)
    case_dir = temp_root / safe_name
    bad = analyze_side(case.bad_files, "OMITGOOD", case_dir / "bad", include_dirs, defines, timeout, keep_artifacts, case.files)
    good = analyze_side(case.good_files, "OMITBAD", case_dir / "good", include_dirs, defines, timeout, keep_artifacts, case.files)
    return {"case_name": case.case_name, "family": case.family, "variant": case.variant, "files": [str(path) for path in case.files], "bad": bad, "good": good, "classification": classify_pair(bad["outcome"], good["outcome"])}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Juliet CWE directory or its s01 directory")
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path)
    parser.add_argument("--flow", help="only evaluate one flow variant, e.g. 01 or 51")
    parser.add_argument("--limit", type=int, help="evaluate at most N cases after deterministic sorting")
    parser.add_argument("--include-dir", type=Path, action="append", default=[])
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--artifact-dir", type=Path, help="persistent directory for normalized IR and MiniIR artifacts")
    parser.add_argument("--jobs", type=int, default=1, help="parallel case workers (use 18 on the provided 18-core host)")
    args = parser.parse_args(argv)
    cases = discover_cases(args.root, args.flow)
    if args.limit is not None:
        cases = cases[: max(0, args.limit)]
    run_id = f"juliet-{uuid.uuid4().hex}"
    evaluated: list[dict[str, Any]] = []
    temporary = None
    if args.keep_artifacts:
        temp_root = args.artifact_dir or args.output.with_suffix(".artifacts")
        temp_root.mkdir(parents=True, exist_ok=True)
    else:
        temporary = tempfile.TemporaryDirectory(prefix="tea121-juliet-")
        temp_root = Path(temporary.name)
    try:
        worker_count = max(1, args.jobs)
        if worker_count == 1:
            evaluated.extend(_evaluate_case(case, temp_root, tuple(args.include_dir), tuple(args.define), args.timeout, args.keep_artifacts) for case in cases)
        else:
            # executor.map preserves sorted case order while subprocess work is
            # overlapped. Each case owns a separate artifact directory.
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                evaluated.extend(executor.map(lambda case: _evaluate_case(case, temp_root, tuple(args.include_dir), tuple(args.define), args.timeout, args.keep_artifacts), cases))
    finally:
        if temporary is not None:
            temporary.cleanup()
    result = {"schema_version": "1.0.0", "run_id": run_id, "dataset": "Juliet CWE-121 s01", "root": str(args.root), "config": {"flow": args.flow, "limit": args.limit, "timeout": args.timeout, "jobs": max(1, args.jobs), "include_dirs": [str(path) for path in args.include_dir], "defines": args.define, "keep_artifacts": args.keep_artifacts, "artifact_dir": str(args.artifact_dir or args.output.with_suffix(".artifacts")) if args.keep_artifacts else None}, "cases": evaluated, "summary": _summary(evaluated)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.csv_output:
        args.csv_output.parent.mkdir(parents=True, exist_ok=True)
        write_csv(args.csv_output, evaluated)
    print(json.dumps({"status": "succeeded", "run_id": run_id, "total_cases": len(evaluated), "output": str(args.output), "summary": result["summary"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
