import asyncio
import hashlib
import json
import shlex
import shutil
import tempfile
import weakref
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import AnalysisRun, RulePack, SourceFile

from .event_bus import event_bus
from .result_importer import import_result
from .toolchain import inspect_toolchain

_semaphores: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


async def _run_slot():
    loop = asyncio.get_running_loop()
    semaphore = _semaphores.get(loop)
    if semaphore is None:
        semaphore = asyncio.Semaphore(max(1, settings.max_concurrent_runs))
        _semaphores[loop] = semaphore
    await semaphore.acquire()
    return semaphore


def transition(run: AnalysisRun, status: str) -> None:
    allowed = {
        "queued": {"running", "cancelled", "failed"},
        "running": {"succeeded", "failed", "cancelled"},
        "succeeded": set(),
        "failed": set(),
        "cancelled": set(),
    }
    if status not in allowed.get(run.status, set()):
        raise ValueError(f"invalid run transition {run.status} -> {status}")
    run.status = status
    if status == "running":
        run.started_at = datetime.now(timezone.utc)
        run.progress = max(run.progress, 5)
    if status in {"succeeded", "failed", "cancelled"}:
        run.finished_at = datetime.now(timezone.utc)
        run.progress = 100 if status == "succeeded" else run.progress


async def execute_run(
    run_id: str,
    db_factory,
    rule_pack: RulePack | None = None,
    fixture: Path | None = None,
) -> None:
    db: Session = db_factory()
    run = db.get(AnalysisRun, run_id)
    if not run or run.status != "queued":
        db.close()
        return
    slot = None
    try:
        slot = await _run_slot()
        transition(run, "running")
        db.commit()
        await event_bus.publish(run.id, "run.started", {"run_id": run.id})
        with tempfile.TemporaryDirectory(prefix="tea121-") as tmp:
            output_path = Path(tmp) / "result.json"
            process_log = ""
            toolchain = inspect_toolchain()
            fixture_data = None
            if fixture:
                fixture_data = json.loads(fixture.read_text(encoding="utf-8"))
            fixture_is_result = bool(
                fixture_data and "analyzer_version" in fixture_data and "status" in fixture_data
            )
            if fixture_is_result:
                result = fixture_data
                result["run_id"] = run.id
            elif not toolchain.available:
                result = {
                    "schema_version": run.result_schema_version,
                    "run_id": run.id,
                    "analyzer_version": run.analyzer_version,
                    "detector_id": run.detector_id,
                    "detector_version": run.detector_version,
                    "rule_pack_id": run.rule_pack_id,
                    "rule_pack_version": run.rule_pack_version,
                    "status": "unsupported",
                    "summary": {
                        "alarm_count": 0,
                        "diagnostic_count": 1,
                        "unsupported_count": 1,
                        "error_count": 0,
                    },
                    "alarms": [],
                    "diagnostics": [
                        {
                            "diagnostic_id": "toolchain-1",
                            "code": "ANALYZER_UNAVAILABLE",
                            "severity": "unsupported",
                            "message": "tea121 analyzer command is not available",
                            "impact": "analysis cannot start until TEA121_ANALYZER_COMMAND is installed",
                        }
                    ],
                    "artifacts": [],
                    "cfg": [],
                    "block_states": [],
                    "trace": [],
                }
            elif fixture:
                cmd = _analyzer_cmd() + [
                    "analyze",
                    str(fixture),
                    "--format",
                    "json",
                    "--output",
                    str(output_path),
                    "--mode",
                    run.mode,
                ]
                stdout, stderr, returncode = await _invoke_analyzer(cmd)
                process_log = _process_log(cmd, returncode, stdout, stderr)
                if not output_path.exists():
                    raise RuntimeError(stderr or stdout or "analyzer produced no result")
                result = json.loads(output_path.read_text(encoding="utf-8"))
                result["run_id"] = run.id
            else:
                file_ids = json.loads(run.file_ids_json or "[]")
                source = db.get(SourceFile, file_ids[0]) if file_ids else None
                suffix = Path(source.path).suffix if source else ".json"
                input_path = Path(tmp) / ("input" + (suffix or ".c"))
                input_path.write_text(source.content if source else "{}", encoding="utf-8")
                cmd = _analyzer_cmd() + [
                    "analyze",
                    str(input_path),
                    "--format",
                    "json",
                    "--output",
                    str(output_path),
                    "--mode",
                    run.mode,
                ]
                stdout, stderr, returncode = await _invoke_analyzer(cmd)
                process_log = _process_log(cmd, returncode, stdout, stderr)
                if not output_path.exists():
                    raise RuntimeError(stderr or stdout or "analyzer produced no result")
                result = json.loads(output_path.read_text(encoding="utf-8"))
            # The backend owns the public run resource. Analyzer-generated IDs
            # are local execution IDs and must be rebound before import.
            result["run_id"] = run.id
            # Keep immutable input snapshots queryable with the run, even when
            # the analyzer only emits CFG/trace data.
            source_artifacts = []
            for file_id in json.loads(run.file_ids_json or "[]"):
                source = db.get(SourceFile, file_id)
                if source:
                    source_artifacts.append(
                        {
                            "kind": "source",
                            "source_file_id": source.id,
                            "content": source.content,
                            "sha256": source.sha256,
                        }
                    )
            result["artifacts"] = list(result.get("artifacts", [])) + source_artifacts
            if process_log:
                result["artifacts"].append(
                    {
                        "kind": "analyzer_log",
                        "content": process_log,
                        "sha256": hashlib.sha256(process_log.encode()).hexdigest(),
                    }
                )
            import_result(db, run, result, rule_pack)
        # Unsupported findings are a completed analysis with diagnostics; only
        # an analyzer error maps to the run-level failed state.
        transition(run, "failed" if result.get("status") == "error" else "succeeded")
        run.error_message = "analyzer returned error" if run.status == "failed" else None
        db.commit()
        for trace in run.trace_events:
            await event_bus.publish(
                run.id,
                "trace.event",
                {
                    "id": trace.id,
                    "sequence_no": trace.sequence_no,
                    "event_type": trace.event_type,
                    "function_name": trace.function_name,
                    "block_id": trace.block_id,
                    "instruction_id": trace.instruction_id,
                },
            )
        for alarm in run.alarms:
            await event_bus.publish(
                run.id, "alarm.created", {"id": alarm.id, "severity": alarm.severity}
            )
        for diagnostic in run.diagnostics:
            await event_bus.publish(
                run.id,
                "diagnostic.created",
                {"id": diagnostic.id, "severity": diagnostic.severity},
            )
        await event_bus.publish(
            run.id,
            "run.completed" if run.status == "succeeded" else "run.failed",
            {"run_id": run.id, "status": run.status},
        )
    except asyncio.CancelledError:
        db.rollback()
        run = db.get(AnalysisRun, run_id)
        if run and run.status in {"queued", "running"}:
            transition(run, "cancelled")
            db.commit()
            await event_bus.publish(run.id, "run.cancelled", {"run_id": run.id})
    except Exception as exc:
        db.rollback()
        run = db.get(AnalysisRun, run_id)
        if run and run.status in {"queued", "running"}:
            transition(run, "failed")
            run.error_message = str(exc)
            db.commit()
            await event_bus.publish(run.id, "run.failed", {"run_id": run.id, "error": str(exc)})
    finally:
        if slot is not None:
            slot.release()
        db.close()


def _analyzer_cmd() -> list[str]:
    parts = shlex.split(settings.analyzer_command)
    if len(parts) == 1 and shutil.which(parts[0]) is None:
        local = Path(__file__).resolve().parents[3] / "backend" / ".venv" / "bin" / parts[0]
        if local.exists():
            return [str(local)]
    return parts


async def _invoke_analyzer(cmd: list[str]) -> tuple[str, str, int]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=settings.analyzer_timeout_seconds
        )
    except TimeoutError as exc:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except TimeoutError:
            proc.kill()
            await proc.wait()
        raise RuntimeError(
            f"analyzer timed out after {settings.analyzer_timeout_seconds:g} seconds"
        ) from exc
    except asyncio.CancelledError:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except TimeoutError:
            proc.kill()
            await proc.wait()
        raise
    return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode


def _process_log(cmd: list[str], returncode: int, stdout: str, stderr: str) -> str:
    return json.dumps(
        {"argv": cmd, "returncode": returncode, "stdout": stdout, "stderr": stderr},
        ensure_ascii=False,
        indent=2,
    )
