"""Create the deterministic demo-cwe121 project and a completed fixture run."""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.catalog.detectors import seed as seed_detector
from app.catalog.rule_packs import seed as seed_rule_pack
from app.config import settings
from app.db.models import AnalysisRun, Project, RunFile, SourceFile
from app.db.session import SessionLocal, init_db
from app.services.run_service import execute_run


def main() -> None:
    init_db()
    db = SessionLocal()
    detector = seed_detector(db)
    pack = seed_rule_pack(db)
    project = Project(name="demo-cwe121", description="tea121-lite deterministic backend demo")
    db.add(project)
    db.flush()
    source = SourceFile(
        project_id=project.id,
        path="demo.c",
        language="c",
        content="int main(void) { char buffer[8]; buffer[8] = 1; return 0; }\n",
        sha256="",
        size_bytes=0,
    )
    import hashlib

    source.sha256 = hashlib.sha256(source.content.encode()).hexdigest()
    source.size_bytes = len(source.content.encode())
    db.add(source)
    run = AnalysisRun(
        project_id=project.id,
        detector_id=detector.id,
        detector_version=detector.version,
        rule_pack_id=pack.id,
        rule_pack_version=pack.version,
        analyzer_version=settings.analyzer_version,
        result_schema_version="1.0.0",
        mode="normal",
        file_ids_json=json.dumps([]),
        config_json=json.dumps({"fixture_path": "analyzer/tests/fixtures/miniir/oob_store.json"}),
    )
    db.add(run)
    db.flush()
    run.file_ids_json = json.dumps([source.id])
    db.add(RunFile(run_id=run.id, source_file_id=source.id, variant="single"))
    db.commit()
    run_id, project_id = run.id, project.id
    db.close()
    fixture = Path(__file__).resolve().parents[2] / "analyzer/tests/fixtures/miniir/oob_store.json"
    asyncio.run(execute_run(run_id, SessionLocal, pack, fixture))
    print(json.dumps({"project_id": project_id, "run_id": run_id}, indent=2))


if __name__ == "__main__":
    main()
