import json
import os
import time

os.environ.setdefault("TEA121_DATABASE_URL", "sqlite:////tmp/tea121-backend-pytest.db")
os.environ.setdefault("TEA121_STORAGE_DIR", "/tmp/tea121-backend-pytest-data")

from app.db.models import Alarm, AnalysisRun, DiagnosticRow, Project, SourceFile
from app.db.session import SessionLocal
from app.main import app
from fastapi.testclient import TestClient


def test_catalog_and_run_fixture():
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/api/v1/detectors").json()["total"] >= 1
        project = client.post("/api/v1/projects", json={"name": "pytest-demo"}).json()
        response = client.post(
            f"/api/v1/projects/{project['id']}/runs",
            json={
                "detector_id": "stack-bounds",
                "rule_pack_id": "cwe121-core",
                "config": {"fixture_path": "analyzer/tests/fixtures/miniir/oob_store.json"},
            },
        )
        assert response.status_code == 202
        run_id = response.json()["id"]
        for _ in range(30):
            run = client.get(f"/api/v1/runs/{run_id}").json()
            if run["status"] != "queued" and run["status"] != "running":
                break
            time.sleep(0.05)
        assert run["status"] == "succeeded"
        alarms = client.get(f"/api/v1/runs/{run_id}/alarms").json()
        assert alarms["total"] == 1
        assert alarms["items"][0]["severity"] == "definite"


def test_integer_overflow_alarm_is_imported():
    with TestClient(app) as client:
        project = client.post("/api/v1/projects", json={"name": "pytest-overflow"}).json()
        response = client.post(
            f"/api/v1/projects/{project['id']}/runs",
            json={
                "detector_id": "stack-bounds",
                "rule_pack_id": "cwe121-core",
                "config": {
                    "fixture_path": "analyzer/tests/fixtures/miniir/integer_overflow.json"
                },
            },
        )
        assert response.status_code == 202
        run_id = response.json()["id"]
        for _ in range(30):
            run = client.get(f"/api/v1/runs/{run_id}").json()
            if run["status"] not in {"queued", "running"}:
                break
            time.sleep(0.05)
        assert run["status"] == "succeeded"
        alarms = client.get(f"/api/v1/runs/{run_id}/alarms").json()
        assert alarms["total"] == 1
        alarm = alarms["items"][0]
        assert alarm["cwe_id"] == "CWE-190"
        assert alarm["violation_kind"] == "integer_overflow"
        assert alarm["severity"] == "definite"


def test_integer_underflow_alarm_is_imported():
    with TestClient(app) as client:
        project = client.post("/api/v1/projects", json={"name": "pytest-underflow"}).json()
        response = client.post(
            f"/api/v1/projects/{project['id']}/runs",
            json={
                "detector_id": "stack-bounds",
                "rule_pack_id": "cwe121-core",
                "config": {
                    "fixture_path": "analyzer/tests/fixtures/miniir/integer_underflow.json"
                },
            },
        )
        assert response.status_code == 202
        run_id = response.json()["id"]
        for _ in range(30):
            run = client.get(f"/api/v1/runs/{run_id}").json()
            if run["status"] not in {"queued", "running"}:
                break
            time.sleep(0.05)
        assert run["status"] == "succeeded"
        alarms = client.get(f"/api/v1/runs/{run_id}/alarms").json()
        assert alarms["total"] == 1
        alarm = alarms["items"][0]
        assert alarm["cwe_id"] == "CWE-191"
        assert alarm["violation_kind"] == "integer_underflow"
        assert alarm["severity"] == "definite"


def test_debug_project_edits_source_and_persists_rerun_results():
    with TestClient(app) as client:
        project = client.post(
            "/api/v1/projects", json={"name": "debug-live-edit", "debug_mode": True}
        ).json()
        assert project["debug_mode"] is True

        files = client.get(f"/api/v1/projects/{project['id']}/files").json()
        assert files["total"] == 1
        blank = client.get(
            f"/api/v1/projects/{project['id']}/files/{files['items'][0]['id']}"
        ).json()
        assert blank["path"] == "blank.c"
        assert blank["content"] == ""
        assert blank["size_bytes"] == 0

        edited_source = "int main(void) { return 0; }\n"
        updated = client.put(
            f"/api/v1/projects/{project['id']}/files/{blank['id']}",
            json={"content": edited_source},
        )
        assert updated.status_code == 200
        revision = updated.json()
        assert revision["id"] != blank["id"]
        assert revision["content"] == edited_source
        assert revision["size_bytes"] == len(edited_source.encode())

        with SessionLocal() as db:
            stored = db.get(SourceFile, revision["id"])
            assert stored is not None
            assert stored.content == edited_source

        response = client.post(
            f"/api/v1/projects/{project['id']}/runs",
            json={
                "file_ids": [revision["id"]],
                "detector_id": "stack-bounds",
                "rule_pack_id": "cwe121-core",
                "config": {
                    "fixture_path": "contracts/examples/analyzer-result.succeeded.json"
                },
            },
        )
        assert response.status_code == 202
        run_id = response.json()["id"]
        for _ in range(30):
            current = client.get(f"/api/v1/runs/{run_id}").json()
            if current["status"] not in {"queued", "running"}:
                break
            time.sleep(0.05)
        assert current["status"] == "succeeded"

        artifacts = client.get(f"/api/v1/runs/{run_id}/ir").json()["items"]
        source = next(item for item in artifacts if item["kind"] == "source")
        assert source["source_file_id"] == revision["id"]
        assert source["content"] == edited_source


def test_delete_project_cascades_database_rows():
    with TestClient(app) as client:
        project = client.post("/api/v1/projects", json={"name": "delete-demo"}).json()
        project_id = project["id"]
        upload = client.post(
            f"/api/v1/projects/{project_id}/files",
            files={"file": ("delete-me.c", b"int main(void) { return 0; }", "text/plain")},
        )
        assert upload.status_code == 201
        file_id = upload.json()["id"]

        response = client.post(
            f"/api/v1/projects/{project_id}/runs",
            json={
                "detector_id": "stack-bounds",
                "rule_pack_id": "cwe121-core",
                "config": {"fixture_path": "analyzer/tests/fixtures/miniir/oob_store.json"},
            },
        )
        assert response.status_code == 202
        run_id = response.json()["id"]
        for _ in range(30):
            run = client.get(f"/api/v1/runs/{run_id}").json()
            if run["status"] not in {"queued", "running"}:
                break
            time.sleep(0.05)
        assert run["status"] == "succeeded"
        with SessionLocal() as db:
            alarm = Alarm(
                run_id=run_id,
                alarm_key="delete-cascade-test",
                detector_id="stack-bounds",
                detector_version="0.1.0",
                rule_pack_id="cwe121-core",
                rule_pack_version="0.1.0",
                cwe_id="CWE-121",
                violation_kind="copy_length_overflow",
                severity="possible",
                memory_object_id="%buffer",
                access_size=1,
            )
            db.add(alarm)
            db.commit()
            alarm_id = alarm.id

        assert client.delete(f"/api/v1/projects/{project_id}").status_code == 204
        assert client.get(f"/api/v1/projects/{project_id}").status_code == 404
        assert client.get(f"/api/v1/runs/{run_id}").status_code == 404

        with SessionLocal() as db:
            assert db.get(Project, project_id) is None
            assert db.get(SourceFile, file_id) is None
            assert db.get(AnalysisRun, run_id) is None
            assert db.get(Alarm, alarm_id) is None


def test_diagnostics_are_grouped_by_source_statement():
    with TestClient(app) as client:
        project = client.post("/api/v1/projects", json={"name": "diagnostic-dedupe"}).json()
        with SessionLocal() as db:
            run = AnalysisRun(
                project_id=project["id"],
                status="succeeded",
                detector_id="stack-bounds",
                detector_version="0.1.0",
                rule_pack_id="cwe121-core",
                rule_pack_version="0.1.0",
                analyzer_version="0.1.0",
            )
            db.add(run)
            db.flush()
            for instruction_id in ("v1", "v2", "v3"):
                db.add(
                    DiagnosticRow(
                        run_id=run.id,
                        diagnostic_id=f"d-{instruction_id}",
                        code="UNSUPPORTED_INSTRUCTION",
                        severity="unsupported",
                        message="unsupported MiniIR instruction",
                        impact="instruction semantics are not implemented",
                        function_name="mvp_unsupported_operation",
                        block_id="bb0",
                        instruction_id=instruction_id,
                        source_line=141,
                        location_json=json.dumps(
                            {"file": "input.c", "line": 141, "column": 19}
                        ),
                    )
                )
            db.commit()
            run_id = run.id

        diagnostics = client.get(f"/api/v1/runs/{run_id}/diagnostics").json()
        assert diagnostics["total"] == 1
        assert len(diagnostics["items"]) == 1
        assert diagnostics["items"][0]["code"] == "UNSUPPORTED_INSTRUCTION"

        summary = client.get(f"/api/v1/runs/{run_id}/summary").json()
        assert summary["diagnostic_count"] == 1
        assert summary["unsupported_count"] == 1


def test_unknown_detector_error_shape():
    with TestClient(app) as client:
        project = client.post("/api/v1/projects", json={"name": "error-demo"}).json()
        response = client.post(
            f"/api/v1/projects/{project['id']}/runs",
            json={"detector_id": "missing", "rule_pack_id": "cwe121-core"},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "DETECTOR_NOT_FOUND"


def test_evaluation_worker_finishes():
    with TestClient(app) as client:
        project = client.post("/api/v1/projects", json={"name": "evaluation-demo"}).json()
        response = client.post(
            f"/api/v1/projects/{project['id']}/evaluations",
            json={
                "dataset_name": "fixture",
                "dataset_version": "1",
                "detector_id": "stack-bounds",
                "rule_pack_id": "cwe121-core",
                "cases": [],
            },
        )
        assert response.status_code == 202
        evaluation_id = response.json()["id"]
        for _ in range(20):
            evaluation = client.get(f"/api/v1/evaluations/{evaluation_id}").json()
            if evaluation["status"] not in {"queued", "running"}:
                break
            time.sleep(0.05)
        assert evaluation["status"] == "succeeded"
        assert client.get(f"/api/v1/evaluations/{evaluation_id}/matrix").json()["total"] == 0


def test_manifest_materializes_bad_and_good_runs(tmp_path):
    bad = tmp_path / "Case_01_bad.c"
    good = tmp_path / "Case_01_goodB2G.c"
    bad.write_text("int main(void) { char x[1]; x[1] = 1; }", encoding="utf-8")
    good.write_text("int main(void) { char x[1]; x[0] = 1; }", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "case_name": "Case_01",
                        "family": "CWE131_loop",
                        "bad_files": [str(bad)],
                        "good_files": [str(good)],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with TestClient(app) as client:
        project = client.post("/api/v1/projects", json={"name": "manifest-demo"}).json()
        response = client.post(
            f"/api/v1/projects/{project['id']}/evaluations",
            json={
                "dataset_name": "manifest",
                "detector_id": "stack-bounds",
                "rule_pack_id": "cwe121-core",
                "manifest_path": str(manifest),
            },
        )
        assert response.status_code == 202
        evaluation_id = response.json()["id"]
        for _ in range(60):
            current = client.get(f"/api/v1/evaluations/{evaluation_id}").json()
            if current["status"] not in {"queued", "running"}:
                break
            time.sleep(0.05)
        assert current["status"] == "succeeded"
        cases = client.get(f"/api/v1/evaluations/{evaluation_id}/cases").json()
        assert cases["total"] == 1
        assert cases["items"][0]["bad_run_id"] != cases["items"][0]["good_run_id"]
