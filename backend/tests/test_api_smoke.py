import json
import os
import time

os.environ.setdefault("TEA121_DATABASE_URL", "sqlite:////tmp/tea121-backend-pytest.db")
os.environ.setdefault("TEA121_STORAGE_DIR", "/tmp/tea121-backend-pytest-data")

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
