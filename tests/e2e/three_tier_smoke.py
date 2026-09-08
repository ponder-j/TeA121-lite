"""Exercise Web proxy -> backend -> real LLVM analyzer with one C file."""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from uuid import uuid4

import httpx


def checked(response: httpx.Response) -> dict:
    response.raise_for_status()
    return response.json()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:4173")
    parser.add_argument("--keep", action="store_true", help="keep the generated project")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    api = f"{base}/api/v1"
    project_id = None
    with httpx.Client(timeout=10.0) as client:
        page = client.get(base)
        page.raise_for_status()
        assert '<div id="root"></div>' in page.text, "Web app did not serve its React root"

        project = checked(
            client.post(
                f"{api}/projects",
                json={"name": f"three-tier-smoke-{uuid4().hex[:8]}"},
            )
        )
        project_id = project["id"]
        source = Path(__file__).resolve().parents[2] / "analyzer/tests/fixtures/c/simple_oob.c"
        with source.open("rb") as handle:
            uploaded = checked(
                client.post(
                    f"{api}/projects/{project_id}/files",
                    files={"file": (source.name, handle, "text/x-c")},
                    data={"path": source.name},
                )
            )
        run = checked(
            client.post(
                f"{api}/projects/{project_id}/runs",
                json={
                    "file_ids": [uploaded["id"]],
                    "detector_id": "stack-bounds",
                    "rule_pack_id": "cwe121-core",
                    "mode": "trace",
                    "cwe_id": "CWE-121",
                },
            )
        )
        run_id = run["id"]

        deadline = time.monotonic() + 30
        while run["status"] in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(0.2)
            run = checked(client.get(f"{api}/runs/{run_id}"))
        assert run["status"] == "succeeded", run

        summary = checked(client.get(f"{api}/runs/{run_id}/summary"))
        alarms = checked(
            client.get(
                f"{api}/runs/{run_id}/alarms",
                params={"cwe_id": "CWE-121", "severity": "definite"},
            )
        )
        states = checked(client.get(f"{api}/runs/{run_id}/states"))
        trace = checked(client.get(f"{api}/runs/{run_id}/trace"))
        artifacts = checked(client.get(f"{api}/runs/{run_id}/ir"))

        assert summary["alarm_count"] == 1, summary
        assert alarms["total"] == 1, alarms
        assert alarms["items"][0]["offset"] == {
            "lower": 8,
            "upper": 8,
            "is_bottom": False,
        }
        assert alarms["items"][0]["source_file_id"] == uploaded["id"], alarms
        assert states["items"], states
        assert trace["items"], trace
        assert any(item["kind"] == "source" for item in artifacts["items"]), artifacts
        assert any(item["kind"] == "normalized_ir" for item in artifacts["items"]), artifacts

        print(
            f"three-tier smoke passed: project={project_id} run={run_id} "
            f"alarms={summary['alarm_count']} trace={len(trace['items'])}"
        )
        if not args.keep:
            client.delete(f"{api}/projects/{project_id}").raise_for_status()
            project_id = None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
