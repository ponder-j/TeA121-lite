"""Small smoke client used after installing backend optional test dependencies."""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

async def main():
    import httpx
    from app.main import app
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        print((await client.get("/healthz")).json())
        project = (await client.post("/api/v1/projects", json={"name": "demo-cwe121"})).json()
        print("project", project["id"])
        print("detectors", (await client.get("/api/v1/detectors")).json()["total"])

if __name__ == "__main__": asyncio.run(main())
