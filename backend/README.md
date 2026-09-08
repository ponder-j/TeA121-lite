# tea121-lite backend

FastAPI + SQLite service for project files, analyzer runs, structured results,
SSE events and evaluation cases. The service does not implement static analysis;
it invokes the `tea121` CLI or imports a contract-valid fixture.

The repository Compose backend includes Clang/LLVM 15, `tea121-extract`, the
analyzer CLI, and the API. Start the integrated stack and run its smoke check:

```bash
docker compose up --build backend web
backend/.venv/bin/python tests/e2e/three_tier_smoke.py
```

## Start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
uvicorn app.main:app --reload
```

Set `TEA121_DATABASE_URL`, `TEA121_STORAGE_DIR`, or `TEA121_ANALYZER_COMMAND`
in the environment. A fresh database is initialized and the
`stack-bounds/cwe121-core` catalog entries are seeded automatically.

For a deterministic demo, create a run with
`config.fixture_path=contracts/examples/analyzer-result.succeeded.json`.
The fixture runner replaces its fixture run id with the newly-created UUID and
uses the same importer as a real analyzer invocation.

## Checks

```bash
pytest
python scripts/api_smoke.py
python scripts/seed_demo.py
python scripts/juliet_manifest.py ../juliet测试集/testcases/CWE121_Stack_Based_Buffer_Overflow -o /tmp/juliet.json --limit 10
```

`GET /openapi.json` is the generated API contract. All list endpoints use
`limit`/`offset` and return `{items,total,limit,offset}`.
