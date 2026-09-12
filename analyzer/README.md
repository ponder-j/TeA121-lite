# tea121-lite analyzer

The analyzer is an offline, explainable CWE-121 checker. Its Python core accepts
versioned MiniIR JSON, runs a forward interval analysis, and emits a structured
result suitable for the backend contract. It does not depend on FastAPI,
SQLite, React, or a running service.

## Run the fixture

```bash
PYTHONPATH=analyzer/src python3 -m tea121 analyze analyzer/tests/fixtures/miniir/oob_store.json --format text
PYTHONPATH=analyzer/src python3 -m tea121 analyze analyzer/tests/fixtures/miniir/safe_store.json --format json
```

The normal result includes CFG and block entry/exit states. Add `--mode trace`
to include per-instruction state transitions on the final narrowed fixed point.
C/LLVM inputs also include the
normalized LLVM IR and its SHA-256 as an artifact for backend/workbench use.
A missing LLVM toolchain is
reported as `unsupported` by `tools/compile_case.py`; no shell command is
constructed from user input.

## Docker/LLVM pipeline

The reproducible image is based on Ubuntu 22.04 and installs LLVM/Clang 15,
LLVM development headers, CMake, Ninja, and Python. It builds the C++
`tea121-extract` binary during `docker build`.

```bash
docker build -t tea121-lite:llvm15 .
docker run --rm -v "$PWD:/workspace/project:ro" tea121-lite:llvm15 \
  analyze /workspace/project/analyzer/tests/fixtures/c/simple_oob.c --format text
# run the analyzer unit tests
docker run --rm --entrypoint pytest tea121-lite:llvm15 -q /workspace/analyzer/tests
```

For repeated runs, `docker compose run --rm analyzer --version` uses the same
image and mounts the repository plus Juliet data. `scripts/docker-analyze.sh`
is a small wrapper that writes JSON results to `analysis-output/`.

## Juliet evaluation

The I8 runner evaluates each bad/good side independently and records one of
`alarm`, `clean`, `unsupported`, or `error`. It understands single-file cases,
`51a/51b` split cases, and C++ `81a + _bad/_good*` cases. Source SHA-256 values,
compiler/linker/extractor commands, durations, diagnostics, and the raw analyzer
result are retained in the JSON manifest.

```bash
docker run --rm --entrypoint python3 \
  -v "$PWD:/workspace/project:ro" \
  -v "$PWD/juliet测试集:/workspace/juliet测试集:ro" \
  -v "$PWD/analysis-output:/workspace/output" \
  tea121-lite:llvm15 \
  /workspace/project/analyzer/tools/evaluate_juliet.py \
  /workspace/juliet测试集/testcases/CWE121_Stack_Based_Buffer_Overflow \
  --include-dir /workspace/juliet测试集/testcasesupport \
  --flow 01 --limit 10 --jobs 18 --keep-artifacts \
  -o /workspace/output/juliet-s01.json \
  --csv-output /workspace/output/juliet-s01.csv
```

The Juliet distribution must provide its support headers (including
`std_testcase.h`); pass their directory with one or more `--include-dir`
options. A compilation failure remains `error` and is included in conservative
metrics. Use `--flow`/`--limit` for a deterministic smoke subset before a full
run.

The Docker wrappers default to `NCPU - 2` workers (with a minimum fallback)
so the daemon and the backend/web containers retain CPU and memory headroom.
Override with `TEA121_JOBS` when running on an otherwise idle host. Set
`TEA121_FLOW=51` to restrict the legacy wrapper to one flow variant.
Results remain deterministically sorted even when case subprocesses run concurrently.

### Full CWE-121 batch evaluation

`evaluate_cwe121.py` discovers every `sNN` suite and aggregates TP/FP/FN/TN,
supported-only recall/specificity, and per-suite/family matrices. The Docker
wrapper defaults to the dataset checked out under `tests/testcases`:

```bash
scripts/docker-evaluate-cwe121.sh
# On this 10-CPU/8-GiB Docker VM the default is 8 workers.
# optional deterministic subset:
TEA121_SUITE=s01,s02 TEA121_FLOW=01 TEA121_LIMIT=20   scripts/docker-evaluate-cwe121.sh
```

Outputs default to `analysis-output/juliet-cwe121-all.json` and `.csv`. The
CSV keeps the per-case outcome plus diagnostic codes for failure triage.

The tracked evaluation report records the reproducible baseline and the
iteration history: `docs/juliet-cwe121-evaluation.md`.

For integer overflow/underflow evaluation, use
`scripts/docker-evaluate-integer-cwes.sh`; the tracked report is
`docs/juliet-cwe190-191-evaluation.md`.

## Supported MiniIR operations

`const`, `add`, `sub`, `mul`, `icmp`, `phi`, `select`, `alloca`, `gep`,
`load`, `store`, and conservative models for `memcpy`, `memmove`, `memset`,
`strcpy`, `strncpy`, `fgets`, `fscanf`, and `recv` are implemented. Scalar
results from observational calls such as `atoi`, `strlen`, and `rand` are
propagated as bounded type ranges when an exact summary is unavailable.
Unknown scalar instructions and calls are conservatively abstracted; calls
that may mutate tracked pointer arguments still create diagnostics.

Control-flow analysis supports edge-sensitive PHI values, all signed/unsigned
`icmp` predicates on both branch polarities, bounded narrowing after loop
widening, and single-sided interval arithmetic. Access checks are replayed on
the final stable state so intermediate widen-to-`Top` states do not leave stale
alarms.
