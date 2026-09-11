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

For a full local s01 run on the configured 18-core machine, use
`TEA121_JOBS=18 scripts/docker-evaluate-juliet.sh`. Set `TEA121_FLOW=51` to
restrict the wrapper to one flow variant. Results remain deterministically
sorted even when case subprocesses run concurrently.

## Supported MiniIR operations

`const`, `add`, `sub`, `mul`, `icmp`, `phi`, `select`, `alloca`, `gep`,
`load`, `store`, and conservative models for `memcpy`, `memmove`, `memset`,
`strcpy`, `strncpy`, `fgets`, `fscanf`, and `recv` are implemented. Scalar
results from observational calls such as `atoi`, `strlen`, and `rand` are
propagated as exact summaries when available or `Top` otherwise. Unknown
instructions/calls create diagnostics rather than being treated as clean.

Control-flow analysis supports edge-sensitive PHI values, all signed/unsigned
`icmp` predicates on both branch polarities, bounded narrowing after loop
widening, and single-sided interval arithmetic. Access checks are replayed on
the final stable state so intermediate widen-to-`Top` states do not leave stale
alarms.
