#!/usr/bin/env bash
set -euo pipefail

jobs="${TEA121_JOBS:-18}"
flow_args=()
if [[ -n "${TEA121_FLOW:-}" ]]; then
  flow_args+=(--flow "$TEA121_FLOW")
fi

mkdir -p analysis-output
docker run --rm --entrypoint python3 \
  -v "$PWD:/workspace/project:ro" \
  -v "$PWD/juliet测试集:/workspace/juliet测试集:ro" \
  -v "$PWD/analysis-output:/workspace/output" \
  tea121-lite:llvm15 \
  /workspace/project/analyzer/tools/evaluate_juliet.py \
  /workspace/juliet测试集/testcases/CWE121_Stack_Based_Buffer_Overflow \
  --include-dir /workspace/juliet测试集/testcasesupport \
  --jobs "$jobs" \
  "${flow_args[@]}" \
  -o /workspace/output/juliet-s01-all.json \
  --csv-output /workspace/output/juliet-s01-all.csv
