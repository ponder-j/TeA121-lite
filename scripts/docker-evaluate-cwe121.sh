#!/usr/bin/env bash
set -euo pipefail

docker_cpus="$(docker info --format '{{.NCPU}}' 2>/dev/null || true)"
if [[ "$docker_cpus" =~ ^[0-9]+$ ]] && (( docker_cpus > 2 )); then
  default_jobs=$((docker_cpus - 2))
else
  default_jobs=4
fi
jobs="${TEA121_JOBS:-$default_jobs}"
image="${TEA121_IMAGE:-tea121-lite:llvm15}"
dataset_root="${TEA121_DATASET_ROOT:-$PWD/tests/testcases}"
support_dir="${TEA121_SUPPORT_DIR:-$PWD/tests/testcasesupport}"
output="${TEA121_OUTPUT:-$PWD/analysis-output/juliet-cwe121-all.json}"
csv_output="${TEA121_CSV_OUTPUT:-$PWD/analysis-output/juliet-cwe121-all.csv}"

extra_args=()
if [[ -n "${TEA121_FLOW:-}" ]]; then
  extra_args+=(--flow "$TEA121_FLOW")
fi
if [[ -n "${TEA121_SUITE:-}" ]]; then
  IFS=',' read -r -a suites <<< "$TEA121_SUITE"
  for suite in "${suites[@]}"; do
    extra_args+=(--suite "$suite")
  done
fi
if [[ -n "${TEA121_LIMIT:-}" ]]; then
  extra_args+=(--limit "$TEA121_LIMIT")
fi

mkdir -p "$(dirname "$output")" "$(dirname "$csv_output")"
docker run --rm --entrypoint python3 \
  -v "$PWD:/workspace/project:ro" \
  -v "$dataset_root:/workspace/testcases:ro" \
  -v "$support_dir:/workspace/testcasesupport:ro" \
  -v "$(dirname "$output"):/workspace/output" \
  "$image" \
  /workspace/project/analyzer/tools/evaluate_cwe121.py \
  /workspace/testcases \
  --include-dir /workspace/testcasesupport \
  --jobs "$jobs" \
  ${extra_args[@]+"${extra_args[@]}"} \
  -o "/workspace/output/$(basename "$output")" \
  --csv-output "/workspace/output/$(basename "$csv_output")"
