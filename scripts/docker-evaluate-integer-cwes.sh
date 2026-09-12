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
output_dir="${TEA121_OUTPUT_DIR:-$PWD/analysis-output}"
cwes="${TEA121_INTEGER_CWES:-190,191}"

extra_args=()
if [[ -n "${TEA121_FLOW:-}" ]]; then extra_args+=(--flow "$TEA121_FLOW"); fi
if [[ -n "${TEA121_SUITE:-}" ]]; then
  IFS=',' read -r -a suites <<< "$TEA121_SUITE"
  for suite in "${suites[@]}"; do extra_args+=(--suite "$suite"); done
fi
if [[ -n "${TEA121_LIMIT:-}" ]]; then extra_args+=(--limit "$TEA121_LIMIT"); fi

mkdir -p "$output_dir"
IFS=',' read -r -a cwe_list <<< "$cwes"
for number in "${cwe_list[@]}"; do
  case "$number" in
    190)
      cwe_dir="CWE190_Integer_Overflow"
      expected_cwe="CWE-190"
      ;;
    191)
      cwe_dir="CWE191_Integer_Underflow"
      expected_cwe="CWE-191"
      ;;
    *)
      echo "unsupported integer CWE: $number" >&2
      exit 2
      ;;
  esac
  docker run --rm --entrypoint python3 \
    -v "$PWD:/workspace/project:ro" \
    -v "$dataset_root:/workspace/testcases:ro" \
    -v "$support_dir:/workspace/testcasesupport:ro" \
    -v "$output_dir:/workspace/output" \
    "$image" \
    /workspace/project/analyzer/tools/evaluate_cwe121.py \
    /workspace/testcases \
    --cwe-dir "$cwe_dir" \
    --expected-cwe "$expected_cwe" \
    --check-integer-overflow \
    --integer-signedness "${TEA121_INTEGER_SIGNEDNESS:-auto}" \
    --ignore-juliet-macros \
    --compile-arg=-fsigned-char \
    --include-dir /workspace/testcasesupport \
    --jobs "$jobs" \
    ${extra_args[@]+"${extra_args[@]}"} \
    -o "/workspace/output/juliet-cwe${number}-all.json" \
    --csv-output "/workspace/output/juliet-cwe${number}-all.csv"
done
