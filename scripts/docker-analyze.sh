#!/usr/bin/env bash
set -euo pipefail

input_path=${1:?usage: scripts/docker-analyze.sh path/to/file.c [output.json]}
output_path=${2:-/workspace/output/result.json}

mkdir -p analysis-output
docker run --rm \
  -v "$PWD:/workspace/project:ro" \
  -v "$PWD/analysis-output:/workspace/output" \
  tea121-lite:llvm15 analyze "/workspace/project/$input_path" \
  --format json --output "$output_path"
