#!/usr/bin/env sh
set -eu

docker compose up -d --build backend web
backend/.venv/bin/python tests/e2e/three_tier_smoke.py "$@"
