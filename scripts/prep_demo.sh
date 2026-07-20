#!/usr/bin/env bash
# Prep terminal + dashboard for recording docs/DEMO_SCRIPT.md
# Usage: ./scripts/prep_demo.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

echo "==> Eval harness (metrics + dashboard badge)"
python -m src.eval_main

echo "==> Simulate all attack signatures → pcap"
python -m src.lab_main --simulate all --yes

echo "==> Offline WIDS + dashboard (Ctrl+C when recording is done)"
echo "    Open http://127.0.0.1:8080  — follow docs/DEMO_SCRIPT.md"
exec python -m src.main --offline data/captures/lab_simulated.pcap --keep-dashboard
