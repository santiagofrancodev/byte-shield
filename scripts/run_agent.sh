#!/usr/bin/env bash
# Ejemplo: agente OpenClaw en modo import (por defecto)
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:-}:$(pwd)/src"
TARGET="${1:-127.0.0.1}"
python -m openclaw_agent.orchestrator --target "$TARGET" --ports 443 --trigger cicd_hook --ci-exit
