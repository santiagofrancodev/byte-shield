#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev,api]"
pre-commit install || true
echo "Listo. Activa: source .venv/bin/activate"
