#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
if [ ! -f .env ]; then cp .env.example .env; fi
echo "Installed. Web: phishshield web | CLI: phishshield scan https://example.com"
