#!/usr/bin/env bash
set -euo pipefail

status="FAILED"
mkdir -p .verification-artifacts

write_receipt() {
  python - "$status" <<'PY'
from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

status = sys.argv[1]
receipt = {
    "schema": "glaciereq.python-verification-receipt.v1",
    "status": status,
    "repository": os.environ.get("GITHUB_REPOSITORY"),
    "source_sha": os.environ.get("GITHUB_SHA"),
    "run_id": os.environ.get("GITHUB_RUN_ID"),
    "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    "generated_at": datetime.now(UTC).isoformat(),
    "gates": [
        "ruff_check",
        "ruff_format_check",
        "compileall",
        "pytest",
    ],
}
Path(".verification-artifacts/verification.json").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}
trap write_receipt EXIT

python -m pip install --disable-pip-version-check ruff pytest
[[ -f requirements.txt ]] && python -m pip install -r requirements.txt
[[ -f requirements-dev.txt ]] && python -m pip install -r requirements-dev.txt

ruff check .
ruff format --check .
python -m compileall -q .
pytest -q | tee .verification-artifacts/pytest.txt

status="PASSED"
