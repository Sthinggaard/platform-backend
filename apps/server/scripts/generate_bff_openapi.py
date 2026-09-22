"""
Generate OpenAPI schema for the BFF.

Outputs to bff/openapi.json. Intended to be run from repo root:
    poetry run python scripts/generate_bff_openapi.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bff.app import app


def main() -> None:
    target = Path(__file__).resolve().parent.parent / "bff" / "openapi.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    spec = app.openapi()
    target.write_text(json.dumps(spec, indent=2))
    print(f"Wrote OpenAPI schema to {target}")


if __name__ == "__main__":
    main()
