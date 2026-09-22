"""
Simple smoke script to exercise the BFF edge with auth propagation.

Usage:
    poetry run python scripts/smoke_bff.py --base http://localhost:8080 --token "Bearer <token>"
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid

import requests


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test BFF")
    parser.add_argument("--base", default="http://localhost:8080", help="BFF base URL")
    parser.add_argument("--token", help="Bearer token (include 'Bearer ' prefix or raw token)")
    args = parser.parse_args()

    headers = {"x-request-id": str(uuid.uuid4())}
    if args.token:
        headers["Authorization"] = args.token if args.token.lower().startswith("bearer ") else f"Bearer {args.token}"

    def call(path: str, method: str = "GET", payload: dict | None = None):
        url = f"{args.base}{path}"
        resp = requests.request(method, url, headers=headers, json=payload, timeout=10)
        print(f"{method} {path} -> {resp.status_code}")
        try:
            print(json.dumps(resp.json(), indent=2))
        except Exception:
            print(resp.text)
        return resp

    call("/health")

    if not args.token:
        print("Skipping authenticated smoke checks because no token was provided.")
        return 0

    session_resp = call("/api/v1/onboarding/", method="POST", payload={"current_step": "start"})
    if not session_resp.ok:
        return 1
    session_id = session_resp.json().get("id")
    call(f"/api/v1/onboarding/{session_id}/events")
    call(f"/api/v1/onboarding/{session_id}/prompt/mock-next", method="POST")
    call(f"/api/v1/onboarding/{session_id}/prompt/respond", method="POST", payload={"value": "hello"})
    call(f"/api/v1/onboarding/{session_id}/artefacts/completeness")
    call(f"/api/v1/onboarding/{session_id}/evidence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
