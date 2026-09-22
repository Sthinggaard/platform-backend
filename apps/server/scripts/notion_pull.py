"""
Simple Notion page pull helper.

Reads env vars:
- NOTION_TOKEN: integration secret (do not commit)
- NOTION_PAGE_ID: target page ID

Usage:
    NOTION_TOKEN=xxx NOTION_PAGE_ID=yyy poetry run python scripts/notion_pull.py

Prints the page metadata and top-level blocks as JSON to stdout.
"""

import json
import os
import sys
from typing import Any, Dict

import requests


NOTION_API_URL = "https://api.notion.com/v1"
NOTION_VERSION = "2022-06-28"


def get_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise SystemExit(f"Missing required env var: {name}")
    return val


def notion_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Notion-Version": NOTION_VERSION,
        "Content-Type": "application/json",
    }


def fetch_page(token: str, page_id: str) -> Dict[str, Any]:
    resp = requests.get(f"{NOTION_API_URL}/pages/{page_id}", headers=notion_headers(token))
    resp.raise_for_status()
    return resp.json()


def fetch_blocks(token: str, page_id: str) -> Dict[str, Any]:
    resp = requests.get(
        f"{NOTION_API_URL}/blocks/{page_id}/children",
        headers=notion_headers(token),
        params={"page_size": 100},
    )
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    token = get_env("NOTION_TOKEN")
    page_id = get_env("NOTION_PAGE_ID")

    page = fetch_page(token, page_id)
    blocks = fetch_blocks(token, page_id)

    output = {"page": page, "blocks": blocks}
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
