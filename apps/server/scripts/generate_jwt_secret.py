"""
Generate a secure JWT secret and optionally persist it to env files.

Usage:
    cd server
    poetry run python scripts/generate_jwt_secret.py     # prints a new base64 secret
    poetry run python scripts/generate_jwt_secret.py --env ../.env.local
"""

import argparse
import base64
import secrets
from pathlib import Path


def make_secret(num_bytes: int = 32) -> str:
    """Generate a URL-safe base64 secret."""
    return base64.urlsafe_b64encode(secrets.token_bytes(num_bytes)).decode().rstrip("=")


def update_env_file(path: Path, secret: str) -> Path:
    """Update or create secret entries inside an env file."""
    updates = {
        "AUTH_JWT_SECRET": secret,
        "SECRET_KEY": secret,
    }

    if not path.exists():
        path.write_text("\n".join(f"{key}={value}" for key, value in updates.items()) + "\n")
        return path

    lines = path.read_text().splitlines()
    touched = set()
    new_lines = []
    for raw in lines:
        if "=" not in raw or raw.strip().startswith("#"):
            new_lines.append(raw)
            continue
        key, _, _ = raw.partition("=")
        if key in updates:
            new_lines.append(f"{key}={updates[key]}")
            touched.add(key)
        else:
            new_lines.append(raw)
    for key, value in updates.items():
        if key not in touched:
            new_lines.append(f"{key}={value}")
    path.write_text("\n".join(new_lines) + "\n")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a secure AUTH_JWT_SECRET/SECRET_KEY value.")
    parser.add_argument(
        "--env",
        type=Path,
        help="Optional path to an env file to update with the generated secret.",
    )
    parser.add_argument(
        "--bytes",
        type=int,
        default=32,
        help="Number of random bytes to use for the secret (default: 32).",
    )
    args = parser.parse_args()

    secret = make_secret(args.bytes)
    print(secret)
    if args.env:
        updated = update_env_file(args.env.expanduser(), secret)
        print(f"Updated {updated} with the new secret.")


if __name__ == "__main__":
    main()
