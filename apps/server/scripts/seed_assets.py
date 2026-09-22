"""
Seed demo organization, assets, and baseline controls for UC-01/02/03.

Usage:
    poetry run python scripts/seed_assets.py
"""

from src.asset_monitoring.service import ensure_seed_org, seed_assets, seed_controls
from src.core.database import get_db_context


def main() -> None:
    with get_db_context() as db:
        org = ensure_seed_org(db)
        seed_assets(db, org.id)
        seed_controls(db)
        db.commit()
        print(f"Seeded assets and controls for org {org.id} ({org.name})")


if __name__ == "__main__":
    main()
