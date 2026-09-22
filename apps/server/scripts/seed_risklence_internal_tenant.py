"""Seed the Risklence internal tenant with guided SaaS demo data."""

from src.core.database import get_db_context
from src.core.seeds.risklence_internal_tenant_seed import seed_risklence_internal_tenant


def main() -> None:
    with get_db_context() as db:
        blueprint = seed_risklence_internal_tenant(db)
        print(
            f"Seeded {blueprint['organization']['name']} internal tenant with "
            f"{len(blueprint['business_services'])} services, "
            f"{len(blueprint['interventions'])} interventions, and "
            f"{len(blueprint['decisions'])} decisions."
        )


if __name__ == "__main__":
    main()
