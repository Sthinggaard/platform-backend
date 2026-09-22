#!/usr/bin/env python3
"""
Smoke test script to verify the foundation is working correctly.
Tests configuration, logging, and database connections.
"""

import sys
from pathlib import Path

# Add src to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.core.config import settings
from src.core.database import get_db_context, get_mongodb
from src.core.logging_config import get_logger
from src.core.models import ComplianceFramework

console = Console()
logger = get_logger(__name__)


def test_configuration() -> bool:
    """Test configuration loading."""
    console.print("\n[bold cyan]Testing Configuration...[/bold cyan]")

    try:
        # Test basic settings
        assert settings.app_name == "Risklence Tower"
        assert settings.app_version == "0.1.0"

        # Test nested settings
        assert settings.database.postgres_host is not None
        assert settings.database.mongodb_uri is not None

        console.print("[green]✓[/green] Configuration loaded successfully")
        console.print(f"  - Environment: {settings.environment.value}")
        console.print(f"  - Debug mode: {settings.debug}")
        console.print(f"  - Log level: {settings.log_level}")
        return True

    except Exception as e:
        console.print(f"[red]✗[/red] Configuration failed: {e}")
        return False


def test_logging() -> bool:
    """Test logging system."""
    console.print("\n[bold cyan]Testing Logging...[/bold cyan]")

    try:
        logger.info("smoke_test_started", component="logging")
        logger.debug("smoke_test_debug", test_data={"key": "value"})

        console.print("[green]✓[/green] Logging system working")
        console.print(f"  - Structlog configured")
        console.print(f"  - Log level: {settings.log_level}")
        return True

    except Exception as e:
        console.print(f"[red]✗[/red] Logging failed: {e}")
        return False


def test_postgresql() -> bool:
    """Test PostgreSQL connection."""
    console.print("\n[bold cyan]Testing PostgreSQL...[/bold cyan]")

    try:
        with get_db_context() as db:
            # Test connection with a simple query
            from sqlalchemy import text

            result = db.execute(text("SELECT 1"))
            assert result.scalar() == 1

            # Test ORM
            count = db.query(ComplianceFramework).count()

            console.print("[green]✓[/green] PostgreSQL connection successful")
            console.print(f"  - Host: {settings.database.postgres_host}")
            console.print(f"  - Database: {settings.database.postgres_db}")
            console.print(f"  - Framework count: {count}")
            return True

    except Exception as e:
        console.print(f"[red]✗[/red] PostgreSQL failed: {e}")
        console.print(
            "  [yellow]Hint:[/yellow] Make sure PostgreSQL is running "
            "(docker-compose up -d)"
        )
        return False


def test_mongodb() -> bool:
    """Test MongoDB connection."""
    console.print("\n[bold cyan]Testing MongoDB...[/bold cyan]")

    try:
        db = get_mongodb()

        # Test connection
        db.command("ping")

        # Test collection access
        collection = db["test_collection"]
        test_doc = {"test": "smoke_test", "timestamp": "2024-01-01"}
        result = collection.insert_one(test_doc)

        # Clean up
        collection.delete_one({"_id": result.inserted_id})

        console.print("[green]✓[/green] MongoDB connection successful")
        console.print(f"  - Database: {db.name}")
        console.print("  - Read/write operations working")
        return True

    except Exception as e:
        console.print(f"[red]✗[/red] MongoDB failed: {e}")
        console.print(
            "  [yellow]Hint:[/yellow] Make sure MongoDB is running (docker-compose up -d)"
        )
        return False


def test_models() -> bool:
    """Test ORM models."""
    console.print("\n[bold cyan]Testing ORM Models...[/bold cyan]")

    try:
        import uuid

        from src.core.models import (
            CloudAsset,
            Organization,
            ScanRun,
            ScanStatus,
        )

        with get_db_context() as db:
            # Ensure we have a test organization to satisfy FK constraints
            org = db.query(Organization.id).order_by(Organization.id).first()
            if org is None:
                org = Organization(name="Smoke Test Org", slug="smoke-test-org")
                db.add(org)
                db.commit()
                db.refresh(org)

            org_id = getattr(org, "id", None) or org[0]
            asset_id = f"/test/smoke-test-asset-{uuid.uuid4()}"

            # Create test data
            asset = CloudAsset(
                organization_id=org_id,
                asset_id=asset_id,
                asset_type="test",
                cloud_provider="test",
                region="test",
                name="Smoke Test Asset",
            )
            db.add(asset)
            db.commit()

            scan = ScanRun(
                organization_id=org_id,
                scan_type="smoke_test",
                status=ScanStatus.COMPLETED,
            )
            db.add(scan)
            db.commit()

            # Clean up
            db.delete(asset)
            db.delete(scan)
            db.commit()

        console.print("[green]✓[/green] ORM models working")
        console.print("  - CloudAsset model tested")
        console.print("  - ScanRun model tested")
        return True

    except Exception as e:
        console.print(f"[red]✗[/red] Models failed: {e}")
        return False


def main() -> None:
    """Run all smoke tests."""
    console.print(
        Panel.fit(
            "[bold]Risklence Tower - Foundation Smoke Test[/bold]",
            border_style="cyan",
        )
    )

    results = {
        "Configuration": test_configuration(),
        "Logging": test_logging(),
        "PostgreSQL": test_postgresql(),
        "MongoDB": test_mongodb(),
        "ORM Models": test_models(),
    }

    # Create results table
    console.print("\n[bold cyan]Test Results:[/bold cyan]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Component", style="cyan")
    table.add_column("Status", justify="center")

    for component, passed in results.items():
        status = "[green]✓ PASS[/green]" if passed else "[red]✗ FAIL[/red]"
        table.add_row(component, status)

    console.print(table)

    # Summary
    passed_count = sum(results.values())
    total_count = len(results)

    if passed_count == total_count:
        console.print(
            f"\n[bold green]All tests passed! ({passed_count}/{total_count})[/bold green]"
        )
        console.print("\n[green]Foundation is ready to use! 🎉[/green]")
        sys.exit(0)
    else:
        console.print(
            f"\n[bold red]Some tests failed ({passed_count}/{total_count})[/bold red]"
        )
        console.print(
            "\n[yellow]Please ensure Docker services are running:[/yellow]"
        )
        console.print("  cd docker && docker-compose up -d")
        sys.exit(1)


if __name__ == "__main__":
    main()
