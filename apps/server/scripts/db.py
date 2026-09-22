import typer
from alembic import command
from alembic.config import Config

app = typer.Typer(help="Database migration helpers")


def _config() -> Config:
    cfg = Config("alembic.ini")
    return cfg


@app.command()
def upgrade(revision: str = "head") -> None:
    """Upgrade database to a revision (default: head)."""
    command.upgrade(_config(), revision)


@app.command()
def downgrade(revision: str) -> None:
    """Downgrade database to a revision."""
    command.downgrade(_config(), revision)


@app.command()
def revision(message: str = "auto", autogenerate: bool = True) -> None:
    """Create a new migration revision."""
    command.revision(_config(), message=message, autogenerate=autogenerate)


if __name__ == "__main__":
    app()
