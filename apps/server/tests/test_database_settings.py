from src.core.config import DatabaseSettings


def test_database_settings_use_the_documented_local_compose_port(monkeypatch):
    monkeypatch.delenv("POSTGRES_PORT", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    settings = DatabaseSettings()

    assert settings.postgres_port == 5433
