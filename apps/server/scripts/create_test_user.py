"""
Create or update a local-login test user.

Usage:
    poetry run python scripts/create_test_user.py
"""

from datetime import datetime, timezone

from sqlalchemy import inspect, text

from src.core.database import get_db_context
from src.core.models import UserStatus
from src.core.services.auth_service import hash_password


EMAIL = "admin@risklence.com"
PASSWORD = "RisklenceSeedAdmin2026!"
ORG_NAME = "Risklence"
ORG_SLUG = "risklence-internal"
DOMAIN = "risklence.com"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _table_columns(db, table_name: str) -> set[str]:
    inspector = inspect(db.get_bind())
    return {col["name"] for col in inspector.get_columns(table_name)}


def _table_exists(db, table_name: str) -> bool:
    inspector = inspect(db.get_bind())
    return table_name in inspector.get_table_names()


def ensure_org(db) -> tuple[int, bool]:
    org_id = db.execute(
        text("SELECT id FROM organizations WHERE slug = :slug LIMIT 1"),
        {"slug": ORG_SLUG},
    ).scalar_one_or_none()
    org_columns = _table_columns(db, "organizations")
    if org_id is None:
        values = {
            "name": ORG_NAME,
            "slug": ORG_SLUG,
            "plan_tier": "enterprise",
            "subscription_status": "trial",
        }
        insert_cols = [key for key in values.keys() if key in org_columns]
        if not insert_cols:
            raise RuntimeError("organizations table schema is unexpected; no insertable columns found.")
        columns_sql = ", ".join(insert_cols)
        params_sql = ", ".join(f":{col}" for col in insert_cols)
        # False positive (A1 security remediation review): columns_sql is
        # built from insert_cols, itself filtered against org_columns (the
        # real table's own introspected schema) — never runtime/user input.
        # Values are bound parameters, not interpolated. This is also a
        # local dev-only utility script, not deployed.
        org_id = db.execute(
            text(f"INSERT INTO organizations ({columns_sql}) VALUES ({params_sql}) RETURNING id"),  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            {key: values[key] for key in insert_cols},
        ).scalar_one()
        db.commit()

    has_auth_settings = _table_exists(db, "auth_tenant_settings")
    if has_auth_settings:
        settings_columns = _table_columns(db, "auth_tenant_settings")
        settings_id = db.execute(
            text("SELECT id FROM auth_tenant_settings WHERE organization_id = :org_id LIMIT 1"),
            {"org_id": org_id},
        ).scalar_one_or_none()
        if settings_id is None:
            values = {
                "organization_id": org_id,
                "local_login_enabled": True,
                "sso_required": False,
                "sso_google_enabled": False,
                "sso_ms_enabled": False,
                "domain_allowlist": [DOMAIN],
                "created_at": _now(),
                "updated_at": _now(),
            }
            insert_cols = [key for key in values.keys() if key in settings_columns]
            columns_sql = ", ".join(insert_cols)
            params_sql = ", ".join(f":{col}" for col in insert_cols)
            # False positive (A1 security remediation review): same
            # schema-introspected-columns + bound-values pattern as the
            # organizations insert above.
            db.execute(
                text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                    f"INSERT INTO auth_tenant_settings ({columns_sql}) VALUES ({params_sql})"
                ),
                {key: values[key] for key in insert_cols},
            )
        else:
            db.execute(
                text(
                    "UPDATE auth_tenant_settings "
                    "SET domain_allowlist = CASE "
                    "WHEN domain_allowlist IS NULL THEN ARRAY[:domain]::varchar[] "
                    "WHEN NOT (domain_allowlist @> ARRAY[:domain]::varchar[]) THEN array_append(domain_allowlist, :domain) "
                    "ELSE domain_allowlist END "
                    "WHERE organization_id = :org_id"
                ),
                {"domain": DOMAIN, "org_id": org_id},
            )
        db.commit()
    return int(org_id), has_auth_settings


def ensure_user(db, org_id: int) -> None:
    auth0_user_id = f"local|{EMAIL}"
    user_id = db.execute(
        text("SELECT id FROM users WHERE auth0_user_id = :auth0_user_id LIMIT 1"),
        {"auth0_user_id": auth0_user_id},
    ).scalar_one_or_none()
    if user_id is None:
        user_id = db.execute(
            text("SELECT id FROM users WHERE email = :email LIMIT 1"),
            {"email": EMAIL},
        ).scalar_one_or_none()
    password_hash = hash_password(PASSWORD)
    user_columns = _table_columns(db, "users")
    if user_id is None:
        values = {
            "organization_id": org_id,
            "auth0_user_id": auth0_user_id,
            "email": EMAIL,
            "email_verified": True,
            "password_hash": password_hash,
            "role": "admin",
            "is_active": True,
            "status": UserStatus.ACTIVE.value,
        }
        insert_cols = [key for key in values.keys() if key in user_columns]
        columns_sql = ", ".join(insert_cols)
        params_sql = ", ".join(f":{col}" for col in insert_cols)
        # False positive — see the organizations insert above; same reasoning.
        db.execute(
            text(f"INSERT INTO users ({columns_sql}) VALUES ({params_sql})"),  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            {key: values[key] for key in insert_cols},
        )
        db.commit()
        return
    updates = {
        "organization_id": org_id,
        "auth0_user_id": auth0_user_id,
        "email": EMAIL,
        "email_verified": True,
        "password_hash": password_hash,
        "role": "admin",
        "is_active": True,
        "status": UserStatus.ACTIVE.value,
    }
    update_cols = [key for key in updates.keys() if key in user_columns]
    if update_cols:
        set_sql = ", ".join(f"{col} = :{col}" for col in update_cols)
        params = {col: updates[col] for col in update_cols}
        params["user_id"] = user_id
        # False positive (A1 security remediation review): set_sql is
        # built from update_cols, filtered against user_columns (the
        # real table's own introspected schema); values are bound
        # parameters via `params`, never interpolated.
        db.execute(
            text(f"UPDATE users SET {set_sql} WHERE id = :user_id"),  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            params,
        )
    db.commit()


def main() -> None:
    with get_db_context() as db:
        org_id, has_auth_settings = ensure_org(db)
        ensure_user(db, org_id)
        if not has_auth_settings:
            print("Warning: auth_tenant_settings is missing. Run migrations so email-based login works.")
        print(f"Test user ready: {EMAIL} (org {org_id}:{ORG_SLUG})")


if __name__ == "__main__":
    main()
