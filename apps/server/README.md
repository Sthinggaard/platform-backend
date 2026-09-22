# Risklence Backend (FastAPI)

The core backend API service for the Risklence platform, providing asset management, onboarding, and monitoring capabilities.

## Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL (or SQLite for development)

### Setup and Run

This project uses **Poetry** for dependency management.

```bash
# Install dependencies with Poetry
poetry install

# Run database migrations
poetry run python migrations/run_migration.py

# Start the server (default port 8000)
make api-dev
```

**Alternative: Using Poetry Shell**
```bash
# Activate Poetry virtual environment
poetry shell

# Then run commands without 'poetry run' prefix
python migrations/run_migration.py
make api-dev
```

### Verify
- API root: http://localhost:8000
- Health check: `curl http://localhost:8000/api/v1/org/current`

## Key Endpoints

### Asset Onboarding (UC-01/UC-02)
- `POST /api/v1/orgs/{org_id}/assets` - Create new asset
- `GET /api/v1/orgs/{org_id}/assets/schema?primary_layer=L7` - Get OSI layer schema
- `POST /api/v1/orgs/{org_id}/assets/{asset_id}/complete-setup` - Complete access setup
- `POST /api/v1/orgs/{org_id}/assets/{asset_id}/verify-connection` - Verify connectivity
- `GET /api/v1/orgs/{org_id}/assets/{asset_id}/setup-instructions` - Get setup instructions

### Onboarding Canvas
- `POST /api/v1/onboarding/` - Start onboarding session
- `GET /api/v1/onboarding/{session_id}/events` - Get onboarding events
- `POST /api/v1/onboarding/{session_id}/prompt/respond` - Respond to prompts

### Assets & Monitoring
- `GET /api/v1/assets` - List all assets
- `POST /api/v1/assets/{asset_id}/connect` - Connect asset
- `GET /api/v1/assets/{asset_id}/findings` - List findings
- `GET /api/v1/assets/{asset_id}/status-history` - Status history

### Audit
- `GET /api/v1/audit/controls` - List control evidences
- `GET /api/v1/audit/overview` - Audit coverage metrics
- `POST /api/v1/audit/export` - Export audit bundle

## Database Migrations

Migrations are located in `migrations/` and should be run in order.

### Available Migrations
1. `001_add_multi_tenancy.sql` - Multi-tenancy support
2. `007_add_asset_connectivity.sql` - Asset connectivity status
3. `008_provider_agnostic_assets.sql` - Provider-agnostic asset model
4. `009_add_provider_resource_id.sql` - Provider resource identifiers

### Run Migrations
```bash
python migrations/run_migration.py
```

### Local API Run Command
```bash
make api-dev
```

This target runs the API with:
- `DEBUG=false`
- `MONITORING_ENABLED=false`
- `uvicorn src.api.main:app --reload --port 8000`

### Database Connectivity Check
```bash
make db-check
```

Expected result:
```text
('risklence_app', 'defaultdb')
```

### Rollback (if needed)
```bash
# Manually run rollback SQL files
psql -d risklence -f migrations/009_add_provider_resource_id_rollback.sql
```

## Architecture

This backend serves as the **upstream API** for the BFF (Backend-for-Frontend) layer.

```
Frontend (:3000) → BFF (:8080) → Backend (:8000)
```

The backend is provider-agnostic and uses the OSI layer model for asset classification.

### External planning-tool boundary

Plane is an external planning, documentation, backlog, and project-structure tool used by the Risklence team. It is not part of the Risklence product.

Risklence must not:

- depend on Plane or Plane Cloud at runtime;
- require a Plane installation, account, subscription, or customer integration;
- send customer data, credentials, tenant records, or operational events to Plane;
- import Plane APIs, SDKs, URLs, identifiers, or authentication into product code;
- make customer functionality unavailable when Plane is unreachable or removed.

Plane links may be used in internal work items and delivery documentation only. The Risklence repository, product APIs, database, audit records, and customer-facing documentation remain authoritative for the product.

### Plane Pages maintenance procedure

Detailed Claude/Codex handover for Plane access, task pickup, sprint branch creation, page updates, and image-asset handling lives at `tasks/guidance/checklists/plane-claude-handover.md`.

For internal Plane documentation on the self-hosted Community Edition installation, do not use the Plane Pages API tools. The API path has been unreliable for frontend-visible content. Use direct installation access and keep the editor fields consistent.

For a page to be visible in the project UI:

1. The `Page` record must exist in the Risklence workspace.
2. The `ProjectPage` through-row must exist with the same workspace and project IDs; the UI filters pages through this relationship.
3. `Page.description_html`, `Page.description_stripped`, and `Page.description_json` must be updated together.
4. `Page.description_binary` must not be left stale. Regenerate it through Plane's internal converter when available. If conversion is unavailable, clear it to `NULL` so the frontend does not continue rendering the old serialized editor state.
5. Verify from the database that the new `description_html` contains the expected text and that the stale binary payload is gone or regenerated, then hard-refresh the browser page.

The stale-page failure mode is specific: a direct update to `description_html` can appear successful in the database while the browser still renders the old document from `description_binary`. A second observed failure mode is that the visible page shows a rewritten copy of the documentation underneath the old content instead of integrating the update into the existing section. Do not treat an HTML-only update or a duplicated appended rewrite as complete. Updates must preserve useful existing content and edit or extend the relevant section in place.

The duplication failure has been confirmed in the self-hosted editor: a stale open page can autosave its previous editor state after a direct correction, producing multiple concatenated top-level documents. Close or reload all open copies of the page before correcting it. When repairing a duplicated page, retain exactly one canonical top-level document, preserve its `image-component` nodes, clear stale `description_binary` if it cannot be regenerated, and verify one primary heading plus the expected image count before reopening the page.

For text-only updates, preserve the existing HTML and edit only the targeted paragraph, list item, table cell, or caption. Do not regenerate and append a complete page. The image-component ID set and order must remain unchanged for a text-only update. For image additions, reuse the existing `FileAsset.id`, insert one image node at the step it explains, and add a caption immediately below it; asset presence alone does not prove correct context.

Documentation must describe only verified Risklence UI. Scanner setup belongs in two product contexts: initial tenant onboarding, and Business Process setup when scanner evidence is needed for a process. `Configuration -> Scanners` is not a setup wizard; it is the inventory view for scanners that already exist, with credential rotation and status review actions. Do not document `Configuration -> Scanners` as the place to install or approve new scanners. If an onboarding or Business Process scanner setup control is missing from the deployed frontend, record it as an implementation gap instead of inventing a label.

For the self-hosted Plane instance served through Tailscale HTTPS, Plane page asset uploads must not return presigned URLs on the LAN MinIO endpoint. Keep `AWS_S3_ENDPOINT_URL` internal to Docker (`http://plane-minio:9000`), enable `USE_MINIO=1`, force `MINIO_ENDPOINT_SSL=1`, and serve `/uploads` through Tailscale to `http://127.0.0.1:9000/uploads`. This makes browser upload URLs same-origin HTTPS, while background tasks can still reach MinIO internally. The upstream Plane AIO `start.sh` rewrites `plane.env` and hardcodes `USE_MINIO=0`; the custom Plane image must patch that startup script to preserve the compose-provided `USE_MINIO` and `MINIO_ENDPOINT_SSL` values, or the browser will receive `http://plane-minio:9000/uploads`.

This procedure is for internal documentation only. It must never be added as a Risklence runtime dependency or exposed as a customer requirement.

## Environment Variables

Create a `.env` file in the server directory (see `.env.example`). You may copy `.env.local`
from the repo root for development. The env file must include database credentials plus the
shared JWT secret described below.

```bash
DATABASE_URL=postgresql://user:pass@localhost/risklence
# Or use SQLite for dev:
# DATABASE_URL=sqlite:///./risklence.db

AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_AUDIENCE=https://api.risklence.com
AUTH0_TESTING_SECRET=your-testing-secret-for-dev-tokens

# Local auth / SSO
AUTH_JWT_SECRET=<your-generated-secret>
AUTH_ACCESS_TOKEN_TTL=15
AUTH_REFRESH_TOKEN_TTL=30
AUTH_REFRESH_COOKIE_NAME=rl_refresh
FRONTEND_BASE_URL=http://localhost:3000
SSO_CALLBACK_URL=http://localhost:3000/auth/sso/callback
SSO_GOOGLE_CLIENT_ID=
SSO_GOOGLE_CLIENT_SECRET=
SSO_GOOGLE_REDIRECT_URI=
SSO_MS_CLIENT_ID=
SSO_MS_CLIENT_SECRET=
SSO_MS_REDIRECT_URI=
```

### JWT secret management

- Generate the secret with `poetry run python scripts/generate_jwt_secret.py --env ../.env.local` (or point `--env` at the env file you actually source). It prints a URL-safe base64 value and, when given `--env`, injects it as both `AUTH_JWT_SECRET` and `SECRET_KEY`.
- Make sure every process that validates bearer tokens (API, BFF, CLI scripts) starts with that same env file so HS256 signatures can be verified. For example:
  ```bash
  source .env.local
  poetry run uvicorn src.api.main:app --reload --port 8000
  ```
- Rotate the secret by re-running the script, updating the env file(s), and restarting all services simultaneously so tokens signed with the new key stay valid.

## Development

## Auth Strategy

Access tokens are short-lived JWTs (HS256) signed by `AUTH_JWT_SECRET`. Refresh tokens are opaque, rotated on every refresh, and stored hashed in `user_sessions` with reuse detection. If a rotated refresh token is reused, all sessions for the user are revoked.

SSO linking policy:
- If `user_identities` contains `(provider, sub)`, log that user in.
- Else if a verified email matches an existing user and `SSO_AUTO_LINK` is enabled, link the identity.
- Else if `SSO_AUTO_PROVISION` is enabled, create a user and link the identity.
- Otherwise deny the SSO login.

## Frontend Integration Contract

- `POST /api/v1/auth/login` returns `access_token` and sets the refresh token cookie (`AUTH_REFRESH_COOKIE_NAME`).
- `POST /api/v1/auth/refresh` expects the refresh cookie (or `refresh_token` in body) and returns a new access token while rotating the refresh token cookie.
- `GET /api/v1/auth/me` is used for session restore; the frontend should call `/auth/refresh` first if it lacks a valid access token.
- SSO callbacks set the refresh cookie and redirect to `SSO_CALLBACK_URL` or `FRONTEND_BASE_URL`. The frontend should call `/auth/refresh` after redirect to obtain an access token.

### Code Structure
- `src/api/` - API routes and schemas
  - `routes/assets.py` - Asset management endpoints
  - `routes/onboarding.py` - Onboarding flow endpoints
  - `schemas/` - Pydantic request/response schemas
  - `middleware/` - Tenant context and auth middleware
- `src/core/` - Core business logic
  - `models.py` - SQLAlchemy database models
  - `services/` - Business logic services
  - `constants/` - Enums and constants
- `src/asset_monitoring/` - Asset monitoring engine
- `migrations/` - Database migrations

### Running Tests
```bash
make test-server  # Ensures the local Docker test DB exists, then runs pytest safely
pytest  # Also safe now: pytest forces DATABASE__DATABASE_URL to the local test DB
pytest tests/test_assets.py  # Run specific test file
```

Pytest now forces `DATABASE__DATABASE_URL` to `TEST_POSTGRES_URL`, which defaults to
`postgresql://risklence:risklence_dev_password@localhost:5433/risklence_test_db`.
If `TEST_POSTGRES_URL` points to a non-local host, pytest will refuse to start unless
you explicitly set `ALLOW_REMOTE_TEST_DATABASE=true`.

### Code Formatting
```bash
black .  # Format all Python files
isort .  # Sort imports
```

## Troubleshooting

### Port Already in Use
```bash
# Check what's using port 8000
lsof -i :8000

# Run on different port
uvicorn src.api.main:app --reload --port 8001
```

### Database Connection Issues
- Verify PostgreSQL is running: `psql -l`
- Check `DATABASE_URL` in `.env`
- Ensure migrations have been run

### 422 Unprocessable Entity Errors
- Verify request payload matches Pydantic schema
- Check API docs at `/docs` for expected format
- Enable debug logging to see validation errors

## Related Documentation
- [DEVELOPMENT_SETUP.md](../docs/DEVELOPMENT_SETUP.md) - Full stack setup guide
- [HANDOVER_ASSET_ONBOARDING.md](../docs/HANDOVER_ASSET_ONBOARDING.md) - Asset onboarding implementation
- [UC-01.md](../docs/UC-01.md) - OSI-first asset onboarding use case
- [UC-02.md](../docs/UC-02.md) - Complete access setup use case
