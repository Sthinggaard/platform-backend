# Risklence backend

Status: **partial** — local extraction of the current Risklence backend workspace on 2026-09-22. It has no remote and no release pipeline yet.

This repository contains the FastAPI server (`apps/server`), Python BFF (`apps/bff`), and operator scanner agent (`apps/scanner`). It excludes the tenant and www applications, Storybook, and design system. Browser clients connect through the BFF; set CORS and callback URLs for their actual origins.

## Local setup

1. Copy `.env.example` to `.env.local` and set local values. Never commit real credentials.
2. Install Poetry in the server and scanner directories: `poetry install` in each.
3. Run `docker compose --env-file .env.local -f docker/docker-compose.yml up --build` for API, BFF, Postgres, MongoDB, Redis, and Mailpit.
4. Run `docker compose --env-file .env.local -f docker/docker-compose.yml run --rm api alembic upgrade head` before using a fresh database.
5. Start optional Celery processes with the `workers` profile. The scanner is an operator-side package and is installed or built separately from `apps/scanner`.

The Compose file uses the same local container names and ports as the original workspace. Stop that stack before starting this one. These are separate copies of the code, with no automatic synchronization.

## Checks

- `cd apps/server && poetry run pytest tests/ --tb=short`
- `cd apps/bff && PYTHONPATH=../server:.. poetry --directory ../server run pytest tests/ --tb=short`
- `cd apps/scanner && poetry run pytest tests/ --tb=short`
- `docker compose --env-file .env.local -f docker/docker-compose.yml config --quiet`

The architecture notes in `docs/architecture` describe the server and BFF boundaries. The extraction record in `tasks/active` identifies what was copied and what remains to validate.
