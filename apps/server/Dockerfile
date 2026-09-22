FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

ARG POETRY_EXTRAS=openai

WORKDIR /app

# Trivy container scan (A1 security gate) found 475 CRITICAL/HIGH CVEs in
# the base image's Debian packages, all with fixes already published
# upstream (--ignore-unfixed still surfaced them) — this image was never
# upgrading the base layer's own packages, only installing new ones on top
# of whatever was baked into the python:3.11-slim tag at build time.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry

# Build context is apps/server in DigitalOcean App Platform.
COPY pyproject.toml poetry.lock ./

# Install runtime deps (optionally include extras via build-arg)
RUN poetry install --only main --extras "${POETRY_EXTRAS}" --no-root

# Copy application code
COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini
# The migrate step runs this before `alembic upgrade head`: it carries a database
# stamped at one of the archived revisions onto `20260910_schema_baseline`, and
# refuses to when the schema does not match the models. Without it the image has
# an entrypoint that cannot start — staging found that out on 2026-09-10, and the
# guard held.
#
# This one file, not `scripts/`. That directory also holds `create_test_user.py`
# and `generate_test_jwt.py`, which have no business in a runtime image.
COPY scripts/ensure_schema.py ./scripts/ensure_schema.py

# BUG-DISC-10: the evidence directory must exist in the image, owned by app.
# The API and the discovery worker share it as a named volume, and Docker
# seeds a fresh named volume from the image's directory — ownership included.
# Without it the volume is created root-owned, and the non-root process cannot
# write evidence at all.
#
# Trivy container scan (A1 security gate) also flagged this image running
# as root — a real defense-in-depth gap, not just a CVE count. Dependencies
# are installed system-wide (POETRY_VIRTUALENVS_CREATE=false) so the
# non-root user only needs read access to /app; port 8000 needs no
# privileged-port capability.
RUN groupadd --system app && useradd --system --gid app --home /app app \
    && mkdir -p /app/var/discovery-evidence \
    && chown -R app:app /app
USER app

EXPOSE 8000

CMD ["sh", "-c", "uvicorn src.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
