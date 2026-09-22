FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN mkdir -p /app/server

# System deps for compiled wheels + curl for healthchecks
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry for dependency management
RUN pip install --no-cache-dir poetry

# Copy dependency definitions first for better build caching
COPY apps/server/pyproject.toml apps/server/poetry.lock* ./server/

WORKDIR /app/server

# Install only runtime dependencies (skip dev extras)
RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-interaction --no-root

WORKDIR /app

# Copy application code
COPY apps/bff ./bff
# Keep the server layout expected by bff/start.sh and expose it through PYTHONPATH.
COPY apps/server/src ./server/src

RUN chmod +x /app/bff/start.sh

# A1 security remediation — Trivy/Semgrep container-scan findings: this
# image ran as root by default with no USER directive. Dependencies are
# installed system-wide (poetry config virtualenvs.create false above) so
# the non-root user only needs read access to /app.
RUN groupadd --system app && useradd --system --gid app --home /app app \
    && chown -R app:app /app
USER app

EXPOSE 8080

CMD ["/app/bff/start.sh"]
