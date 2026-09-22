# BFF Overview

## Role

`bff` is the backend-for-frontend / edge policy layer.

It proxies requests to `server`, applies edge middleware, exposes metrics, and normalizes browser-facing behavior such as CORS and rate limiting.

## Confirmed Responsibilities

- upstream request forwarding
- auth header enforcement for authenticated calls
- public onboarding forwarding
- per-minute rate limiting
- Prometheus metrics
- CORS policy
- request ID forwarding
- edge-side logging with sanitized onboarding path handling

## Main Entry Points

- `apps/bff/app.py`
- `apps/bff/openapi.json`

## Known Gap

- in-memory rate limiting is visible in code and not shared across workers

