# Server Overview

## Role

`server` is the upstream FastAPI backend.

It owns:

- authenticated tenant APIs
- public onboarding APIs
- activation
- auth and SSO
- assets, services, threats, appetite, recovery, scenarios, testing, and settings
- template library and template governance
- tenant isolation and public-onboarding isolation

## Main Entry Points

- `apps/server/src/api/main.py`
- `apps/server/src/api/routes/*.py`
- `apps/server/src/core/models.py`
- `apps/server/src/core/services/*`

## Critical Architectural Rules Visible In Code

- `TenantContextMiddleware` enforces authenticated tenant scoping
- `PreTenantGuardMiddleware` blocks public onboarding from touching tenant DB paths
- template, process, and service systems are split into distinct route families
- authenticated runtime and pre-tenant onboarding are intentionally separate subsystems

## Known Overlap

- older onboarding APIs and newer public onboarding workspace APIs coexist
- legacy migration SQL exists alongside Alembic history
- decision-support runtime is spread across threats, recovery, scenarios, signals, testing, and services routes

## Guardrails

- [The Resilience Interpretation Boundary](ca-05-resilience-interpretation-boundary.md) defines
  the enforced boundary between scanner evidence and human interpretation.
