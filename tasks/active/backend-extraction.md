---
kind: active-task
status: partial
last-updated: 2026-09-22
domain: platform
skill: none
---

# Backend repository extraction

## Outcome

Create a separate local repository containing the server, BFF, and scanner, without the tenant or www frontend applications.

## Direction record

- **Owning domain:** Platform repository and deployment boundary.
- **Authoritative System records:** `docs/architecture/server/README.md`, `docs/architecture/bff/README.md`, `docs/architecture/server/ca-05-resilience-interpretation-boundary.md`.
- **Applicable Skill:** None.
- **Reuse rung and selected component:** Existing backend modules copied unchanged; no UI.
- **Expected files:** `apps/server`, `apps/bff`, `apps/scanner`, backend Compose stack, local configuration, README, this record.
- **Verification:** File inventory, secret exclusion, Compose config, targeted server/BFF/scanner tests.

## Scope and acceptance criteria

- Current working-tree backend files, including uncommitted backend work, are copied to a new Git repository.
- No tenant/www/Storybook/design-system source is present.
- The existing workspace remains untouched.
- No production or GitHub remote is changed.

## Human decision required

A future remote name, hosting location, and migration plan for production/staging pipelines are not specified.

## Implementation log

Copied backend application source, tests, migrations, and package manifests from the active checkout. Frontend Compose service and unused test runner removed. Browser origins and callback URLs are configurable for separately hosted clients.

## Verification evidence

Compose configuration passed with the sample copied to ignored `.env.local`. Targeted tests using the existing Python 3.11 environment: server `test_process_scan_scope_service.py` 14 passed; BFF `test_bff_auth.py` 3 passed; scanner `test_config.py` 5 passed. Full suites, Docker image builds, and live integration were not run.

## Handoff and residual risk

The new repository is a point-in-time snapshot. Subsequent backend changes in the original repository will not flow here automatically. The existing deployment pipelines still build from the original repository.
