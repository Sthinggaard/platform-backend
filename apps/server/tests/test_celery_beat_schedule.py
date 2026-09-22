"""Every scheduled sweep must actually be reachable.

A ``beat_schedule`` entry naming a task that is not registered does not raise
at import, at startup, or on the first tick — beat simply never runs it. That is
the same shape as the defect this suite gained a sweep for on 2026-09-07:
analysis was implemented, correct and tested, and ran zero times because nothing
scheduled it. A silent no-op is the worst failure mode a periodic job has, so
the wiring gets a test rather than trust.

``celery_app.conf.include`` is lazy: importing the app registers nothing, so
these assertions import exactly what a worker imports before checking. Asserting
against a bare import would pass while the schedule was entirely broken.
"""

from __future__ import annotations

import importlib

import pytest

from src.core.celery_app import celery_app


def _registered_task_names() -> set[str]:
    for module in celery_app.conf.include:
        importlib.import_module(module)
    return set(celery_app.tasks)


@pytest.mark.parametrize("entry_name", sorted(celery_app.conf.beat_schedule))
def test_every_beat_entry_resolves_to_a_registered_task(entry_name: str) -> None:
    task_name = celery_app.conf.beat_schedule[entry_name]["task"]
    assert task_name in _registered_task_names(), (
        f"beat entry {entry_name!r} points at {task_name!r}, which no module in "
        "celery_app.conf.include registers. Beat will skip it silently."
    )


@pytest.mark.parametrize("module", sorted(celery_app.conf.include))
def test_every_included_module_imports(module: str) -> None:
    """A module that raises on import takes its tasks down with it, and the
    worker keeps running with the rest — so the loss is partial and quiet."""
    assert importlib.import_module(module) is not None


def test_the_analysis_sweep_is_scheduled() -> None:
    """The specific regression: findings became AssetFindings automatically and
    then stopped, because nothing turned them into threats a person could act
    on. Read from the running platform on 2026-09-07 — 0 batches had ever
    reached ANALYZED."""
    tasks = {entry["task"] for entry in celery_app.conf.beat_schedule.values()}
    assert (
        "src.core.tasks.risk_intelligence_analysis_tasks.analyze_pending_ingestion_batches" in tasks
    )
