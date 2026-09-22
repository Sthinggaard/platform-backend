"""#463 — a Business Service records only its exceptions to each Business Process's BIA

Creates `service_bia_exceptions`: one row per service, process and BIA field where the service
genuinely differs from the process. Then it records, as exceptions, the differences already held in
`business_services.bia_answers`.

**Why.** Søren, 2026-09-15 (option B): the owner sees the process's answers and records only what
differs, with a structured reason. Until now `PUT /services/{id}` stored the whole questionnaire for
every service, so 17 of org 7's 25 services held their own answers even where they matched.

**Per process.** A service in several processes is compared with each one separately. The same answer
can be inherited in one process and an exception in another.

**The process BIA compared against** is resolved as `effective_process_bia_service` does on
2026-09-15, frozen here because a migration must not import application code that later changes:
1. the process's latest non-superseded assessment, if it is attested;
2. otherwise the organisation's latest active baseline;
3. otherwise nothing, if an assessment was started and never attested;
4. otherwise the legacy `value_streams.bia_answers`.

**What is recorded.** For each of the seven BIA fields a service answered (a non-empty value):
- identical to the process's answer: nothing is recorded, so it reads as inherited;
- different, or the process has no answer for it: an exception with `recorded_before_reasons = true`.
  `previous_value` holds the process's answer. There is no reason and no actor.
  `recorded_at` is when this migration ran, because the answer's original time was never stored.

**What is not touched.**
- `business_services.bia_answers` itself. Every reader still uses it until the per-process resolver
  replaces them (#463 slice B). Removing copied answers waits for the write path (slice C).
- `serviceOwnerTitle` and `impactPath`, which are not BIA answers and never become exceptions.
- A process id in `value_stream_ids` that does not exist in the service's organisation.

**Report.** Per organisation: answers that became inherited, answers kept as exceptions, answers kept
because the process has no BIA, and services holding answers with no process to compare against.

Idempotent: the table is guarded, and a field that already has an active exception is skipped.

**On the inline `nosemgrep`.** `avoid-sqlalchemy-text` fires on f-string statements. The only values
interpolated are this module's constants, so nothing a request can reach. Suppressed at the site with
the rule id, as `20260915_slot_assessment` does.

Revision ID: 20260915_service_bia_exceptions
Revises: 20260915_slot_assessment
Create Date: 2026-09-15 00:00:00.000000
"""

import logging

import sqlalchemy as sa

from alembic import op

# ⚠️ 32 characters is the hard limit for `alembic_version.version_num`; this is 31.
revision = "20260915_service_bia_exceptions"
down_revision = "20260915_slot_assessment"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

TABLE = "service_bia_exceptions"
ACTIVE_UNIQUE_INDEX = "uq_service_bia_exceptions_active"
INDEXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ix_service_bia_exceptions_org_service", ("organization_id", "service_id")),
    ("ix_service_bia_exceptions_process", ("process_id",)),
)

#: Frozen copy of `bia_inheritance_service.BIA_FIELD_KEYS` on 2026-09-15.
BIA_FIELD_KEYS: tuple[str, ...] = (
    "alternativeChannel",
    "dataSensitivity",
    "impact1h",
    "impact24h",
    "impact4h",
    "mtd",
    "workaround",
)
_FIELDS = "ARRAY[" + ", ".join(f"'{field}'" for field in BIA_FIELD_KEYS) + "]::text[]"


def columns() -> list[sa.Column]:
    """The table's columns. One definition, so the test can hold it against the model."""
    return [
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "service_id",
            sa.String(length=36),
            sa.ForeignKey("business_services.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "process_id",
            sa.String(length=36),
            sa.ForeignKey("value_streams.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("field", sa.String(length=40), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("previous_value", sa.Text(), nullable=True),
        sa.Column("reason_code", sa.String(length=40), nullable=True),
        sa.Column("reason_note", sa.Text(), nullable=True),
        sa.Column("recorded_before_reasons", sa.Boolean(), nullable=False),
        sa.Column(
            "recorded_by_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("recorded_at", sa.DateTime(), nullable=False),
        sa.Column("withdrawn_at", sa.DateTime(), nullable=True),
        sa.Column(
            "withdrawn_by_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    ]


# Every answered BIA field of every service, against each of its processes' BIA in force.
_FIELD_ANSWERS = f"""
WITH current_assessment AS (
    SELECT DISTINCT ON (a.process_id) a.process_id, a.status, a.answers
    FROM process_bia_assessments AS a
    WHERE a.status <> 'superseded'
    ORDER BY a.process_id, a.created_at DESC
),
active_baseline AS (
    SELECT DISTINCT ON (b.organization_id) b.organization_id, b.answers
    FROM organization_bia_baselines AS b
    WHERE b.status = 'active'
    ORDER BY b.organization_id, b.created_at DESC
),
service_process AS (
    SELECT
        s.organization_id,
        s.id AS service_id,
        p.id AS process_id,
        s.bia_answers,
        CASE
            WHEN ca.status = 'attested' THEN ca.answers
            WHEN ab.organization_id IS NOT NULL THEN ab.answers
            WHEN ca.process_id IS NOT NULL THEN NULL
            ELSE p.bia_answers
        END AS process_answers
    FROM business_services AS s
    CROSS JOIN LATERAL (
        SELECT DISTINCT l.link_id FROM unnest(s.value_stream_ids) AS l(link_id)
    ) AS link
    JOIN value_streams AS p
        ON p.id = link.link_id AND p.organization_id = s.organization_id
    LEFT JOIN current_assessment AS ca ON ca.process_id = p.id
    LEFT JOIN active_baseline AS ab ON ab.organization_id = s.organization_id
    WHERE jsonb_typeof(s.bia_answers) = 'object'
),
field_answer AS (
    SELECT
        sp.organization_id,
        sp.service_id,
        sp.process_id,
        f.field,
        sp.bia_answers ->> f.field AS service_value,
        CASE
            WHEN jsonb_typeof(sp.process_answers) = 'object' THEN sp.process_answers ->> f.field
        END AS process_value,
        COALESCE(jsonb_typeof(sp.process_answers) = 'object', false) AS process_has_bia
    FROM service_process AS sp
    CROSS JOIN unnest({_FIELDS}) AS f(field)
    WHERE NULLIF(btrim(sp.bia_answers ->> f.field), '') IS NOT NULL
)
"""

BACKFILL_SERVICE_BIA_EXCEPTIONS = sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    f"""
{_FIELD_ANSWERS}
INSERT INTO service_bia_exceptions (
    id, organization_id, service_id, process_id, field, value, previous_value,
    reason_code, reason_note, recorded_before_reasons, recorded_by_user_id, recorded_at,
    withdrawn_at, withdrawn_by_user_id, created_at, updated_at
)
SELECT
    gen_random_uuid()::text, fa.organization_id, fa.service_id, fa.process_id, fa.field,
    fa.service_value, fa.process_value,
    NULL, NULL, true, NULL, now() AT TIME ZONE 'utc',
    NULL, NULL, now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc'
FROM field_answer AS fa
WHERE fa.service_value IS DISTINCT FROM fa.process_value
  AND NOT EXISTS (
      SELECT 1 FROM service_bia_exceptions AS e
      WHERE e.service_id = fa.service_id
        AND e.process_id = fa.process_id
        AND e.field = fa.field
        AND e.withdrawn_at IS NULL
  )
"""
)

REPORT_BY_ORGANIZATION = sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    f"""
{_FIELD_ANSWERS}
SELECT
    fa.organization_id,
    count(*) FILTER (WHERE fa.process_has_bia AND fa.service_value = fa.process_value) AS inherited,
    count(*) FILTER (
        WHERE fa.process_has_bia AND fa.service_value IS DISTINCT FROM fa.process_value
    ) AS exceptions,
    count(*) FILTER (WHERE NOT fa.process_has_bia) AS kept_without_process_bia
FROM field_answer AS fa
GROUP BY fa.organization_id
ORDER BY fa.organization_id
"""
)

COUNT_SERVICES_WITHOUT_PROCESS = sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    f"""
SELECT s.organization_id, count(*) AS services
FROM business_services AS s
WHERE jsonb_typeof(s.bia_answers) = 'object'
  AND EXISTS (
      SELECT 1 FROM unnest({_FIELDS}) AS f(field)
      WHERE NULLIF(btrim(s.bia_answers ->> f.field), '') IS NOT NULL
  )
  AND NOT EXISTS (
      SELECT 1 FROM value_streams AS p
      WHERE p.organization_id = s.organization_id AND p.id = ANY(s.value_stream_ids)
  )
GROUP BY s.organization_id
ORDER BY s.organization_id
"""
)


def _table_exists(conn, table: str) -> bool:
    return (
        conn.execute(
            sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"), {"t": table}
        ).first()
        is not None
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, TABLE):
        op.create_table(TABLE, *columns())
        for name, index_columns in INDEXES:
            op.create_index(name, TABLE, list(index_columns))
        op.create_index(
            ACTIVE_UNIQUE_INDEX,
            TABLE,
            ["service_id", "process_id", "field"],
            unique=True,
            postgresql_where=sa.text("withdrawn_at IS NULL"),
        )

    recorded = conn.execute(BACKFILL_SERVICE_BIA_EXCEPTIONS).rowcount
    logger.info("%s: recorded %s exceptions carried over from service answers", revision, recorded)
    for organization_id, inherited, exceptions, kept in conn.execute(REPORT_BY_ORGANIZATION):
        logger.info(
            "%s: organization %s: %s answers read as inherited, %s kept as exceptions, "
            "%s kept because the process has no BIA",
            revision,
            organization_id,
            inherited,
            exceptions,
            kept,
        )
    for organization_id, services in conn.execute(COUNT_SERVICES_WITHOUT_PROCESS):
        logger.info(
            "%s: organization %s: %s services hold answers but no process to compare against; "
            "left untouched",
            revision,
            organization_id,
            services,
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, TABLE):
        op.drop_index(ACTIVE_UNIQUE_INDEX, table_name=TABLE)
        for name, _ in INDEXES:
            op.drop_index(name, table_name=TABLE)
        op.drop_table(TABLE)
