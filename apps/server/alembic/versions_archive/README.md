# Archived migrations

The 131 revisions here ran between December 2024 and September 2026. They are
**not** on Alembic's version path and will never run again — the schema they
built incrementally is frozen in
`alembic/versions/20260910_schema_baseline.py`.

They are kept because they are the only record of *why* the schema looks the way
it does: which ticket added a column, which decision renamed one, which
migration moved `permission_profiles` from `connector_id` to a supertable.
Read them for that. Do not move one back onto the version path.

Two facts about them worth knowing before you trust one:

- The chain never built a database from nothing. `0001_baseline` was a no-op and
  nothing after it created `organizations`, `users`, or any other core table, so
  every revision here assumes a schema `create_all` had already produced.
- 32 of the ids are longer than Alembic's default `VARCHAR(32)` version column,
  so applying them to a database created before 2026-09-09 would fail on the
  bookkeeping rather than the DDL.
