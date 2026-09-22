# Database Migrations

This directory contains SQL migration scripts for Risklence Tower.

## Migration Files

- `001_add_multi_tenancy.sql` - Adds multi-tenant tables and columns
- `001_add_multi_tenancy_rollback.sql` - Rollback script for multi-tenancy migration

## Running Migrations

### Option 1: Using psql (Command Line)

```bash
# Apply migration
psql -U your_user -d risklence_tower -f migrations/001_add_multi_tenancy.sql

# Rollback migration (WARNING: This will delete data)
psql -U your_user -d risklence_tower -f migrations/001_add_multi_tenancy_rollback.sql
```

### Option 2: Using Python Script

```bash
# Apply migration
python migrations/run_migration.py apply 001

# Rollback migration
python migrations/run_migration.py rollback 001
```

### Option 3: Using Docker

```bash
# Copy migration into Docker container
docker cp migrations/001_add_multi_tenancy.sql postgres-container:/tmp/

# Execute migration
docker exec -it postgres-container psql -U postgres -d risklence_tower -f /tmp/001_add_multi_tenancy.sql
```

## Migration 001: Add Multi-Tenancy

This migration transforms Risklence Tower from single-tenant to multi-tenant SaaS:

### New Tables Created:
- `organizations` - Root tenant entity with subscription info
- `users` - Multi-tenant users linked to Auth0
- `cloud_credentials` - Encrypted credential storage per organization

### Modified Tables:
Adds `organization_id` column to:
- `compliance_frameworks` (nullable - NULL = global)
- `compliance_controls` (nullable - NULL = global)
- `policy_rules` (nullable - NULL = global)
- `cloud_assets` (required)
- `scan_runs` (required)
- `findings` (required)
- `jira_tickets` (required)
- `key_risk_indicators` (required)
- `risk_appetite` (required + composite unique key)

### Indexes Created:
- All `organization_id` columns are indexed for performance
- Additional indexes on commonly queried fields

### Safety Features:
- Uses `DO $$ ... END $$` blocks to check if columns exist before adding
- Creates default organization for existing data
- Includes rollback script for safe reversal

## Best Practices

1. **Backup Before Migration**: Always backup your database before running migrations
   ```bash
   pg_dump risklence_tower > backup_before_migration.sql
   ```

2. **Test in Development First**: Run migrations in development/staging before production

3. **Review Changes**: Read the SQL file to understand what changes will be made

4. **Monitor Performance**: For large databases, some operations may take time

## Troubleshooting

**Error: "relation already exists"**
- The migration is idempotent and checks for existing tables/columns
- Safe to re-run if it fails partway through

**Error: "column already exists"**
- The migration checks for existing columns
- If you see this, the migration may have already been partially applied

**Need to Rollback:**
```bash
python migrations/run_migration.py rollback 001
```

## Future: Alembic Integration

This project will eventually use Alembic for automated migrations. For now, manual SQL scripts provide maximum control and transparency.

```bash
# Future setup (not yet implemented)
alembic init alembic
alembic revision --autogenerate -m "Add multi-tenancy"
alembic upgrade head
```
