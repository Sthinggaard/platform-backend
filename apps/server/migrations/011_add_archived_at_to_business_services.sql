-- Add soft-archive support to business_services (BPD-20)
-- Services are never hard-deleted; archived_at IS NOT NULL means removed from process view.

ALTER TABLE business_services
    ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP NULL;
