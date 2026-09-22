-- Add optional description field to value_streams for process edit modal (BPD-19)

ALTER TABLE value_streams
    ADD COLUMN IF NOT EXISTS description TEXT NULL;
