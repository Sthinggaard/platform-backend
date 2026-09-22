-- UC-18: Thread references for sub-dialogs
ALTER TABLE onboarding_events
ADD COLUMN IF NOT EXISTS thread_ref VARCHAR(100);
