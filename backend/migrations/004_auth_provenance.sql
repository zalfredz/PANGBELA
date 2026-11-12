-- Ingestion provenance for login events. Their producer can state whether a login was
-- authorized, so which producer wrote a row matters; older rows predate the column.
ALTER TABLE auth_events ADD COLUMN producer text NOT NULL DEFAULT 'unknown';
