-- Team baseline of 11 Nov 2026 (docs/build-spec.md, section 12).

-- Brute force incidents can be opened by auth log events alone, which carry no
-- destination address.
ALTER TABLE incidents ALTER COLUMN dest_ip DROP NOT NULL;
ALTER TABLE incidents
  ADD COLUMN opened_by text NOT NULL DEFAULT 'suricata'
    CHECK (opened_by IN ('suricata','auth_log')),
  ADD COLUMN verification_state text
    CHECK (verification_state IN ('verified','partially_verified','insufficient_telemetry')),
  ADD COLUMN evidence_coverage numeric(3,2) CHECK (evidence_coverage BETWEEN 0 AND 1),
  ADD COLUMN confidence_level text CHECK (confidence_level IN ('low','medium','high')),
  -- Rules-only assessment before the agents run, for early warnings.
  ADD COLUMN provisional_status text
    CHECK (provisional_status IN ('benign','suspected','attempted','confirmed')),
  ADD COLUMN provisional_severity text
    CHECK (provisional_severity IN ('none','low','medium','high','critical')),
  ADD COLUMN provisional_verification text
    CHECK (provisional_verification IN
      ('verified','partially_verified','insufficient_telemetry')),
  ADD COLUMN provisional_at timestamptz;

-- Every login event the shipper posts, kept before any incident exists, so the
-- brute force threshold can be counted across batches. event_time is the log's own
-- time; ingested_at is ours.
CREATE TABLE auth_events (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_time   timestamptz NOT NULL,
  src_ip       inet NOT NULL,
  result       text NOT NULL CHECK (result IN ('success','failure')),
  raw          text NOT NULL,
  fields       jsonb NOT NULL,
  ingested_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX auth_events_src_idx ON auth_events (src_ip, event_time);
-- A resent batch must not count the same line twice.
CREATE UNIQUE INDEX auth_events_line_idx ON auth_events (event_time, md5(raw));
