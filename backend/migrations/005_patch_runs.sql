-- Read-only patch lifecycle records (Phase 5). Written by the operator-run lab executor
-- through an authenticated endpoint; the backend never applies a patch itself.
CREATE TABLE patch_runs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id       uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  template_id       text NOT NULL,
  template_version  text NOT NULL,
  target_id         text NOT NULL,
  allowed           boolean NOT NULL,
  reason            text NOT NULL,
  result            text NOT NULL,
  audit_ref         text NOT NULL,
  detail            jsonb NOT NULL DEFAULT '{}'::jsonb,
  recorded_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX patch_runs_incident_time ON patch_runs (incident_id, recorded_at DESC);
