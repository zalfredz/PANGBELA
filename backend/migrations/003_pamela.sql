-- PAMELA and approved actions (docs/build-spec.md, section 13).

-- One row per approved recommendation that the system can carry out. The lab pulls
-- the active rows from GET /enforcement and applies them; the backend itself never
-- touches a firewall, an account or a host.
CREATE TABLE actions (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id        uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  recommendation_id  uuid NOT NULL UNIQUE REFERENCES recommendations(id) ON DELETE CASCADE,
  action             text NOT NULL
                     CHECK (action IN ('block_ip','reset_password','isolate_host','monitor')),
  -- Taken from the incident by code, never from the agent's text.
  target             text NOT NULL,
  by_pamela          boolean NOT NULL,
  executed_by        text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz,          -- block_ip only
  fetched_at         timestamptz,          -- first time the lab pulled this row
  reverted_at        timestamptz,
  reverted_by        text
);
CREATE INDEX actions_incident ON actions (incident_id);

-- Before this migration a rerun asked again about actions already decided. Drop those
-- repeats; the pipeline no longer creates them (save_node).
DELETE FROM recommendations p
USING recommendations d
WHERE p.incident_id = d.incident_id AND p.action = d.action
  AND p.status = 'pending' AND d.status <> 'pending'
  AND (p.action <> 'patch_endpoint' OR p.target = d.target);

-- When the lab last pulled the enforcement list, so the dashboard can say whether
-- anything is reading it at all.
CREATE TABLE lab_status (
  id            int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  last_pull_at  timestamptz
);
