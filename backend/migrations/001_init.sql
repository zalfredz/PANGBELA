CREATE TABLE incidents (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  attack_type     text NOT NULL DEFAULT 'unknown'
                  CHECK (attack_type IN ('rce','brute_force','unknown')),
  status          text NOT NULL DEFAULT 'suspected'
                  CHECK (status IN ('benign','suspected','attempted','confirmed')),
  severity        text NOT NULL DEFAULT 'low'
                  CHECK (severity IN ('none','low','medium','high','critical')),
  confidence      numeric(3,2) CHECK (confidence BETWEEN 0 AND 1),
  scanner_likely  boolean NOT NULL DEFAULT false,
  src_ip          inet NOT NULL,
  dest_ip         inet NOT NULL,
  first_seen      timestamptz NOT NULL,
  last_seen       timestamptz NOT NULL,
  summary         text,
  report_md       text,
  pipeline_state  text NOT NULL DEFAULT 'queued'
                  CHECK (pipeline_state IN ('queued','running','done','failed')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incidents_grouping_idx ON incidents (src_ip, dest_ip, last_seen);

CREATE TABLE alerts (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id   uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  ts            timestamptz NOT NULL,
  src_ip        inet NOT NULL,
  dest_ip       inet NOT NULL,
  signature_id  bigint,
  signature     text,
  category      text,
  flow_id       bigint,
  raw_json      jsonb NOT NULL,
  received_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX alerts_incident_idx ON alerts (incident_id);

CREATE TABLE evidence (
  id            text PRIMARY KEY,           -- ev_xxxxxxxx
  incident_id   uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  source        text NOT NULL
                CHECK (source IN ('suricata','access_log','auth_log','process')),
  ts            timestamptz NOT NULL,
  src_ip        inet,
  summary       text NOT NULL,
  raw           text NOT NULL,
  fields        jsonb NOT NULL DEFAULT '{}',
  collected_by  text NOT NULL,              -- 'ingest' or agent name
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX evidence_incident_idx ON evidence (incident_id, ts);

CREATE TABLE agent_runs (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id         uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  agent               text NOT NULL
                      CHECK (agent IN ('detection','investigation','forensics','decision','rules')),
  round               int NOT NULL DEFAULT 1,
  status              text NOT NULL CHECK (status IN ('ok','invalid','error')),
  output_json         jsonb,
  cited_evidence_ids  text[] NOT NULL DEFAULT '{}',
  rules_conflict      text,                 -- set when rules overrode the proposal
  model               text,
  latency_ms          int,
  error               text,
  started_at          timestamptz NOT NULL,
  finished_at         timestamptz
);
CREATE INDEX agent_runs_incident_idx ON agent_runs (incident_id, started_at);

CREATE TABLE recommendations (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id  uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  action       text NOT NULL
               CHECK (action IN ('block_ip','reset_password','isolate_host','patch_endpoint','monitor')),
  target       text NOT NULL,
  reason       text NOT NULL,
  status       text NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending','approved','rejected')),
  decided_by   text,
  decided_at   timestamptz
);

CREATE TABLE test_cases (
  id                 text PRIMARY KEY,      -- 'T1' to 'T9'
  scenario           text NOT NULL,
  src_ip             inet NOT NULL,         -- each scenario attacks from its own IP
  attack_type        text NOT NULL,
  presence           text NOT NULL CHECK (presence IN ('attack','benign')),
  outcome            text NOT NULL CHECK (outcome IN ('successful','failed','not_applicable')),
  expected_status    text NOT NULL,
  expected_severity  text NOT NULL,
  expected_impact    text,
  expected_evidence  text
);
