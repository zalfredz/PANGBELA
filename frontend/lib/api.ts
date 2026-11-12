// Typed helpers for the FastAPI backend (spec section 8). The dashboard talks only to
// this API: never to the database or the LLM, so no secret reaches the browser.

export const API_BASE = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000").replace(
  /\/$/,
  "",
);

export type Status = "benign" | "suspected" | "attempted" | "confirmed";
export type Severity = "none" | "low" | "medium" | "high" | "critical";
export type AttackType = "rce" | "brute_force" | "unknown";
export type PipelineState = "queued" | "running" | "done" | "failed";
export type AgentName = "detection" | "investigation" | "forensics" | "decision";

export type Verification = "verified" | "partially_verified" | "insufficient_telemetry";

export interface Incident {
  id: string;
  attack_type: AttackType;
  status: Status;
  severity: Severity;
  // Set only by the rules gate; null until the first verdict.
  confidence: number | null;
  confidence_level: "low" | "medium" | "high" | null;
  evidence_coverage: number | null;
  verification_state: Verification | null;
  scanner_likely: boolean;
  src_ip: string;
  // null when login events opened the incident: they carry no destination address.
  dest_ip: string | null;
  opened_by: "suricata" | "auth_log";
  // Rules-only assessment before the agents run (early warning).
  provisional_status: Status | null;
  provisional_severity: Severity | null;
  provisional_verification: Verification | null;
  provisional_at: string | null;
  first_seen: string;
  last_seen: string;
  summary: string | null;
  report_md: string | null;
  pipeline_state: PipelineState;
  created_at: string;
  updated_at: string;
}

export interface Evidence {
  id: string;
  source: "suricata" | "access_log" | "auth_log" | "process";
  ts: string;
  src_ip: string | null;
  summary: string;
  raw: string;
  fields: Record<string, unknown>;
  collected_by: string;
  created_at: string;
}

export interface AgentRun {
  id: string;
  agent: AgentName | "rules";
  round: number;
  status: "ok" | "invalid" | "error";
  output_json: Record<string, unknown> | null;
  cited_evidence_ids: string[];
  rules_conflict: string | null;
  model: string | null;
  latency_ms: number | null;
  error: string | null;
  started_at: string;
  finished_at: string | null;
}

export type ManualReason =
  | "manual_only"
  | "protected_ip"
  | "no_host"
  | "no_account"
  | "several_accounts";

export interface Recommendation {
  id: string;
  action: "block_ip" | "reset_password" | "isolate_host" | "patch_endpoint" | "monitor";
  // Written by the Decision agent; shown only when the system has no target of its own.
  target: string;
  reason: string;
  status: "pending" | "approved" | "rejected";
  decided_by: string | null;
  decided_at: string | null;
  // What approving acts on, taken from the incident by code; null = a manual task.
  system_target: string | null;
  manual_reason: ManualReason | null;
}

export interface Action {
  id: string;
  recommendation_id: string;
  action: Recommendation["action"];
  target: string;
  by_pamela: boolean;
  executed_by: string;
  created_at: string;
  expires_at: string | null;
  fetched_at: string | null;
  reverted_at: string | null;
  reverted_by: string | null;
}

export type PamelaBlock = "not_decided" | "no_threat" | "needs_human";

export interface IncidentDetail {
  incident: Incident;
  alerts: unknown[];
  evidence: Evidence[];
  agent_runs: AgentRun[];
  recommendations: Recommendation[];
  actions: Action[];
  pamela: { blocked_reason: PamelaBlock | null; max_severity: Severity; block_seconds: number };
  lab_last_pull_at: string | null;
}

export type Queue = "needs_human" | "pamela" | "running" | "done";

export interface ListedIncident extends Incident {
  queue: Queue;
}

export interface IncidentPage {
  items: ListedIncident[];
  next_before: string | null;
}

export type Overview = Record<Queue, number>;

export interface TestResult {
  test_case: string;
  incident_id: string | null;
  expected_status: string;
  actual_status: string | null;
  match: boolean;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    detail: string,
  ) {
    super(detail);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "network", `Tidak bisa menghubungi ${API_BASE}. Pastikan backend berjalan.`);
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    throw new ApiError(
      res.status,
      body?.error ?? "http_error",
      body?.detail ?? `Request failed with HTTP ${res.status}`,
    );
  }
  return body as T;
}

export interface IncidentFilters {
  status?: Status;
  severity?: Severity;
  attack_type?: AttackType;
  queue?: Queue;
}

export const getOverview = () => request<Overview>("/incidents/overview");

export function listIncidents(filters: IncidentFilters, before?: string | null) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) if (v) q.set(k, v);
  if (before) q.set("before", before);
  q.set("limit", "50");
  return request<IncidentPage>(`/incidents?${q}`);
}

export const getIncident = (id: string) =>
  request<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`);

export const rerunIncident = (id: string) =>
  request<{ id: string; pipeline_state: string }>(`/incidents/${encodeURIComponent(id)}/rerun`, {
    method: "POST",
  });

const operatorHeaders = (token: string) => ({ "X-Operator-Token": token });

export const decideRecommendation = (id: string, decision: "approved" | "rejected", token: string) =>
  request<Recommendation & { action: Action | null }>(
    `/recommendations/${encodeURIComponent(id)}/decision`,
    { method: "POST", body: JSON.stringify({ decision }), headers: operatorHeaders(token) },
  );

export const handToPamela = (id: string, token: string) =>
  request<Recommendation & { action: Action | null }>(
    `/recommendations/${encodeURIComponent(id)}/pamela`,
    { method: "POST", headers: operatorHeaders(token) },
  );

export const revertAction = (id: string, token: string) =>
  request<Action>(`/actions/${encodeURIComponent(id)}/revert`, {
    method: "POST",
    headers: operatorHeaders(token),
  });

export const getTestResults = () => request<TestResult[]>("/tests/results");

export const streamUrl = (id: string) => `${API_BASE}/incidents/${encodeURIComponent(id)}/stream`;
