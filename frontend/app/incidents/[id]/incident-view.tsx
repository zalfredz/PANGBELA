"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  type Action,
  type AgentName,
  ApiError,
  decideRecommendation,
  type Evidence,
  getIncident,
  handToPamela,
  type IncidentDetail,
  type Recommendation,
  rerunIncident,
  revertAction,
  type Severity,
  type Status,
} from "@/lib/api";
import {
  actionEffect,
  actionTitle,
  AGENT_TEXT,
  agentConclusion,
  certainty,
  explain,
  latestRules,
  MANUAL_TEXT,
  PAMELA_BLOCK_TEXT,
  SEVERITY_TEXT,
  SOURCE_LABEL,
  STATUS_MEANING,
  STATUS_TEXT,
  TYPE_TEXT,
} from "@/lib/plain";
import {
  Button,
  EmptyState,
  ErrorState,
  errorText,
  formatTime,
  hasEarlyWarning,
  LoadingState,
  PipelineLabel,
  SectionTitle,
  SeverityBadge,
  shortTime,
  StatusLabel,
  targetText,
} from "@/components/ui";
import { type AgentStep, type Connection, useAgentStream } from "./use-agent-stream";

type Load =
  | { kind: "loading" }
  | { kind: "error"; message: string; notFound: boolean }
  | { kind: "ready"; detail: IncidentDetail };

export default function IncidentView() {
  const { id } = useParams<{ id: string }>();
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [reloads, setReloads] = useState(0);
  const refetchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [techOpen, setTechOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getIncident(id)
      .then((detail) => !cancelled && setLoad({ kind: "ready", detail }))
      .catch((e) => {
        if (cancelled) return;
        const notFound = e instanceof ApiError && e.status === 404;
        setLoad({ kind: "error", message: errorText(e), notFound });
      });
    return () => {
      cancelled = true;
    };
  }, [id, reloads]);

  // Evidence arrives in bursts; one refetch per burst is enough.
  const refetch = useCallback(() => {
    if (refetchTimer.current) clearTimeout(refetchTimer.current);
    refetchTimer.current = setTimeout(() => setReloads((n) => n + 1), 400);
  }, []);
  useEffect(() => () => void (refetchTimer.current && clearTimeout(refetchTimer.current)), []);

  // An [ev_…] link opens the evidence panel first, then jumps, so :target highlights it.
  const jumpTo = useRef<string | null>(null);
  const openEvidence = useCallback((evId: string) => {
    if (document.getElementById(evId)) {
      window.location.hash = evId;
      return;
    }
    jumpTo.current = evId;
    setTechOpen(true);
  }, []);
  useEffect(() => {
    if (techOpen && jumpTo.current && document.getElementById(jumpTo.current)) {
      window.location.hash = jumpTo.current;
      jumpTo.current = null;
    }
  }, [techOpen]);

  const stream = useAgentStream(id, refetch);
  const reload = () => setReloads((n) => n + 1);

  if (load.kind === "loading") return <LoadingState label="Memuat kejadian…" />;
  if (load.kind === "error")
    return (
      <div className="space-y-4">
        <BackLink />
        {load.notFound ? (
          <EmptyState title="Kejadian ini tidak ada.">
            Mungkin sudah dihapus, atau tautannya salah.
          </EmptyState>
        ) : (
          <ErrorState
            message={load.message}
            onRetry={() => {
              setLoad({ kind: "loading" });
              reload();
            }}
          />
        )}
      </div>
    );

  const d = load.detail;
  return (
    <div className="space-y-10">
      <div className="space-y-4">
        <BackLink />
        <Summary detail={d} techOpen={techOpen} onToggleTech={() => setTechOpen((o) => !o)} />
        {techOpen && <TechnicalPanel detail={d} />}
      </div>

      <section aria-labelledby="todo-title">
        <SectionTitle id="todo-title">Yang perlu dilakukan</SectionTitle>
        <Recommendations detail={d} onChanged={reload} />
      </section>

      <section aria-labelledby="how-title">
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
          <SectionTitle id="how-title">Bagaimana PANGBELA memutuskan</SectionTitle>
          <ConnectionNote connection={stream.connection} />
        </div>
        <AgentSteps detail={d} stream={stream} onEvidence={openEvidence} />
      </section>

      <Rerun detail={d} onDone={reload} />
    </div>
  );
}

function BackLink() {
  return (
    <Link href="/incidents" className="inline-flex min-h-11 items-center text-sm text-muted hover:text-ink">
      ← Dasbor
    </Link>
  );
}

function Summary({
  detail: d,
  techOpen,
  onToggleTech,
}: {
  detail: IncidentDetail;
  techOpen: boolean;
  onToggleTech: () => void;
}) {
  const inc = d.incident;
  const decided = inc.confidence !== null;
  const { title, body } = explain(d);
  const sure = certainty(d);
  const rules = latestRules(d);
  const conflict = [...d.agent_runs].reverse().find((r) => r.agent === "rules")?.rules_conflict;
  return (
    <header className="space-y-4 rounded border border-line bg-surface p-4 sm:p-6">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {decided && <SeverityBadge severity={inc.severity} />}
        {decided && <StatusLabel status={inc.status} />}
        <span className="text-sm text-muted">{TYPE_TEXT[inc.attack_type]}</span>
      </div>
      <h1 className="text-xl font-semibold leading-snug sm:text-2xl">{title}</h1>

      {hasEarlyWarning(inc) && (
        <p className="max-w-prose rounded border-2 border-bad px-3 py-2">
          <span className="font-semibold">Peringatan dini.</span> Sebelum agen selesai, aturan
          sudah menilai ini <span className="font-medium">{STATUS_TEXT[inc.provisional_status!].toLowerCase()}</span>{" "}
          dengan tingkat <span className="font-medium">{SEVERITY_TEXT[inc.provisional_severity!].toLowerCase()}</span>{" "}
          ({shortTime(inc.provisional_at)}). Hasil akhir muncul setelah agen selesai.
        </p>
      )}

      <div className="max-w-prose space-y-2 leading-relaxed">
        {body.map((s) => (
          <p key={s}>{s}</p>
        ))}
        {decided && <p className="text-muted">{STATUS_MEANING[inc.status]} {sure}</p>}
        {conflict && rules && (
          <p className="text-muted">
            Agen sempat mengusulkan “{STATUS_TEXT[rules.proposed as Status]?.toLowerCase()}”, tapi aturan
            hanya mengizinkan “{STATUS_TEXT[rules.allowed as Status]?.toLowerCase()}”. Yang dipakai
            adalah keputusan aturan.
          </p>
        )}
      </div>

      {inc.pipeline_state !== "done" && (
        <p>
          Status analisis: <PipelineLabel state={inc.pipeline_state} />
        </p>
      )}

      <div className="flex flex-col gap-3 border-t border-line pt-4 sm:flex-row sm:items-center sm:justify-between">
        <p className="break-all font-mono text-sm text-muted">
          dari {inc.src_ip} ke {targetText(inc)} ·{" "}
          {inc.first_seen === inc.last_seen
            ? formatTime(inc.first_seen)
            : `${formatTime(inc.first_seen)} sampai ${shortTime(inc.last_seen)}`}
        </p>
        <Button onClick={onToggleTech} aria-expanded={techOpen} aria-controls="bukti-teknis">
          {techOpen ? "Tutup bukti teknis" : `Lihat bukti teknis (${d.evidence.length})`}
        </Button>
      </div>
    </header>
  );
}

function TechnicalPanel({ detail: d }: { detail: IncidentDetail }) {
  const inc = d.incident;
  return (
    <section
      id="bukti-teknis"
      aria-label="Bukti teknis"
      className="space-y-5 rounded border border-line bg-surface p-4 sm:p-6"
    >
      <div>
        <h2 className="font-semibold">Bukti teknis</h2>
        <p className="mt-1 max-w-prose text-sm text-muted">
          Untuk analis. Teks dari agen ditulis dalam bahasa Inggris dan tidak diubah.
        </p>
      </div>

      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
        <TechFact label="Keyakinan (bukan tingkat bahaya)">
          {inc.confidence === null ? "-" : `${inc.confidence_level} · ${inc.confidence.toFixed(2)}`}
        </TechFact>
        <TechFact label="Verifikasi">{inc.verification_state ?? "-"}</TechFact>
        <TechFact label="Cakupan catatan">
          {inc.evidence_coverage === null ? "-" : `${Math.round(inc.evidence_coverage * 100)}%`}
        </TechFact>
      </dl>

      {inc.summary && (
        <div>
          <h3 className="text-sm font-medium">Ringkasan dari agen Keputusan</h3>
          <p className="mt-1 max-w-prose text-sm">{inc.summary}</p>
        </div>
      )}

      <div>
        <h3 className="text-sm font-medium">Catatan log ({d.evidence.length})</h3>
        <p className="mt-1 text-sm text-muted">Klik satu baris untuk melihat isi aslinya.</p>
        <EvidenceList items={d.evidence} />
      </div>

      {inc.report_md && (
        <details className="rounded border border-line">
          <summary className="flex min-h-11 cursor-pointer items-center px-3 text-sm font-medium">
            Laporan lengkap dari agen Keputusan
          </summary>
          {/* Written by an agent from attacker-influenced input: plain text, never HTML. */}
          <pre className="whitespace-pre-wrap break-words border-t border-line p-3 font-sans text-sm leading-relaxed">
            {inc.report_md}
          </pre>
        </details>
      )}
    </section>
  );
}

function TechFact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-muted">{label}</dt>
      <dd className="font-mono">{children}</dd>
    </div>
  );
}

function EvidenceList({ items }: { items: Evidence[] }) {
  if (items.length === 0) return <p className="mt-2 text-sm text-muted">Belum ada catatan tersimpan.</p>;
  return (
    <ul className="mt-2 divide-y divide-line rounded border border-line">
      {items.map((e) => (
        <li key={e.id} id={e.id} className="scroll-mt-4 px-3 target:bg-sev-medium-bg">
          <details>
            <summary className="flex min-h-11 cursor-pointer flex-wrap items-baseline gap-x-3 py-2 text-sm">
              <span className="font-mono text-xs text-muted">{formatTime(e.ts).slice(11, 19)}</span>
              <span className="text-xs text-muted">{SOURCE_LABEL[e.source]}</span>
              <span className="min-w-0 flex-1 break-words">{e.summary}</span>
            </summary>
            <div className="pb-3 text-xs">
              <p className="font-mono text-muted">{e.id}</p>
              <pre className="mt-1 whitespace-pre-wrap break-all rounded bg-paper p-3 font-mono">{e.raw}</pre>
            </div>
          </details>
        </li>
      ))}
    </ul>
  );
}

// --- what to do -----------------------------------------------------------------------

// The operator token is a lab credential, kept in sessionStorage only for the tab's
// lifetime. shortcut: no login/session yet, so any script on the page could read it;
// upgrade to a server-side session before this leaves the isolated lab.
const TOKEN_KEY = "ai-soc.operator-token";

function Recommendations({ detail: d, onChanged }: { detail: IncidentDetail; onChanged: () => void }) {
  const [token, setToken] = useState(() => {
    try {
      return typeof window === "undefined" ? "" : (sessionStorage.getItem(TOKEN_KEY) ?? "");
    } catch {
      return "";
    }
  });
  const [busy, setBusy] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [note, setNote] = useState<string | null>(null);

  const recs = d.recommendations;
  if (recs.length === 0)
    return (
      <EmptyState title="Belum ada saran tindakan.">
        {d.incident.pipeline_state === "done"
          ? "Agen tidak menyarankan tindakan apa pun untuk kejadian ini."
          : "Agen Keputusan menyusun saran di akhir analisis."}
      </EmptyState>
    );

  const pamelaReason = d.pamela.blocked_reason;
  const pending = recs.filter((r) => r.status === "pending");
  const forPamela = pending.filter((r) => pamelaReason === null && r.system_target !== null);
  const activeActions = d.actions.filter((a) => isActive(a));
  const authToken = token.trim();

  async function act(key: string, fn: () => Promise<unknown>) {
    setBusy(key);
    setErrors((e) => ({ ...e, [key]: "" }));
    try {
      await fn();
      onChanged();
    } catch (e) {
      setErrors((x) => ({ ...x, [key]: errorText(e) }));
      if (e instanceof ApiError && e.status === 409) onChanged();
    } finally {
      setBusy(null);
    }
  }

  async function allToPamela() {
    setBusy("all");
    setNote(null);
    let done = 0;
    for (const r of forPamela) {
      try {
        await handToPamela(r.id, authToken);
        done += 1;
      } catch (e) {
        setErrors((x) => ({ ...x, [r.id]: errorText(e) }));
      }
    }
    setNote(`PAMELA mengerjakan ${done} dari ${forPamela.length} saran.`);
    setBusy(null);
    onChanged();
  }

  return (
    <div className="space-y-4">
      {pending.length > 0 && (
        <div
          className={`max-w-prose rounded border px-4 py-3 ${pamelaReason === "needs_human" ? "border-bad" : "border-line bg-surface"}`}
        >
          {pamelaReason === null && forPamela.length === 0 ? (
            <p>
              <span className="font-semibold">Sisa saran perlu dikerjakan manusia.</span> PAMELA sudah
              mengerjakan bagiannya, atau saran ini di luar kemampuannya.
            </p>
          ) : pamelaReason === null ? (
            <p>
              <span className="font-semibold">PAMELA bisa membantu.</span> Kasus ini tingkat{" "}
              {SEVERITY_TEXT[d.incident.severity].toLowerCase()}, jadi PAMELA boleh menjalankan saran
              di bawah untuk Anda. Semua yang dikerjakan PAMELA tercatat dan bisa dibatalkan.
            </p>
          ) : (
            <p>
              {pamelaReason === "needs_human" && <span className="font-semibold">Perlu keputusan Anda. </span>}
              {PAMELA_BLOCK_TEXT[pamelaReason]}
            </p>
          )}
          <LabNote lastPull={d.lab_last_pull_at} />
        </div>
      )}

      {(pending.length > 0 || activeActions.length > 0) && (
        <label className="flex max-w-sm flex-col gap-1">
          <span className="text-sm font-medium">Token operator</span>
          <input
            type="password"
            value={token}
            onChange={(e) => {
              setToken(e.target.value);
              try {
                sessionStorage.setItem(TOKEN_KEY, e.target.value);
              } catch {
                // Private mode or blocked storage: the token just isn't remembered.
              }
            }}
            autoComplete="off"
            aria-describedby="token-help"
            className="min-h-11 rounded border border-line bg-surface px-3"
          />
          <span id="token-help" className="text-sm text-muted">
            Dikirim sebagai X-Operator-Token; nama pencatat diambil server, bukan dari isian.
            Wajib untuk menyetujui, menolak, atau membatalkan. PAMELA tidak butuh token.
          </span>
        </label>
      )}

      {forPamela.length > 1 && (
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="primary" disabled={busy !== null} onClick={allToPamela}>
            {busy === "all" ? "PAMELA sedang bekerja…" : `Serahkan semua ke PAMELA (${forPamela.length})`}
          </Button>
          {note && (
            <p role="status" className="text-sm text-muted">
              {note}
            </p>
          )}
        </div>
      )}

      <ul className="divide-y divide-line rounded border border-line bg-surface">
        {recs.map((r) => {
          const action = d.actions.find((a) => a.recommendation_id === r.id) ?? null;
          const canPamela = r.status === "pending" && pamelaReason === null && r.system_target !== null;
          return (
            <li key={r.id} className="space-y-3 px-4 py-4">
              <div>
                <p className="font-medium">{actionTitle(r)}</p>
                <p className="mt-0.5 max-w-prose text-sm text-muted">
                  {r.system_target === null && r.manual_reason
                    ? MANUAL_TEXT[r.manual_reason]
                    : actionEffect(r, d.pamela.block_seconds)}
                </p>
              </div>

              {r.status === "pending" ? (
                <div className="flex flex-wrap gap-2">
                  {canPamela ? (
                    <Button
                      variant="primary"
                      disabled={busy !== null}
                      onClick={() => act(r.id, () => handToPamela(r.id, authToken))}
                    >
                      {busy === r.id ? "PAMELA sedang bekerja…" : "Serahkan ke PAMELA"}
                    </Button>
                  ) : (
                    <Button
                      variant="primary"
                      disabled={!authToken || busy !== null}
                      onClick={() => act(r.id, () => decideRecommendation(r.id, "approved", authToken))}
                    >
                      {r.system_target ? "Setujui dan jalankan" : "Setujui, saya kerjakan manual"}
                    </Button>
                  )}
                  <Button
                    disabled={!authToken || busy !== null}
                    onClick={() => act(r.id, () => decideRecommendation(r.id, "rejected", authToken))}
                  >
                    Tolak
                  </Button>
                </div>
              ) : (
                <Outcome rec={r} action={action} lastPull={d.lab_last_pull_at} />
              )}

              {action && isActive(action) && (
                <Button
                  disabled={!authToken || busy !== null}
                  onClick={() => act(action.id, () => revertAction(action.id, authToken))}
                >
                  Batalkan tindakan ini
                </Button>
              )}
              {(errors[r.id] || (action && errors[action.id])) && (
                <p role="alert" className="text-sm text-bad">
                  {errors[r.id] || (action && errors[action.id])}
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function isActive(a: Action): boolean {
  return a.reverted_at === null && (a.expires_at === null || new Date(a.expires_at) > new Date());
}

function LabNote({ lastPull }: { lastPull: string | null }) {
  return (
    <p className="mt-2 text-sm text-muted">
      {lastPull
        ? `Lab terakhir mengambil daftar tindakan pukul ${shortTime(lastPull)}.`
        : "Lab belum tersambung: tindakan akan tercatat, tapi belum diterapkan ke lab sampai lab mengambil daftarnya."}
    </p>
  );
}

function Outcome({ rec, action, lastPull }: { rec: Recommendation; action: Action | null; lastPull: string | null }) {
  if (rec.status === "rejected")
    return (
      <p className="text-sm">
        <span className="font-medium">Ditolak</span> oleh {rec.decided_by} · {shortTime(rec.decided_at)}
      </p>
    );
  if (!action)
    return (
      <p className="text-sm">
        <span className="font-medium">Disetujui</span> oleh {rec.decided_by} · {shortTime(rec.decided_at)}.
        Dikerjakan manual.
      </p>
    );
  const by = action.by_pamela ? "Dikerjakan PAMELA" : `Disetujui dan dijalankan oleh ${action.executed_by}`;
  let state: string;
  if (action.reverted_at) state = `Dibatalkan oleh ${action.reverted_by} · ${shortTime(action.reverted_at)}`;
  else if (action.expires_at && new Date(action.expires_at) <= new Date()) state = "Sudah berakhir";
  else {
    const until = action.expires_at ? `Aktif sampai ${shortTime(action.expires_at)}` : "Aktif";
    const lab = action.fetched_at
      ? "sudah diambil lab"
      : lastPull
        ? "menunggu lab mengambil daftar"
        : "belum diterapkan, lab belum tersambung";
    state = `${until}, ${lab}`;
  }
  return (
    <div className="text-sm">
      <p>
        <span className="font-medium">{by}</span> · {shortTime(action.created_at)}
      </p>
      <p className="text-muted">{state}</p>
    </div>
  );
}

// --- how it was decided ---------------------------------------------------------------

function ConnectionNote({ connection }: { connection: Connection }) {
  const text: Record<Connection, string> = {
    connecting: "Menyambung…",
    live: "Langsung",
    reconnecting: "Sambungan putus, menyambung ulang…",
    closed: "Sambungan tertutup. Muat ulang halaman.",
  };
  return (
    <p className={`text-xs ${connection === "live" ? "text-ok" : "text-muted"}`}>
      {connection === "live" && <span aria-hidden="true">● </span>}
      {text[connection]}
    </p>
  );
}

function AgentSteps({
  detail: d,
  stream,
  onEvidence,
}: {
  detail: IncidentDetail;
  stream: ReturnType<typeof useAgentStream>;
  onEvidence: (id: string) => void;
}) {
  const inc = d.incident;
  // Only the latest run: earlier ones read the same logs and are summed up under
  // "Analisis ulang" instead of being stacked here.
  const steps = stream.runs[stream.runs.length - 1] ?? [];
  if (steps.length === 0)
    return (
      <EmptyState title={inc.pipeline_state === "queued" ? "Menunggu agen mulai." : "Belum ada aktivitas agen."}>
        {inc.pipeline_state === "queued" && "Agen mulai begitu tidak ada alarm baru selama beberapa detik."}
      </EmptyState>
    );
  const latency = (agent: string, round: number) =>
    [...d.agent_runs].reverse().find((r) => r.agent === agent && r.round === round)?.latency_ms ?? null;
  const rules = inc.pipeline_state === "done" && inc.confidence !== null ? latestRules(d) : null;
  const decisionOut = [...steps].reverse().find((s) => s.agent === "decision")?.output;
  const proposedSeverity = decisionOut?.proposed_severity as Severity | undefined;

  return (
    <div className="space-y-3">
      <ol className="divide-y divide-line rounded border border-line bg-surface" aria-live="polite">
        {steps.map((s, i) => (
          <li key={i}>
            <StepRow
              n={i + 1}
              step={s}
              latencyMs={s.state === "running" ? null : latency(s.agent, s.round)}
              onEvidence={onEvidence}
            />
          </li>
        ))}
        {rules && (
          <li className="flex gap-3 px-4 py-4">
            <span aria-hidden="true" className="w-5 shrink-0 font-mono text-sm text-muted">
              {steps.length + 1}
            </span>
            <div className="min-w-0 flex-1">
              <h3 className="font-medium">Aturan PANGBELA</h3>
              <p className="text-sm text-muted">Pemeriksaan tetap tanpa AI. Langkah ini yang menentukan hasil akhir.</p>
              <p className="mt-1.5 flex flex-wrap items-center gap-2">
                Hasil akhir: <SeverityBadge severity={inc.severity} />
                <StatusLabel status={inc.status} />
              </p>
              {proposedSeverity && proposedSeverity !== inc.severity && (
                <p className="mt-1 text-sm text-muted">
                  Agen Keputusan mengusulkan tingkat {SEVERITY_TEXT[proposedSeverity].toLowerCase()}, aturan
                  menetapkan {SEVERITY_TEXT[inc.severity].toLowerCase()}.
                </p>
              )}
            </div>
          </li>
        )}
      </ol>
      {stream.failure && (
        <div role="alert" className="rounded border border-bad/40 bg-surface px-4 py-3 text-sm">
          <p className="font-medium text-bad">
            Analisis berhenti di langkah {AGENT_TEXT[stream.failure.agent as AgentName]?.name ?? stream.failure.agent}.
          </p>
          <p className="mt-1 break-words text-muted">{stream.failure.error}</p>
          <p className="mt-1 text-muted">Hasil sebelumnya tidak diubah. Anda bisa menjalankan analisis ulang.</p>
        </div>
      )}
    </div>
  );
}

type Finding = { claim: string; evidence_ids: string[] };

function StepRow({
  n,
  step,
  latencyMs,
  onEvidence,
}: {
  n: number;
  step: AgentStep;
  latencyMs: number | null;
  onEvidence: (id: string) => void;
}) {
  const a = AGENT_TEXT[step.agent];
  const o = step.output;
  const findings = (key: string) => (o && Array.isArray(o[key]) ? (o[key] as Finding[]) : []);
  const all = [...findings("indicators"), ...findings("findings"), ...findings("counter_evidence")];
  return (
    <article className="flex gap-3 px-4 py-4">
      <span aria-hidden="true" className="w-5 shrink-0 font-mono text-sm text-muted">
        {n}
      </span>
      <div className="min-w-0 flex-1">
        <header className="flex flex-wrap items-baseline justify-between gap-x-3">
          <h3 className="font-medium">
            {a.name}
            {step.round > 1 && <span className="font-normal text-muted"> (putaran {step.round})</span>}
          </h3>
          {latencyMs !== null && (
            <span className="font-mono text-xs text-muted">{(latencyMs / 1000).toFixed(1)} detik</span>
          )}
        </header>
        <p className="text-sm text-muted">{a.role}</p>
        <p className={`mt-1.5 ${step.state === "ok" ? "" : step.state === "running" ? "text-accent" : "text-bad"}`}>
          {step.state === "running"
            ? "Sedang bekerja…"
            : step.state === "invalid"
              ? "Jawabannya tidak lolos pemeriksaan format."
              : step.state === "error"
                ? "Gagal."
                : o
                  ? agentConclusion(step.agent, o)
                  : "Selesai."}
        </p>
        {o && (all.length > 0 || step.agent === "detection") && (
          <details className="mt-1 text-sm">
            <summary className="inline-flex min-h-11 cursor-pointer items-center text-muted hover:text-ink">
              Lihat bukti dan alasan<span className="sr-only"> agen {a.name}</span>
            </summary>
            <div className="max-w-prose space-y-2 pb-1">
              {step.agent === "detection" && typeof o.hypothesis === "string" && <p>{o.hypothesis}</p>}
              <ul className="space-y-2">
                {all.map((f, i) => (
                  <li key={i} className="border-l-2 border-line pl-3">
                    {f.claim}{" "}
                    {f.evidence_ids.map((ev) => (
                      <a
                        key={ev}
                        href={`#${ev}`}
                        onClick={(e) => {
                          e.preventDefault();
                          onEvidence(ev);
                        }}
                        // py/-my: a 44px tap target without making the sentence's lines taller.
                        className="-my-3.5 mr-1 inline-block py-3.5 font-mono text-xs text-accent underline-offset-2 hover:underline"
                      >
                        [{ev}]
                      </a>
                    ))}
                  </li>
                ))}
              </ul>
            </div>
          </details>
        )}
      </div>
    </article>
  );
}

// --- rerun ----------------------------------------------------------------------------

function Rerun({ detail: d, onDone }: { detail: IncidentDetail; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const running = d.incident.pipeline_state === "running" || d.incident.pipeline_state === "queued";
  const verdicts = d.agent_runs
    .filter((r) => r.agent === "rules" && r.status === "ok" && r.output_json)
    .map((r) => `${r.output_json!.status}/${r.output_json!.severity}`);
  const n = verdicts.length;
  const same = n > 1 && verdicts[n - 1] === verdicts[n - 2];

  async function rerun() {
    setBusy(true);
    setNote(null);
    try {
      await rerunIncident(d.incident.id);
      setNote("Masuk antrean. Agen mulai dalam beberapa detik dan butuh sekitar 2 menit.");
      onDone();
    } catch (e) {
      setNote(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="rerun-title" className="rounded border border-line bg-surface p-4 sm:p-6">
      <h2 id="rerun-title" className="font-semibold">
        Analisis ulang
      </h2>
      <p className="mt-1 max-w-prose text-sm text-muted">
        Agen membaca lagi catatan yang sama. Karena hasil akhirnya ditentukan aturan dari catatan itu,
        hasilnya akan sama, kecuali ada catatan baru yang masuk atau analisis sebelumnya gagal. Saran yang
        sudah diputuskan tidak akan muncul lagi.
      </p>
      {n > 0 && (
        <p className="mt-2 text-sm">
          Sudah dianalisis {n} kali.
          {n > 1 && (same ? " Hasil terakhir sama dengan sebelumnya." : " Hasil terakhir berbeda dari sebelumnya.")}
        </p>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <Button onClick={rerun} disabled={busy || running}>
          {running ? "Analisis sedang berjalan" : busy ? "Mengantrekan…" : "Analisis ulang"}
        </Button>
        {note && (
          <p role="status" className="text-sm text-muted">
            {note}
          </p>
        )}
      </div>
    </section>
  );
}
