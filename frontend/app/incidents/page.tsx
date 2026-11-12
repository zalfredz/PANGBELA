"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  getOverview,
  type ListedIncident,
  listIncidents,
  type Overview,
  type Queue,
} from "@/lib/api";
import { listTitle, QUEUE_TEXT, TYPE_TEXT } from "@/lib/plain";
import {
  Button,
  EmptyState,
  ErrorState,
  errorText,
  hasEarlyWarning,
  LoadingState,
  SeverityBadge,
  shortTime,
  targetText,
} from "@/components/ui";

type Load =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: ListedIncident[]; next: string | null; overview: Overview };

const QUEUES: Queue[] = ["needs_human", "pamela", "running", "done"];
// Agents take about two minutes; a quiet refresh keeps "Sedang dianalisis" honest.
const REFRESH_MS = 10_000;

export default function Dashboard() {
  const [queue, setQueue] = useState<Queue | null>(null);
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<string | null>(null);
  const [reloads, setReloads] = useState(0);

  useEffect(() => {
    let cancelled = false;
    Promise.all([listIncidents(queue ? { queue } : {}), getOverview()])
      .then(([page, overview]) => {
        if (!cancelled)
          setLoad({ kind: "ready", items: page.items, next: page.next_before, overview });
      })
      .catch((e) => {
        if (!cancelled) setLoad({ kind: "error", message: errorText(e) });
      });
    return () => {
      cancelled = true;
    };
  }, [queue, reloads]);

  useEffect(() => {
    const t = setInterval(() => setReloads((n) => n + 1), REFRESH_MS);
    return () => clearInterval(t);
  }, []);

  const reload = useCallback(() => {
    setLoad({ kind: "loading" });
    setReloads((n) => n + 1);
  }, []);

  function pick(q: Queue | null) {
    setLoad({ kind: "loading" });
    setQueue((cur) => (cur === q ? null : q));
  }

  async function loadMore() {
    if (load.kind !== "ready" || !load.next) return;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const page = await listIncidents(queue ? { queue } : {}, load.next);
      setLoad({ ...load, items: [...load.items, ...page.items], next: page.next_before });
    } catch (e) {
      setMoreError(errorText(e));
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Dasbor</h1>
          <p className="mt-1 max-w-prose text-muted">
            Setiap serangan ke lab diperiksa agen, lalu aturan tetap menentukan hasilnya. Mulai dari
            yang butuh keputusan Anda.
          </p>
        </div>
        <Button onClick={reload}>Muat ulang</Button>
      </div>

      {load.kind === "ready" && (
        <div role="group" aria-label="Saring menurut keadaan" className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {QUEUES.map((q) => (
            <QueueTile
              key={q}
              queue={q}
              count={load.overview[q]}
              active={queue === q}
              onClick={() => pick(q)}
            />
          ))}
        </div>
      )}

      <section aria-labelledby="list-title">
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
          <h2 id="list-title" className="text-base font-semibold">
            {queue ? QUEUE_TEXT[queue].label : "Semua kejadian"}
          </h2>
          {queue && (
            <button
              type="button"
              onClick={() => pick(null)}
              className="inline-flex min-h-11 items-center text-sm text-accent underline-offset-2 hover:underline"
            >
              Tampilkan semua
            </button>
          )}
        </div>

        {load.kind === "loading" && <LoadingState label="Memuat kejadian…" />}
        {load.kind === "error" && <ErrorState message={load.message} onRetry={reload} />}
        {load.kind === "ready" && load.items.length === 0 && (
          <EmptyState title={queue ? "Tidak ada kejadian di sini." : "Belum ada kejadian."}>
            {queue
              ? "Pilih kotak lain, atau tampilkan semua."
              : "Kejadian muncul di sini begitu alarm Suricata atau catatan login dari lab masuk."}
          </EmptyState>
        )}
        {load.kind === "ready" && load.items.length > 0 && (
          <>
            <ul className="space-y-2">
              {load.items.map((i) => (
                <li key={i.id}>
                  <IncidentCard incident={i} />
                </li>
              ))}
            </ul>
            <div className="mt-4 flex flex-col items-center gap-2">
              {moreError && (
                <p role="alert" className="text-sm text-bad">
                  {moreError}
                </p>
              )}
              {load.next && (
                <Button onClick={loadMore} disabled={loadingMore}>
                  {loadingMore ? "Memuat…" : "Tampilkan kejadian lebih lama"}
                </Button>
              )}
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function QueueTile({
  queue,
  count,
  active,
  onClick,
}: {
  queue: Queue;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  const urgent = queue === "needs_human" && count > 0;
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`flex min-h-24 flex-col items-start justify-between rounded border bg-surface p-4 text-left hover:border-muted ${
        active ? "border-ink ring-1 ring-ink" : urgent ? "border-bad" : "border-line"
      }`}
    >
      <span className="text-sm font-medium">{QUEUE_TEXT[queue].label}</span>
      <span className={`text-3xl font-semibold tabular-nums ${urgent ? "text-bad" : ""}`}>{count}</span>
      <span className="text-xs text-muted">{QUEUE_TEXT[queue].hint}</span>
    </button>
  );
}

const QUEUE_TONE: Record<Queue, string> = {
  needs_human: "text-bad font-semibold",
  pamela: "text-ink font-medium",
  running: "text-accent",
  done: "text-muted",
};

function IncidentCard({ incident: i }: { incident: ListedIncident }) {
  const decided = i.confidence !== null;
  const warn = hasEarlyWarning(i);
  return (
    <Link
      href={`/incidents/${i.id}`}
      className="block rounded border border-line bg-surface px-4 py-3 hover:border-muted"
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {warn ? (
          <span className="text-sm font-semibold text-bad">
            Peringatan dini: {i.provisional_severity === "critical" ? "kritis" : "tinggi"}
          </span>
        ) : decided ? (
          <SeverityBadge severity={i.severity} />
        ) : null}
        <span className="text-sm text-muted">{TYPE_TEXT[i.attack_type]}</span>
        <span className="text-sm text-muted">{shortTime(i.last_seen)}</span>
        <span className={`ml-auto text-sm ${QUEUE_TONE[i.queue]}`}>
          {i.pipeline_state === "failed" ? "Analisis gagal" : QUEUE_TEXT[i.queue].label}
          <span aria-hidden="true"> →</span>
        </span>
      </div>
      <p className="mt-1 font-medium">{listTitle(i.attack_type, decided ? i.status : null)}</p>
      <p className="break-all font-mono text-sm text-muted">
        dari {i.src_ip} ke {targetText(i)}
      </p>
    </Link>
  );
}
