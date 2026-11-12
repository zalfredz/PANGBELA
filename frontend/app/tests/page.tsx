"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { getTestResults, type TestResult } from "@/lib/api";
import { Button, EmptyState, ErrorState, errorText, LoadingState } from "@/components/ui";

type Load =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; rows: TestResult[] };

export default function TestsPage() {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [reloads, setReloads] = useState(0);

  useEffect(() => {
    let cancelled = false;
    getTestResults()
      .then((rows) => !cancelled && setLoad({ kind: "ready", rows }))
      .catch(
        (e) =>
          !cancelled &&
          setLoad({ kind: "error", message: errorText(e) }),
      );
    return () => {
      cancelled = true;
    };
  }, [reloads]);

  const reload = useCallback(() => {
    setLoad({ kind: "loading" });
    setReloads((n) => n + 1);
  }, []);

  const matched = load.kind === "ready" ? load.rows.filter((r) => r.match).length : 0;

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-end justify-between gap-3">
        <h1 className="text-2xl font-semibold">Uji skenario</h1>
        <Button onClick={reload}>Muat ulang</Button>
      </div>
      <p className="mb-5 max-w-prose text-muted">
        Setiap skenario menyerang dari alamat IP-nya sendiri. Kejadian terakhir dari alamat itu
        dibandingkan dengan hasil yang diharapkan tim cybersec. Hasil baru dihitung setelah agen
        selesai.
      </p>

      {load.kind === "loading" && <LoadingState label="Memuat hasil…" />}
      {load.kind === "error" && <ErrorState message={load.message} onRetry={reload} />}
      {load.kind === "ready" && load.rows.length === 0 && (
        <EmptyState title="Belum ada skenario uji.">
          Tim cybersec menambahkan skenario berlabel (T1 sampai T9) setelah uji di lab direkam.
        </EmptyState>
      )}
      {load.kind === "ready" && load.rows.length > 0 && (
        <>
          <p role="status" className="mb-3 text-sm">
            <span className="font-semibold">
              {matched} dari {load.rows.length}
            </span>{" "}
            skenario sesuai.
          </p>
          <div
            aria-hidden="true"
            className="hidden grid-cols-[5rem_8rem_8rem_7rem_1fr] gap-3 px-3 pb-2 text-xs font-semibold uppercase tracking-wider text-muted sm:grid"
          >
            <span>Kasus</span>
            <span>Diharapkan</span>
            <span>Hasil</span>
            <span>Cocok</span>
            <span>Kejadian</span>
          </div>
          <ul className="divide-y divide-line rounded border border-line bg-surface">
            {load.rows.map((r) => (
              <li
                key={r.test_case}
                className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 px-3 py-3 text-sm sm:grid-cols-[5rem_8rem_8rem_7rem_1fr] sm:items-center"
              >
                <span className="font-mono font-semibold">{r.test_case}</span>
                <span>
                  <span className="text-muted sm:hidden">Diharapkan </span>
                  {r.expected_status}
                </span>
                <span className="col-start-2 sm:col-start-auto">
                  <span className="text-muted sm:hidden">Hasil </span>
                  {r.actual_status ?? "belum dijalankan"}
                </span>
                <span
                  className={`col-start-2 font-medium sm:col-start-auto ${r.match ? "text-ok" : "text-bad"}`}
                >
                  {r.match ? "✓ sesuai" : r.actual_status === null ? "– belum ada hasil" : "✗ tidak sesuai"}
                </span>
                <span className="col-span-2 min-w-0 sm:col-span-1">
                  {r.incident_id ? (
                    <Link
                      href={`/incidents/${r.incident_id}`}
                      className="inline-flex min-h-11 items-center break-all font-mono text-xs text-accent underline-offset-2 hover:underline"
                    >
                      {r.incident_id}
                    </Link>
                  ) : (
                    <span className="text-muted">belum ada kejadian dari IP ini</span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
