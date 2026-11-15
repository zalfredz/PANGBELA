"use client";

import { useEffect, useState } from "react";

import { getHealth } from "@/lib/api";

/**
 * The dashboard must not look like an AI investigation is running when no provider is
 * configured. Deterministic detection, early warning and evidence still work, so say so
 * instead of showing a green "analyzed" impression.
 */
export function AiAvailability() {
  const [configured, setConfigured] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    getHealth()
      .then((h) => {
        if (!cancelled) setConfigured(h.llm_configured);
      })
      .catch(() => {
        if (!cancelled) setConfigured(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (configured !== false) return null;
  return (
    <p
      role="status"
      className="rounded border border-line bg-surface px-4 py-3 text-sm text-muted"
    >
      <span className="font-medium text-ink">AI belum dikonfigurasi.</span> Analisis agen
      tertunda; deteksi deterministik, peringatan dini, dan penyimpanan bukti tetap berjalan.
      Hasil yang tampil di bawah berasal dari rules gate, bukan dari AI.
    </p>
  );
}
