import type { ReactNode } from "react";
import { ApiError, type Incident, type PipelineState, type Severity, type Status } from "@/lib/api";
import { ERROR_TEXT, SEVERITY_TEXT, STATUS_TEXT } from "@/lib/plain";

// Lab notes are in UTC, so the dashboard shows UTC too: times line up with notes.md.
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

export function shortTime(iso: string | null | undefined): string {
  return formatTime(iso).slice(11, 16) + " UTC";
}

export function errorText(e: unknown): string {
  if (e instanceof ApiError) return ERROR_TEXT[e.code] ?? e.message;
  return "Terjadi kesalahan yang tidak terduga.";
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-sev-critical-bg text-white",
  high: "bg-sev-high-bg text-sev-high-fg",
  medium: "bg-sev-medium-bg text-sev-medium-fg",
  low: "bg-sev-low-bg text-sev-low-fg",
  none: "bg-sev-none-bg text-sev-none-fg",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block whitespace-nowrap rounded-sm px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_STYLE[severity]}`}
    >
      <span className="sr-only">Tingkat </span>
      {SEVERITY_TEXT[severity]}
    </span>
  );
}

export function targetText(i: Pick<Incident, "dest_ip" | "opened_by">): string {
  return i.dest_ip ?? (i.opened_by === "auth_log" ? "layanan login" : "-");
}

// An early warning matters only until the agents and rules finish the incident.
export function hasEarlyWarning(i: Incident): boolean {
  return (
    i.pipeline_state !== "done" &&
    (i.provisional_severity === "high" || i.provisional_severity === "critical")
  );
}

// Filled square = something happened on the host, outline = it did not get that far.
const STATUS_MARK: Record<Status, string> = {
  confirmed: "■",
  attempted: "◧",
  suspected: "□",
  benign: "○",
};

export function StatusLabel({ status }: { status: Status }) {
  return (
    <span className="inline-flex items-center gap-1 text-sm font-medium">
      <span aria-hidden="true" className={status === "confirmed" ? "text-bad" : "text-muted"}>
        {STATUS_MARK[status]}
      </span>
      {STATUS_TEXT[status]}
    </span>
  );
}

const PIPELINE_TEXT: Record<PipelineState, string> = {
  queued: "menunggu giliran",
  running: "agen sedang bekerja",
  done: "selesai",
  failed: "analisis gagal",
};

export function PipelineLabel({ state }: { state: PipelineState }) {
  const tone = state === "failed" ? "text-bad" : state === "running" ? "text-accent" : "text-muted";
  return <span className={`text-sm ${tone}`}>{PIPELINE_TEXT[state]}</span>;
}

export function LoadingState({ label }: { label: string }) {
  return (
    <p role="status" aria-live="polite" className="py-10 text-center text-sm text-muted">
      {label}
    </p>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded border border-dashed border-line bg-surface px-4 py-10 text-center">
      <p className="font-medium">{title}</p>
      {children && <div className="mx-auto mt-2 max-w-prose text-sm text-muted">{children}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded border border-bad/40 bg-surface px-4 py-6">
      <p className="font-medium text-bad">Gagal memuat.</p>
      <p className="mt-1 text-sm text-muted">{message}</p>
      {onRetry && (
        <Button className="mt-4" onClick={onRetry}>
          Coba lagi
        </Button>
      )}
    </div>
  );
}

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary";
};

export function Button({ variant = "secondary", className = "", ...props }: ButtonProps) {
  const look =
    variant === "primary"
      ? "bg-accent text-white hover:bg-accent-strong"
      : "border border-line bg-surface text-ink hover:border-muted";
  return (
    <button
      type="button"
      {...props}
      className={`inline-flex min-h-11 items-center justify-center rounded px-4 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-60 ${look} ${className}`}
    />
  );
}

export function SectionTitle({ id, children }: { id?: string; children: ReactNode }) {
  return (
    <h2 id={id} className="mb-3 text-base font-semibold">
      {children}
    </h2>
  );
}
