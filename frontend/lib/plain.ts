// Plain-language (Bahasa Indonesia) wording for the dashboard. Every sentence is built
// from the rules gate's facts and the stored log fields, never from agent text, so it
// cannot say more than the evidence does and an attacker cannot write it.

import type {
  AgentName,
  AttackType,
  Evidence,
  IncidentDetail,
  ManualReason,
  PamelaBlock,
  Queue,
  Recommendation,
  Severity,
  Status,
  Verification,
} from "./api";

export const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "Kritis",
  high: "Tinggi",
  medium: "Sedang",
  low: "Rendah",
  none: "Aman",
};

export const STATUS_TEXT: Record<Status, string> = {
  confirmed: "Serangan berhasil",
  attempted: "Serangan dicoba",
  suspected: "Dicurigai",
  benign: "Bukan serangan",
};

export const STATUS_MEANING: Record<Status, string> = {
  confirmed: "Catatan server membuktikan serangannya berhasil.",
  attempted: "Serangan sampai ke target, tapi belum ada bukti berhasil.",
  suspected: "Ada tanda serangan, tapi belum terlihat sampai ke target.",
  benign: "Setelah diperiksa, ini tidak dianggap serangan.",
};

export const TYPE_TEXT: Record<AttackType, string> = {
  rce: "Menjalankan perintah dari jauh",
  brute_force: "Menebak password",
  unknown: "Belum dikenali",
};

export const QUEUE_TEXT: Record<Queue, { label: string; hint: string }> = {
  needs_human: { label: "Butuh keputusan Anda", hint: "Tingkat tinggi, atau analisis gagal" },
  pamela: { label: "Bisa diserahkan ke PAMELA", hint: "Tingkat rendah sampai sedang" },
  running: { label: "Sedang dianalisis", hint: "Agen sedang memeriksa catatan" },
  done: { label: "Selesai", hint: "Tidak ada yang perlu dikerjakan" },
};

const SOURCE_TEXT: Record<Evidence["source"], string> = {
  suricata: "alarm Suricata",
  access_log: "catatan server web",
  auth_log: "catatan login",
  process: "catatan proses di server",
};

export const SOURCE_LABEL: Record<Evidence["source"], string> = {
  suricata: "Alarm Suricata",
  access_log: "Server web",
  auth_log: "Login",
  process: "Proses",
};

// Mirrors REQUIRED_SOURCES in backend/app/graph/rules.py.
const REQUIRED: Record<AttackType, Evidence["source"][]> = {
  rce: ["suricata", "access_log", "process"],
  brute_force: ["auth_log"],
  unknown: ["suricata"],
};

export const AGENT_TEXT: Record<AgentName, { name: string; role: string }> = {
  detection: { name: "Deteksi", role: "Mengenali jenis serangan" },
  investigation: { name: "Investigasi", role: "Mencocokkan dengan catatan server" },
  forensics: { name: "Forensik", role: "Mencari dampak serangan" },
  decision: { name: "Keputusan", role: "Menyusun laporan dan saran tindakan" },
};

export function listTitle(type: AttackType, status: Status | null): string {
  if (status === null) return `Sedang diperiksa: ${TYPE_TEXT[type].toLowerCase()}`;
  return title(type, status, null);
}

function title(type: AttackType, status: Status, user: string | null): string {
  const account = user ? `akun ${user}` : "sebuah akun";
  if (type === "brute_force")
    return {
      confirmed: `Penyerang berhasil masuk ke ${account}`,
      attempted: `Ada yang mencoba menebak password ${account}`,
      suspected: "Ada tanda percobaan menebak password",
      benign: "Login gagal beberapa kali, bukan serangan",
    }[status];
  if (type === "rce")
    return {
      confirmed: "Penyerang berhasil menjalankan perintah di server",
      attempted: "Ada percobaan menjalankan perintah di server",
      suspected: "Ada permintaan mencurigakan ke server",
      benign: "Permintaan mencurigakan, bukan serangan",
    }[status];
  return "Aktivitas mencurigakan yang belum dikenali";
}

type Facts = {
  payload_logged?: boolean;
  exec_linked?: boolean;
  exec_unlinked?: boolean;
  failures?: number;
  success_after?: boolean;
  unauthorized_success?: boolean;
  unmarked_success?: boolean;
  sources_available?: string[];
};

export function latestRules(d: IncidentDetail) {
  const run = [...d.agent_runs].reverse().find((r) => r.agent === "rules" && r.status === "ok");
  return run?.output_json ?? null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v ? v : null;
}

function mostCommon(values: (string | null)[]): string | null {
  const counts = new Map<string, number>();
  for (const v of values) if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
}

export function attackedUser(evidence: Evidence[]): string | null {
  return mostCommon(evidence.filter((e) => e.source === "auth_log").map((e) => str(e.fields.username)));
}

/** Headline plus two or three plain sentences: what happened, how sure we are. */
export function explain(d: IncidentDetail): { title: string; body: string[] } {
  const inc = d.incident;
  const rules = latestRules(d);
  const facts = (rules?.facts ?? {}) as Facts;
  const src = inc.src_ip;
  const user = attackedUser(d.evidence);

  if (inc.confidence === null) {
    return {
      title: listTitle(inc.attack_type, null),
      body:
        inc.pipeline_state === "failed"
          ? ["Analisis berhenti sebelum selesai. Jalankan analisis ulang di bawah."]
          : [
              `Ada aktivitas mencurigakan dari alamat ${src}. Agen sedang membaca catatan server untuk memastikan apa yang terjadi. Biasanya selesai dalam sekitar 2 menit.`,
            ],
    };
  }

  const body: string[] = [];
  if (inc.attack_type === "brute_force") {
    const n = facts.failures ?? 0;
    body.push(
      `Alamat ${src} mencoba login ${n > 0 ? `${n} kali ` : ""}ke ${user ? `akun ${user}` : "sebuah akun"}, dan semuanya gagal.`,
    );
    if (inc.status === "confirmed")
      body.push(
        "Setelah itu login berhasil, dan sistem login mencatatnya sebagai login tanpa izin. Penyerang kemungkinan sudah memegang password akun ini.",
      );
    else if (facts.success_after && facts.unmarked_success)
      body.push(
        "Setelah itu ada login yang berhasil, tapi sistem login tidak mencatat apakah login itu sah. Jadi belum bisa dipastikan penyerang yang masuk.",
      );
    else if (facts.success_after)
      body.push("Setelah itu ada login yang berhasil, dan sistem login mencatatnya sebagai login sah.");
    else if (inc.status === "benign")
      body.push("Jumlah percobaannya di bawah batas yang dianggap serangan.");
    else body.push("Tidak ada login yang berhasil dari alamat ini.");
  } else if (inc.attack_type === "rce") {
    const req =
      d.evidence.find((e) => e.source === "access_log" && str(e.fields.query)) ??
      d.evidence.find((e) => e.source === "access_log");
    const path = req ? str(req.fields.path) : null;
    const target = inc.dest_ip ? `server ${inc.dest_ip}` : "server";
    body.push(
      `Alamat ${src} mengirim permintaan ${path ? `ke halaman ${path} di ${target}` : `ke ${target}`} yang berisi perintah sistem tersembunyi.`,
    );
    if (inc.status === "confirmed")
      body.push("Server menjalankan perintah itu. Penyerang kemungkinan bisa mengendalikan server.");
    else if (inc.status === "attempted") {
      if (inc.verification_state === "insufficient_telemetry")
        body.push(
          "Server menerima permintaan itu, tapi catatan proses di server tidak tersedia. Jadi belum bisa dipastikan apakah perintahnya benar-benar dijalankan.",
        );
      else if (facts.exec_unlinked)
        body.push(
          "Server menerima permintaan itu. Ada program yang berjalan di waktu yang sama, tapi tidak bisa dipastikan berasal dari permintaan ini.",
        );
      else body.push("Server menerima permintaan itu, tapi tidak ada tanda perintahnya dijalankan.");
    } else if (inc.status === "suspected")
      body.push(
        "Sistem pendeteksi menandainya, tapi permintaan itu tidak tercatat di server web. Kemungkinan tidak sampai.",
      );
    else body.push("Setelah diperiksa, permintaan ini dinilai tidak berbahaya.");
  } else {
    body.push(`Sistem pendeteksi menandai aktivitas dari alamat ${src}, tapi jenisnya belum dikenali.`);
  }
  return { title: title(inc.attack_type, inc.status, user), body };
}

/** One sentence on how much the result can be trusted. */
export function certainty(d: IncidentDetail): string | null {
  const v: Verification | null = d.incident.verification_state;
  if (v === null) return null;
  if (v === "verified") return "Semua catatan yang dibutuhkan tersedia, jadi hasil ini bisa dipegang.";
  if (v === "partially_verified")
    return "Sebagian bukti belum cukup kuat, jadi hasil ini masih bisa berubah.";
  const have = (latestRules(d)?.facts as Facts | undefined)?.sources_available ?? [];
  const missing = REQUIRED[d.incident.attack_type].filter((s) => !have.includes(s));
  const names = missing.map((s) => SOURCE_TEXT[s]).join(" dan ");
  return `${names ? `${names[0].toUpperCase()}${names.slice(1)} tidak tersedia` : "Ada catatan yang tidak tersedia"}, jadi hasilnya belum bisa naik. Ini bukan berarti serangannya gagal.`;
}

/** What each agent concluded, in one short sentence. */
export function agentConclusion(agent: AgentName, o: Record<string, unknown>): string {
  const status = (s: unknown) => STATUS_TEXT[s as Status]?.toLowerCase() ?? String(s);
  switch (agent) {
    case "detection":
      return `Ini serangan: ${TYPE_TEXT[o.attack_type as AttackType]?.toLowerCase() ?? String(o.attack_type)}.`;
    case "investigation":
      return `Menurutnya: ${status(o.proposed_status)}.${o.scanner_likely ? " Kemungkinan alat pemindai otomatis." : ""}`;
    case "forensics": {
      const impact: Record<string, string> = {
        code_execution: "perintah dijalankan di server",
        outbound_connection: "server menghubungi alamat luar",
        account_login: "ada login ke akun",
      };
      const missing = Array.isArray(o.missing_sources) ? (o.missing_sources as Evidence["source"][]) : [];
      const found = o.impact_found
        ? `Menemukan dampak: ${impact[String(o.impact_type)] ?? String(o.impact_type)}.`
        : "Tidak menemukan dampak.";
      return missing.length
        ? `${found} Tidak bisa memeriksa ${missing.map((s) => SOURCE_TEXT[s] ?? s).join(", ")}.`
        : found;
    }
    case "decision":
      return `Mengusulkan: ${status(o.proposed_status)}, tingkat ${SEVERITY_TEXT[o.proposed_severity as Severity]?.toLowerCase() ?? String(o.proposed_severity)}.`;
  }
}

export function actionTitle(r: Recommendation): string {
  const t = r.system_target;
  switch (r.action) {
    case "block_ip":
      return t ? `Blokir alamat ${t}` : "Blokir alamat penyerang";
    case "monitor":
      return t ? `Pantau alamat ${t}` : "Pantau alamat penyerang";
    case "reset_password":
      return t ? `Reset password akun ${t}` : "Reset password akun yang diserang";
    case "isolate_host":
      return t ? `Putus server ${t} dari jaringan` : "Putus server dari jaringan";
    case "patch_endpoint":
      return `Perbaiki celah di ${r.target}`;
  }
}

export function actionEffect(r: Recommendation, blockSeconds: number): string {
  const minutes = Math.round(blockSeconds / 60);
  const duration = minutes % 60 === 0 ? `${minutes / 60} jam` : `${minutes} menit`;
  return {
    block_ip: `Alamat ini tidak bisa mengakses lab selama ${duration}.`,
    monitor: "Aktivitas berikutnya dari alamat ini ditandai untuk diawasi.",
    reset_password: "Password lama tidak berlaku lagi. Pemilik akun perlu membuat password baru.",
    isolate_host:
      "Server diputus sementara supaya penyerang tidak bisa memakainya. Layanan di server ini ikut berhenti.",
    patch_endpoint: "Perlu dikerjakan developer.",
  }[r.action];
}

export const MANUAL_TEXT: Record<ManualReason, string> = {
  manual_only: "PAMELA tidak bisa mengerjakan ini. Perlu dikerjakan manusia.",
  protected_ip: "Alamat ini ada di daftar yang dilindungi, jadi tidak akan diblokir otomatis.",
  no_host: "Server tujuannya tidak diketahui, jadi perlu dikerjakan manual.",
  no_account: "Akun yang diserang tidak tercatat di catatan login, jadi perlu dikerjakan manual.",
  several_accounts: "Ada beberapa akun di catatan login. Pilih akunnya dan kerjakan manual.",
};

export const PAMELA_BLOCK_TEXT: Record<PamelaBlock, string> = {
  not_decided: "PAMELA menunggu analisis selesai.",
  no_threat: "Tidak ada ancaman, jadi PAMELA tidak perlu bertindak.",
  needs_human:
    "Kasus tingkat ini wajib diputuskan manusia. PAMELA hanya boleh bertindak sendiri untuk tingkat rendah sampai sedang.",
};

// Server errors arrive in English with a stable code; these are the ones a person can
// run into from the buttons on this page.
export const ERROR_TEXT: Record<string, string> = {
  already_decided: "Saran ini sudah diputuskan orang lain. Halaman dimuat ulang.",
  already_reverted: "Tindakan ini sudah dibatalkan.",
  needs_human: PAMELA_BLOCK_TEXT.needs_human,
  not_decided: PAMELA_BLOCK_TEXT.not_decided,
  no_threat: PAMELA_BLOCK_TEXT.no_threat,
  run_in_progress: "Analisis sedang berjalan. Tunggu sampai selesai.",
  network: "Tidak bisa menghubungi server PANGBELA. Pastikan backend berjalan.",
  ...MANUAL_TEXT,
};
