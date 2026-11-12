"use client";

import { useEffect, useRef, useState } from "react";
import { type AgentName, streamUrl } from "@/lib/api";

export interface AgentStep {
  agent: AgentName;
  round: number;
  state: "running" | "ok" | "invalid" | "error";
  output: Record<string, unknown> | null;
}

export interface Verdict {
  status: string;
  severity: string;
  confidence: number;
  confidence_level: string | null;
  evidence_coverage: number | null;
  verification_state: string | null;
  rules_conflict: string | null;
}

export type Connection = "connecting" | "live" | "reconnecting" | "closed";

export interface StreamState {
  runs: AgentStep[][]; // one list of steps per pipeline run, oldest first
  verdict: Verdict | null;
  failure: { agent: string; error: string } | null;
  connection: Connection;
}

const EMPTY: Omit<StreamState, "connection"> = { runs: [], verdict: null, failure: null };

/**
 * Follows /incidents/{id}/stream. On every (re)connect the server replays the whole
 * history first, so the state is rebuilt from scratch on open instead of appended to.
 * onChange fires for events that change stored data (evidence, verdict, failure), so
 * the page can refetch the incident.
 */
export function useAgentStream(id: string, onChange: () => void): StreamState {
  const [data, setData] = useState(EMPTY);
  const [connection, setConnection] = useState<Connection>("connecting");
  const onChangeRef = useRef(onChange);
  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  useEffect(() => {
    const source = new EventSource(streamUrl(id));
    const parse = (e: MessageEvent) => JSON.parse(e.data);

    source.onopen = () => {
      setData(EMPTY);
      setConnection("live");
    };
    source.onerror = () => {
      // EventSource retries by itself while CONNECTING; CLOSED means it gave up.
      setConnection(source.readyState === EventSource.CLOSED ? "closed" : "reconnecting");
    };

    source.addEventListener("agent_started", (e) => {
      const { agent, round } = parse(e as MessageEvent);
      setData((d) => {
        const step: AgentStep = { agent, round, state: "running", output: null };
        // Detection round 1 only ever starts a pipeline run, so it marks a new run.
        const runs =
          agent === "detection" && round === 1
            ? [...d.runs, [step]]
            : d.runs.length
              ? [...d.runs.slice(0, -1), [...d.runs[d.runs.length - 1], step]]
              : [[step]];
        return { ...d, runs, failure: agent === "detection" ? null : d.failure };
      });
    });

    source.addEventListener("agent_finished", (e) => {
      const { agent, round, status, output } = parse(e as MessageEvent);
      setData((d) => {
        const last = d.runs[d.runs.length - 1] ?? [];
        const idx = last.findLastIndex(
          (s) => s.agent === agent && s.round === round && s.state === "running",
        );
        if (idx === -1) return d;
        const steps = last.map((s, i) => (i === idx ? { ...s, state: status, output } : s));
        return { ...d, runs: [...d.runs.slice(0, -1), steps] };
      });
    });

    source.addEventListener("evidence_added", () => onChangeRef.current());
    // The warning itself is stored on the incident; refetching shows it.
    source.addEventListener("early_warning", () => onChangeRef.current());
    source.addEventListener("verdict", (e) => {
      setData((d) => ({ ...d, verdict: parse(e as MessageEvent), failure: null }));
      onChangeRef.current();
    });
    source.addEventListener("pipeline_failed", (e) => {
      setData((d) => ({ ...d, failure: parse(e as MessageEvent) }));
      onChangeRef.current();
    });

    return () => source.close();
  }, [id]);

  return { ...data, connection };
}
