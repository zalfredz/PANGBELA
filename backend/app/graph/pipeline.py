"""LangGraph wiring (spec section 9):

detection -> investigation -> [fetch_more -> investigation]* -> forensics (skipped
when ruled benign) -> decision -> rules -> save

Code fetches and stores evidence before each agent reads it; the rules node, not an
agent, writes incidents.status.
"""

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TypedDict
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel
from sqlalchemy import text

from app import db, events
from app.agents import decision, detection, forensics, investigation
from app.agents.base import IncidentInfo
from app.agents.schemas import (
    DecisionOutput,
    DetectionOutput,
    ForensicsOutput,
    InvestigationOutput,
)
from app.config import Settings, settings
from app.events import broker
from app.evidence import log_sources, readable_sources
from app.evidence.store import insert_evidence, load_evidence
from app.graph.rules import GateResult, cited_ids, compute_facts, rules_gate
from app.llm.client import AgentOutputInvalid, LLMClient

log = logging.getLogger(__name__)

# Logs each attack type needs checked for impact before the decision.
FORENSICS_SOURCES = {
    "rce": ["process"],
    "brute_force": ["auth_log"],
    "unknown": ["process", "auth_log"],
}


class PipelineFailed(Exception):
    def __init__(self, agent: str, error: str):
        super().__init__(f"{agent}: {error}")
        self.agent = agent
        self.error = error


class IncidentNotFound(Exception):
    pass


class AlreadyRunning(Exception):
    pass


# Keys differ from node names on purpose: LangGraph rejects a node named like a state key.
class State(TypedDict, total=False):
    incident: IncidentInfo
    round: int
    fetched: list[str]  # log sources already queried over the incident's time range
    detection_out: DetectionOutput
    attack_type: str  # what the rules use: code's type if set, else the detection agent's
    investigation_out: InvestigationOutput
    forensics_out: ForensicsOutput | None
    decision_out: DecisionOutput
    gate: GateResult
    rules_run: tuple[datetime, datetime]  # started_at, finished_at of the rules agent_runs row


def _now() -> datetime:
    return datetime.now(UTC)


def _record_run(
    incident_id: UUID,
    agent: str,
    round_: int,
    started: datetime,
    status: str,
    *,
    output: dict | None = None,
    cited: list[str] | None = None,
    conflict: str | None = None,
    model: str | None = None,
    latency_ms: int | None = None,
    error: str | None = None,
) -> datetime:
    """Insert one agent_runs row and return its finished_at."""
    finished = _now()
    with db.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO agent_runs (incident_id, agent, round, status, output_json,"
                " cited_evidence_ids, rules_conflict, model, latency_ms, error, started_at,"
                " finished_at)"
                " VALUES (:incident_id, :agent, :round, :status, CAST(:output AS jsonb),"
                " :cited, :conflict, :model, :latency_ms, :error, :started, :finished)"
            ),
            {
                "incident_id": incident_id,
                "agent": agent,
                "round": round_,
                "status": status,
                "output": json.dumps(output) if output is not None else None,
                "cited": cited or [],
                "conflict": conflict,
                "model": model,
                "latency_ms": latency_ms,
                "error": error,
                "started": started,
                "finished": finished,
            },
        )
    return finished


def fetch_evidence(
    incident: IncidentInfo,
    wanted: list[str],
    collected_by: str,
    cfg: Settings,
    readable: dict[str, bool],
) -> None:
    """Query each wanted, readable log over the incident's padded time range and store
    the lines as evidence."""
    sources = log_sources(cfg)
    pad = timedelta(
        seconds=max(
            cfg.BRUTE_FORCE_WINDOW_SECONDS,
            cfg.CORRELATION_WINDOW_SECONDS + cfg.CORRELATION_WINDOW_BEFORE_SECONDS,
        )
    )
    start, end = incident.first_seen - pad, incident.last_seen + pad
    for name in dict.fromkeys(wanted):
        if name not in sources or not readable.get(name):
            continue
        path, _, query = sources[name]
        lines = query(path, incident.src_ip, start, end, incident.id)
        with db.engine.begin() as conn:
            added = insert_evidence(conn, lines, collected_by)
        for ev, created_at in added:
            broker.emit(
                incident.id,
                events.evidence_added(ev.id, ev.source, ev.ts, ev.summary, created_at),
            )


def build_graph(client: LLMClient, cfg: Settings):
    sources = log_sources(cfg)
    readable = readable_sources(cfg)
    unavailable = sorted(s for s, ok in readable.items() if not ok)

    def call_agent[T: BaseModel](
        incident: IncidentInfo, agent: str, round_: int, fn: Callable[[], T]
    ) -> T:
        started = _now()
        broker.emit(incident.id, events.agent_started(agent, round_, started))
        try:
            out = fn()
        except AgentOutputInvalid as e:
            info = client.last_call
            error = "; ".join(e.errors)
            finished = _record_run(
                incident.id,
                agent,
                round_,
                started,
                "invalid",
                model=info.model,
                latency_ms=info.latency_ms,
                error=error,
            )
            fail(incident.id, agent, round_, started, finished, "invalid", error)
            raise PipelineFailed(agent, f"invalid output after {info.attempts} attempt(s)") from e
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
            finished = _record_run(
                incident.id, agent, round_, started, "error", model=client.model, error=error
            )
            fail(incident.id, agent, round_, started, finished, "error", error)
            raise PipelineFailed(agent, type(e).__name__) from e
        info = client.last_call
        output = out.model_dump(mode="json")
        finished = _record_run(
            incident.id,
            agent,
            round_,
            started,
            "ok",
            output=output,
            cited=cited_ids(out),
            model=info.model,
            latency_ms=info.latency_ms,
        )
        broker.emit(
            incident.id, events.agent_finished(agent, round_, started, finished, "ok", output)
        )
        return out

    def fail(
        incident_id: UUID,
        agent: str,
        round_: int,
        started: datetime,
        finished: datetime,
        status: str,
        error: str,
    ) -> None:
        broker.emit(
            incident_id, events.agent_finished(agent, round_, started, finished, status, None)
        )
        broker.emit(incident_id, events.pipeline_failed(agent, error, started, finished))

    def fetch(incident: IncidentInfo, wanted: list[str], collected_by: str) -> None:
        fetch_evidence(incident, wanted, collected_by, cfg, readable)

    def evidence_of(incident: IncidentInfo):
        with db.engine.connect() as conn:
            return load_evidence(conn, incident.id)

    def detection_node(state: State) -> State:
        inc = state["incident"]
        evidence = evidence_of(inc)
        out = call_agent(inc, "detection", 1, lambda: detection.run(client, inc, evidence))
        # A type code already set (lab signature ids, auth log threshold) stands; the
        # agent's choice only fills an unknown one. A disagreement is kept in the rules
        # run's output.
        attack_type = inc.attack_type if inc.attack_type != "unknown" else out.attack_type
        with db.engine.begin() as conn:
            conn.execute(
                text("UPDATE incidents SET attack_type = :t, updated_at = now() WHERE id = :id"),
                {"t": attack_type, "id": inc.id},
            )
        return {"detection_out": out, "attack_type": attack_type, "round": 1}

    def investigation_node(state: State) -> State:
        inc, round_ = state["incident"], state["round"]
        fetched = state.get("fetched", [])
        if round_ == 1:
            fetch(inc, ["access_log", "auth_log"], "investigation")
            fetched = ["access_log", "auth_log"]
        evidence = evidence_of(inc)
        out = call_agent(
            inc,
            "investigation",
            round_,
            lambda: investigation.run(
                client,
                inc,
                evidence,
                state["detection_out"],
                round_,
                cfg.MAX_EVIDENCE_ROUNDS,
                unavailable,
            ),
        )
        return {"investigation_out": out, "fetched": fetched}

    def new_sources(state: State) -> list[str]:
        """Requested sources that can still add evidence. An unavailable source, or one
        already queried over the same time range, returns nothing new, and another
        investigation round on unchanged evidence only repeats the same analysis."""
        requested = dict.fromkeys(r.source for r in state["investigation_out"].evidence_requests)
        return [
            s
            for s in requested
            if s in sources and readable.get(s) and s not in state.get("fetched", [])
        ]

    def route_after_investigation(state: State) -> str:
        inv = state["investigation_out"]
        if new_sources(state) and state["round"] < cfg.MAX_EVIDENCE_ROUNDS:
            return "fetch_more"
        if inv.ruled_benign:
            return "decision"
        return "forensics"

    def fetch_more_node(state: State) -> State:
        inc = state["incident"]
        wanted = new_sources(state)
        fetch(inc, wanted, "investigation")
        return {"round": state["round"] + 1, "fetched": [*state.get("fetched", []), *wanted]}

    def forensics_node(state: State) -> State:
        inc = state["incident"]
        fetch(inc, FORENSICS_SOURCES[state["attack_type"]], "forensics")
        evidence = evidence_of(inc)
        out = call_agent(
            inc,
            "forensics",
            1,
            lambda: forensics.run(
                client,
                inc,
                evidence,
                state["detection_out"],
                state["investigation_out"],
                unavailable,
            ),
        )
        return {"forensics_out": out}

    def decision_node(state: State) -> State:
        inc = state["incident"]
        evidence = evidence_of(inc)
        out = call_agent(
            inc,
            "decision",
            1,
            lambda: decision.run(
                client,
                inc,
                evidence,
                state["detection_out"],
                state["investigation_out"],
                state.get("forensics_out"),
            ),
        )
        return {"decision_out": out}

    def rules_node(state: State) -> State:
        inc = state["incident"]
        started = _now()
        attack_type = state["attack_type"]
        facts = compute_facts(inc.src_ip, evidence_of(inc), cfg, readable)
        gate = rules_gate(
            attack_type,
            facts,
            state["decision_out"].proposed_status,
            state["investigation_out"],
            cfg,
        )
        with db.engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE incidents SET status = :status, severity = :severity,"
                    " confidence = :confidence, confidence_level = :level,"
                    " evidence_coverage = :coverage, verification_state = :verification,"
                    " scanner_likely = :scanner, updated_at = now() WHERE id = :id"
                ),
                {
                    "status": gate.status,
                    "severity": gate.severity,
                    "confidence": gate.confidence,
                    "level": gate.confidence_level,
                    "coverage": gate.evidence_coverage,
                    "verification": gate.verification,
                    "scanner": state["investigation_out"].scanner_likely,
                    "id": inc.id,
                },
            )
        finished = _record_run(
            inc.id,
            "rules",
            1,
            started,
            "ok",
            output={
                "attack_type": attack_type,
                "detection_attack_type": state["detection_out"].attack_type,
                "facts": facts.as_dict(),
                "proposed": state["decision_out"].proposed_status,
                "allowed": gate.allowed,
                "status": gate.status,
                "severity": gate.severity,
                "confidence": gate.confidence,
                "confidence_level": gate.confidence_level,
                "evidence_coverage": gate.evidence_coverage,
                "verification_state": gate.verification,
            },
            conflict=gate.conflict,
        )
        return {"gate": gate, "rules_run": (started, finished)}

    def save_node(state: State) -> State:
        inc, dec = state["incident"], state["decision_out"]
        with db.engine.begin() as conn:
            # A rerun replaces suggestions nobody has acted on; decided ones stay as history.
            conn.execute(
                text("DELETE FROM recommendations WHERE incident_id = :id AND status = 'pending'"),
                {"id": inc.id},
            )
            # Nor does it ask again about something already decided. Except for patching,
            # the system derives one target per action from the incident, so the action
            # alone identifies it; the agent's target text varies between runs.
            for r in dec.recommendations:
                conn.execute(
                    text(
                        "INSERT INTO recommendations (incident_id, action, target, reason)"
                        " SELECT :id, :action, :target, :reason WHERE NOT EXISTS ("
                        "  SELECT 1 FROM recommendations WHERE incident_id = :id"
                        "  AND action = :action AND status <> 'pending'"
                        "  AND (action <> 'patch_endpoint' OR target = :target))"
                    ),
                    {"id": inc.id, "action": r.action, "target": r.target, "reason": r.reason},
                )
            conn.execute(
                text(
                    "UPDATE incidents SET summary = :summary, report_md = :report,"
                    " pipeline_state = 'done', updated_at = now() WHERE id = :id"
                ),
                {"summary": dec.summary, "report": dec.report_md, "id": inc.id},
            )
        gate, (rules_started, rules_finished) = state["gate"], state["rules_run"]
        broker.emit(
            inc.id,
            events.verdict(
                {
                    "status": gate.status,
                    "severity": gate.severity,
                    "confidence": gate.confidence,
                    "confidence_level": gate.confidence_level,
                    "evidence_coverage": gate.evidence_coverage,
                    "verification_state": gate.verification,
                    "rules_conflict": gate.conflict,
                },
                rules_started,
                rules_finished,
            ),
        )
        return {}

    g = StateGraph(State)
    g.add_node("detection", detection_node)
    g.add_node("investigation", investigation_node)
    g.add_node("fetch_more", fetch_more_node)
    g.add_node("forensics", forensics_node)
    g.add_node("decision", decision_node)
    g.add_node("rules", rules_node)
    g.add_node("save", save_node)
    g.add_edge(START, "detection")
    g.add_edge("detection", "investigation")
    g.add_conditional_edges(
        "investigation",
        route_after_investigation,
        {"fetch_more": "fetch_more", "forensics": "forensics", "decision": "decision"},
    )
    g.add_edge("fetch_more", "investigation")
    g.add_edge("forensics", "decision")
    g.add_edge("decision", "rules")
    g.add_edge("rules", "save")
    g.add_edge("save", END)
    return g.compile()


def code_attack_type(conn, incident_id: UUID, opened_by: str, cfg: Settings) -> str:
    """The attack type code can tell without an agent: brute_force for an incident the
    auth log threshold opened, else the type of the lab signature ids among its alerts.
    Recomputed each run rather than read from incidents.attack_type, which also holds
    the detection agent's choice from an earlier run."""
    if opened_by == "auth_log":
        return "brute_force"
    by_sid = cfg.signature_attack_types
    sids = conn.execute(
        text("SELECT DISTINCT signature_id FROM alerts WHERE incident_id = :id"),
        {"id": incident_id},
    ).scalars()
    types = {by_sid[s] for s in sids if s in by_sid}
    # Alerts of both types on one incident: leave it to the agent.
    return types.pop() if len(types) == 1 else "unknown"


def claim_incident(
    incident_id: UUID, *, only_queued: bool = False, cfg: Settings = settings
) -> IncidentInfo:
    """Mark the incident running in one statement, so two callers can't both start it.

    only_queued is for the start-delay loop: an incident that finished or failed
    between the loop's query and this claim must not start again on its own.
    Raises AlreadyRunning (or not queued) or IncidentNotFound.
    """
    allowed = "pipeline_state = 'queued'" if only_queued else "pipeline_state <> 'running'"
    with db.engine.begin() as conn:
        row = (
            conn.execute(
                text(
                    "UPDATE incidents SET pipeline_state = 'running', updated_at = now()"
                    f" WHERE id = :id AND {allowed}"
                    " RETURNING id, host(src_ip) AS src_ip, host(dest_ip) AS dest_ip,"
                    " first_seen, last_seen, opened_by"
                ),
                {"id": incident_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            exists = conn.execute(
                text("SELECT 1 FROM incidents WHERE id = :id"), {"id": incident_id}
            ).scalar()
            raise AlreadyRunning(incident_id) if exists else IncidentNotFound(incident_id)
        attack_type = code_attack_type(conn, incident_id, row["opened_by"], cfg)
    return IncidentInfo(**row, attack_type=attack_type)


def _mark_failed(incident_id: UUID) -> None:
    with db.engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE incidents SET pipeline_state = 'failed', updated_at = now() WHERE id = :id"
            ),
            {"id": incident_id},
        )


def run_claimed(
    incident: IncidentInfo, client: LLMClient | None = None, cfg: Settings = settings
) -> State:
    """Run the whole graph for an incident already claimed with claim_incident.
    Raises PipelineFailed after marking the incident failed."""
    graph = build_graph(client or LLMClient(cfg), cfg)
    try:
        return graph.invoke({"incident": incident})
    except PipelineFailed as e:
        log.warning("pipeline failed for %s at %s: %s", incident.id, e.agent, e.error)
        _mark_failed(incident.id)
        raise
    except Exception as e:
        # A failure outside an agent (database, rules, save): no agent_runs row says
        # so, so the live stream is told directly.
        log.exception("pipeline crashed for %s", incident.id)
        _mark_failed(incident.id)
        now = _now()
        broker.emit(incident.id, events.pipeline_failed("pipeline", type(e).__name__, now, now))
        raise


def run_pipeline(
    incident_id: UUID, client: LLMClient | None = None, cfg: Settings = settings
) -> State:
    return run_claimed(claim_incident(incident_id, cfg=cfg), client, cfg)
