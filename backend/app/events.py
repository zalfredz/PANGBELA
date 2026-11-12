"""Live pipeline events for the SSE stream (spec section 8).

The database is the record: on connect, a stream replays events rebuilt from
evidence and agent_runs. This broker only carries what happens after that, from
the pipeline worker thread or ingest, to each connected stream's asyncio queue.

Every event has a key naming the thing it reports (an evidence id, or an agent run
by agent, round and start time). The replay and the live events use the same keys,
so a stream can drop a live event that its replay already covered.
"""

import asyncio
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class Event:
    name: str  # agent_started, evidence_added, agent_finished, verdict, pipeline_failed
    data: dict[str, Any]
    key: str
    at: datetime = field(compare=False)


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat()


def run_key(agent: str, round_: int, started: datetime) -> str:
    return f"{agent}:{round_}:{_iso(started)}"


def agent_started(agent: str, round_: int, started: datetime) -> Event:
    return Event(
        "agent_started",
        {"agent": agent, "round": round_},
        f"agent_started:{run_key(agent, round_, started)}",
        started,
    )


def agent_finished(
    agent: str, round_: int, started: datetime, finished: datetime, status: str, output: Any
) -> Event:
    return Event(
        "agent_finished",
        {"agent": agent, "round": round_, "status": status, "output": output},
        f"agent_finished:{run_key(agent, round_, started)}",
        finished,
    )


def evidence_added(ev_id: str, source: str, ts: datetime, summary: str, at: datetime) -> Event:
    return Event(
        "evidence_added",
        {"id": ev_id, "source": source, "ts": _iso(ts), "summary": summary},
        f"evidence_added:{ev_id}",
        at,
    )


VERDICT_KEYS = (
    "status",
    "severity",
    "confidence",
    "confidence_level",
    "evidence_coverage",
    "verification_state",
    "rules_conflict",
)


def verdict(data: dict[str, Any], rules_started: datetime, at: datetime) -> Event:
    """data holds VERDICT_KEYS; a rules run recorded before these existed lacks some,
    and they replay as null."""
    return Event(
        "verdict",
        {k: data.get(k) for k in VERDICT_KEYS},
        f"verdict:{_iso(rules_started)}",
        at,
    )


def early_warning(status: str, severity: str, verification: str, at: datetime) -> Event:
    """A provisional high or critical assessment from the rules alone, sent before the
    agents run; the verdict replaces it."""
    return Event(
        "early_warning",
        {
            "status": status,
            "severity": severity,
            "verification_state": verification,
            "provisional": True,
        },
        f"early_warning:{_iso(at)}",
        at,
    )


def pipeline_failed(agent: str, error: str, key_started: datetime, at: datetime) -> Event:
    return Event(
        "pipeline_failed",
        {"agent": agent, "error": error},
        f"pipeline_failed:{_iso(key_started)}",
        at,
    )


class Broker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: dict[UUID, set[tuple[asyncio.AbstractEventLoop, asyncio.Queue]]] = {}
        # The agent each incident is running right now. Its agent_runs row only exists
        # once it finishes, so a stream opened mid-run gets agent_started from here.
        self._in_flight: dict[UUID, Event] = {}

    def emit(self, incident_id: UUID, event: Event) -> None:
        """Safe to call from any thread."""
        with self._lock:
            if event.name == "agent_started":
                self._in_flight[incident_id] = event
            elif event.name in ("agent_finished", "pipeline_failed", "verdict"):
                self._in_flight.pop(incident_id, None)
            for loop, queue in self._subs.get(incident_id, ()):
                loop.call_soon_threadsafe(queue.put_nowait, event)

    def subscribe(self, incident_id: UUID) -> tuple[asyncio.Queue, Event | None]:
        """Register a queue for live events. Call from the stream's event loop, before
        reading the replay from the database, so nothing falls between the two."""
        queue: asyncio.Queue = asyncio.Queue()
        with self._lock:
            self._subs.setdefault(incident_id, set()).add((asyncio.get_running_loop(), queue))
            return queue, self._in_flight.get(incident_id)

    def unsubscribe(self, incident_id: UUID, queue: asyncio.Queue) -> None:
        with self._lock:
            subs = self._subs.get(incident_id, set())
            subs.discard(next(((lp, q) for lp, q in subs if q is queue), None))
            if not subs:
                self._subs.pop(incident_id, None)


broker = Broker()
