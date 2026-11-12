"""Start-delay loop (spec section 9).

Every TICK_SECONDS, start the pipeline for the oldest queued incident whose last_seen
is older than PIPELINE_DEBOUNCE_SECONDS, so a brute force burst finishes arriving
before investigation starts. One pipeline runs at a time; the rest stay queued in the
database, so pipeline_state always says what is really happening.
"""

import asyncio
import logging
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime

from sqlalchemy import text

from app import db, events
from app.agents.base import IncidentInfo
from app.config import Settings
from app.events import broker
from app.evidence import readable_sources
from app.evidence.store import load_evidence
from app.graph.pipeline import (
    AlreadyRunning,
    IncidentNotFound,
    PipelineFailed,
    claim_incident,
    code_attack_type,
    fetch_evidence,
    run_claimed,
)
from app.graph.rules import REQUIRED_SOURCES, compute_facts, provisional
from app.llm.client import LLMClient

log = logging.getLogger(__name__)

TICK_SECONDS = 5


def recover_stale_runs() -> int:
    """At startup no pipeline can be running in this process, so a 'running' row is
    left over from a crash or restart. Mark it failed; the rerun endpoint restarts it."""
    with db.engine.begin() as conn:
        n = conn.execute(
            text(
                "UPDATE incidents SET pipeline_state = 'failed', updated_at = now()"
                " WHERE pipeline_state = 'running'"
            )
        ).rowcount
    if n:
        log.warning("marked %d interrupted pipeline run(s) as failed", n)
    return n


class Runner:
    def __init__(self, cfg: Settings, client_factory: Callable[[], LLMClient] | None = None):
        self.cfg = cfg
        self._client_factory = client_factory or (lambda: LLMClient(cfg))
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pipeline")
        self._busy = threading.Lock()
        self._warned_unconfigured = False

    def tick(self) -> Future | None:
        """Start at most one due incident. Returns its future, or None if nothing started."""
        if not self.cfg.llm_configured:
            if not self._warned_unconfigured:
                log.warning("LLM_* not set: queued incidents wait until it is configured")
                self._warned_unconfigured = True
            return None
        if not self._busy.acquire(blocking=False):
            return None  # a pipeline is running; the next tick checks again
        try:
            with db.engine.connect() as conn:
                incident_id = conn.execute(
                    text(
                        "SELECT id FROM incidents WHERE pipeline_state = 'queued'"
                        " AND last_seen < now() - make_interval(secs => :debounce)"
                        " ORDER BY last_seen LIMIT 1"
                    ),
                    {"debounce": self.cfg.PIPELINE_DEBOUNCE_SECONDS},
                ).scalar()
            if incident_id is None:
                self._busy.release()
                return None
            incident = claim_incident(incident_id, only_queued=True, cfg=self.cfg)
        except (AlreadyRunning, IncidentNotFound):
            self._busy.release()  # taken or deleted since the query; try next tick
            return None
        except Exception:
            self._busy.release()
            raise
        return self._executor.submit(self._run, incident)

    def _run(self, incident) -> None:
        try:
            run_claimed(incident, self._client_factory(), self.cfg)
        except PipelineFailed:
            pass  # recorded in agent_runs and pipeline_state already
        except Exception:
            log.exception("pipeline crashed for %s", incident.id)
        finally:
            self._busy.release()

    def assess(self) -> int:
        """Rules-only assessment of every queued incident whose attack type code
        already knows, without waiting for the debounce or a running pipeline (team
        answer Q6). Stores it as provisional_*, and emits early_warning when it
        changes to high or critical. Returns the number of warnings emitted."""
        readable = readable_sources(self.cfg)
        with db.engine.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        "SELECT id, host(src_ip) AS src_ip, host(dest_ip) AS dest_ip,"
                        " first_seen, last_seen, opened_by, provisional_status,"
                        " provisional_severity, provisional_verification"
                        " FROM incidents WHERE pipeline_state = 'queued'"
                    )
                )
                .mappings()
                .all()
            )
        warned = 0
        for row in rows:
            with db.engine.connect() as conn:
                attack_type = code_attack_type(conn, row["id"], row["opened_by"], self.cfg)
            if attack_type == "unknown":
                continue
            incident = IncidentInfo(
                id=row["id"],
                src_ip=row["src_ip"],
                dest_ip=row["dest_ip"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                attack_type=attack_type,
                opened_by=row["opened_by"],
            )
            wanted = [s for s in REQUIRED_SOURCES[attack_type] if s != "suricata"]
            fetch_evidence(incident, wanted, "rules", self.cfg, readable)
            with db.engine.connect() as conn:
                evidence = load_evidence(conn, incident.id)
            p = provisional(
                attack_type, compute_facts(incident.src_ip, evidence, self.cfg, readable), self.cfg
            )
            before = (
                row["provisional_status"],
                row["provisional_severity"],
                row["provisional_verification"],
            )
            if (p.status, p.severity, p.verification) == before:
                continue  # unchanged: no new timestamp, so no repeated warning
            at = datetime.now(UTC)
            with db.engine.begin() as conn:
                updated = conn.execute(
                    text(
                        "UPDATE incidents SET provisional_status = :s, provisional_severity = :sev,"
                        " provisional_verification = :v, provisional_at = :at"
                        " WHERE id = :id AND pipeline_state = 'queued'"
                    ),
                    {
                        "s": p.status,
                        "sev": p.severity,
                        "v": p.verification,
                        "at": at,
                        "id": incident.id,
                    },
                ).rowcount
            if updated and p.severity in ("high", "critical"):
                log.warning(
                    "early warning: incident %s provisional %s/%s",
                    incident.id,
                    p.status,
                    p.severity,
                )
                broker.emit(
                    incident.id, events.early_warning(p.status, p.severity, p.verification, at)
                )
                warned += 1
        return warned

    async def loop(self) -> None:
        while True:
            # Assessment first and on its own: a running pipeline must not hold back a
            # warning.
            try:
                await asyncio.to_thread(self.assess)
            except Exception:
                log.exception("provisional assessment failed")
            try:
                await asyncio.to_thread(self.tick)
            except Exception:
                log.exception("start-delay tick failed")
            await asyncio.sleep(TICK_SECONDS)

    def shutdown(self) -> None:
        # A running pipeline thread can't be interrupted; if the process exits under
        # it, recover_stale_runs marks the incident failed on the next start.
        self._executor.shutdown(wait=False, cancel_futures=True)
