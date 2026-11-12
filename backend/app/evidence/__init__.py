"""Log sources the pipeline can query, all JSON Lines (docs/log-schema.md).

A source whose file is missing or unreadable is unavailable: the rules count it as
missing telemetry, and forensics reports it as a missing source.
"""

from collections.abc import Callable
from datetime import datetime
from uuid import UUID

from app.config import Settings
from app.evidence import access_log, auth_log, process_log
from app.evidence.store import EvidenceEvent

Query = Callable[[str, str, datetime, datetime, UUID], list[EvidenceEvent]]


def log_sources(cfg: Settings) -> dict[str, tuple[str, Callable[[str], bool], Query]]:
    """source name -> (path, available(path), query(path, src_ip, start, end, incident_id))"""
    return {
        "access_log": (cfg.ACCESS_LOG_PATH, access_log.available, access_log.query),
        "auth_log": (cfg.AUTH_LOG_PATH, auth_log.available, auth_log.query),
        "process": (cfg.PROCESS_LOG_PATH, process_log.available, process_log.query),
    }


def readable_sources(cfg: Settings) -> dict[str, bool]:
    return {name: available(path) for name, (path, available, _) in log_sources(cfg).items()}
