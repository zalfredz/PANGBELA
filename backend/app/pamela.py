"""PAMELA: carries out low-risk recommendations without waiting for a person
(docs/build-spec.md, section 13).

Three limits keep an attacker from steering it through the logs they write:
- it only acts on incidents whose rules severity is at most PAMELA_MAX_SEVERITY, and
  the rules gate (code), not an agent, sets that severity;
- the target of every action comes from the incident record, never from the target
  text the Decision agent wrote;
- PROTECTED_IPS are never blocked, by PAMELA or by a person.

"Carrying out" means writing an action row. The lab pulls active rows from
GET /enforcement and applies them; nothing here touches a firewall, account or host.
"""

import ipaddress
from collections.abc import Mapping

from sqlalchemy import Connection, text

from app.config import Settings

NAME = "PAMELA"
EXECUTABLE = ("block_ip", "monitor", "reset_password", "isolate_host")
SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")


def allowed_severities(cfg: Settings) -> tuple[str, ...]:
    """Severities PAMELA may act on alone. "none" is never one: nothing to fix."""
    return SEVERITY_ORDER[1 : SEVERITY_ORDER.index(cfg.PAMELA_MAX_SEVERITY) + 1]


def gate(incident: Mapping, cfg: Settings) -> str | None:
    """Why PAMELA may not act on this incident, or None when it may."""
    if incident["pipeline_state"] != "done" or incident["confidence"] is None:
        return "not_decided"
    if incident["severity"] == "none":
        return "no_threat"
    if incident["severity"] not in allowed_severities(cfg):
        return "needs_human"
    return None


def _protected(ip: str, cfg: Settings) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in cfg.protected_networks)


def code_target(
    conn: Connection, incident: Mapping, action: str, cfg: Settings
) -> tuple[str | None, str | None]:
    """(target, None) when the system can carry the action out, else (None, reason)."""
    if action in ("block_ip", "monitor"):
        ip = incident["src_ip"]
        if action == "block_ip" and _protected(ip, cfg):
            return None, "protected_ip"
        return ip, None
    if action == "isolate_host":
        return (incident["dest_ip"], None) if incident["dest_ip"] else (None, "no_host")
    if action == "reset_password":
        users = (
            conn.execute(
                text(
                    "SELECT DISTINCT fields->>'username' FROM evidence WHERE incident_id = :id"
                    " AND source = 'auth_log' AND fields->>'username' IS NOT NULL"
                ),
                {"id": incident["id"]},
            )
            .scalars()
            .all()
        )
        if len(users) == 1:
            return users[0], None
        return None, "no_account" if not users else "several_accounts"
    return None, "manual_only"
