"""Shared by the four agents: prompt loading, evidence formatting and the LLM call."""

import json
from dataclasses import dataclass
from datetime import datetime
from functools import cache
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel

from app.evidence.redact import redact
from app.evidence.store import EvidenceEvent
from app.graph.rules import check_citations
from app.llm.client import LLMClient

PROMPTS = Path(__file__).resolve().parent.parent / "llm" / "prompts"


@dataclass(frozen=True)
class IncidentInfo:
    """Code-derived incident facts. IPs are validated inet values, safe for the task text."""

    id: UUID
    src_ip: str
    dest_ip: str | None
    first_seen: datetime
    last_seen: datetime
    # Set by code before any agent runs (lab signature ids, or the auth log
    # threshold); "unknown" leaves the type to the detection agent.
    attack_type: str = "unknown"
    opened_by: str = "suricata"

    def describe(self) -> str:
        if self.opened_by == "auth_log":
            text = (
                f"Incident {self.id}: opened by code because login failures from "
                f"{self.src_ip} reached the brute force threshold, events between "
                f"{_iso(self.first_seen)} and {_iso(self.last_seen)}."
            )
        else:
            text = (
                f"Incident {self.id}: traffic from {self.src_ip} to {self.dest_ip}, "
                f"alerts between {_iso(self.first_seen)} and {_iso(self.last_seen)}."
            )
        if self.attack_type != "unknown":
            text += f" Code has already classified the attack type as {self.attack_type}."
        return text


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@cache
def load_prompt(agent: str) -> str:
    return (PROMPTS / f"{agent}.md").read_text()


def _one_line(text: str) -> str:
    # A newline in attacker data could forge what looks like a separate evidence line.
    return text.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")


def format_evidence(events: list[EvidenceEvent]) -> str:
    """Evidence as the LLM sees it: one line each, secrets redacted (the stored raw
    line is not changed)."""
    if not events:
        return "(no evidence)"
    return "\n".join(
        f"[{e.id}] {_iso(e.ts)} {e.source} src={e.src_ip or '-'} | "
        f"{_one_line(redact(e.summary))} | raw: {_one_line(redact(e.raw))}"
        for e in events
    )


def format_outputs(outputs: dict[str, BaseModel | None]) -> str:
    parts = [
        f"{name} output:\n{out.model_dump_json(indent=1)}"
        for name, out in outputs.items()
        if out is not None
    ]
    return "\n\n".join(parts)


def untrusted_text(evidence: list[EvidenceEvent], outputs: dict[str, BaseModel | None]) -> str:
    """Evidence and earlier agent outputs both go in the untrusted block: outputs can
    quote payloads, URLs and command lines from the logs."""
    text = "Evidence (one per line, id in square brackets):\n" + format_evidence(evidence)
    if any(o is not None for o in outputs.values()):
        text += "\n\nEarlier agent outputs (they may quote attacker content):\n"
        text += format_outputs(outputs)
    return text


def ask[T: BaseModel](
    client: LLMClient,
    agent: str,
    task: str,
    untrusted: str,
    schema: type[T],
    known_ids: set[str],
) -> T:
    return client.complete_json(
        system=load_prompt(agent),
        task=task,
        untrusted=untrusted,
        schema=schema,
        check=lambda out: check_citations(out, known_ids),
    )


def json_list(values: list[str]) -> str:
    return json.dumps(sorted(values))
