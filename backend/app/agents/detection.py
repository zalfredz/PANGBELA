from app.agents.base import IncidentInfo, ask, untrusted_text
from app.agents.schemas import DetectionOutput
from app.evidence.store import EvidenceEvent
from app.llm.client import LLMClient


def run(
    client: LLMClient, incident: IncidentInfo, evidence: list[EvidenceEvent]
) -> DetectionOutput:
    # What opened the incident: Suricata alerts, or the login events that crossed the
    # brute force threshold.
    trigger = "auth_log" if incident.opened_by == "auth_log" else "suricata"
    seen = [e for e in evidence if e.source == trigger]
    what = "login events" if trigger == "auth_log" else "Suricata alerts"
    task = (
        f"{incident.describe()}\n"
        f"Read the {what} in the evidence. Decide the attack_type, state your "
        "hypothesis, list indicators that cite evidence ids, and name the log sources "
        "that would confirm or refute it."
    )
    return ask(
        client,
        "detection",
        task,
        untrusted_text(seen, {}),
        DetectionOutput,
        {e.id for e in seen},
    )
