from app.agents.base import IncidentInfo, ask, json_list, untrusted_text
from app.agents.schemas import DetectionOutput, ForensicsOutput, InvestigationOutput
from app.evidence.store import EvidenceEvent
from app.llm.client import LLMClient


def run(
    client: LLMClient,
    incident: IncidentInfo,
    evidence: list[EvidenceEvent],
    detection: DetectionOutput,
    investigation: InvestigationOutput,
    unavailable: list[str],
) -> ForensicsOutput:
    task = (
        f"{incident.describe()}\n"
        "Look for impact on the host: code executed by the web server process, outbound "
        "connections, or successful logins from the attacking source. Cite evidence ids "
        "for every finding.\n"
        f"Log sources unavailable for this incident: {json_list(unavailable)}. "
        "Report exactly these as missing_sources."
    )
    return ask(
        client,
        "forensics",
        task,
        untrusted_text(evidence, {"detection": detection, "investigation": investigation}),
        ForensicsOutput,
        {e.id for e in evidence},
    )
