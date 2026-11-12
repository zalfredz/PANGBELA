from app.agents.base import IncidentInfo, ask, json_list, untrusted_text
from app.agents.schemas import DetectionOutput, InvestigationOutput
from app.evidence.store import EvidenceEvent
from app.llm.client import LLMClient


def run(
    client: LLMClient,
    incident: IncidentInfo,
    evidence: list[EvidenceEvent],
    detection: DetectionOutput,
    round_: int,
    max_rounds: int,
    unavailable: list[str],
) -> InvestigationOutput:
    last = round_ >= max_rounds
    task = (
        f"{incident.describe()}\n"
        f"Investigation round {round_} of at most {max_rounds}. Test the Detection Agent's "
        "hypothesis against the access log and auth log evidence: list findings that "
        "support it and counter_evidence against it, each citing evidence ids, then "
        "propose a status.\n"
        f"Log sources unavailable for this incident: {json_list(unavailable)}.\n"
        + (
            "This is the last round: leave evidence_requests empty."
            if last
            else "If you need more evidence, list evidence_requests; otherwise leave it empty."
        )
    )
    return ask(
        client,
        "investigation",
        task,
        untrusted_text(evidence, {"detection": detection}),
        InvestigationOutput,
        {e.id for e in evidence},
    )
