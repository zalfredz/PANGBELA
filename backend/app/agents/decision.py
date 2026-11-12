from app.agents.base import IncidentInfo, ask, untrusted_text
from app.agents.schemas import (
    DecisionOutput,
    DetectionOutput,
    ForensicsOutput,
    InvestigationOutput,
)
from app.evidence.store import EvidenceEvent
from app.graph.rules import cited_ids
from app.llm.client import LLMClient


def run(
    client: LLMClient,
    incident: IncidentInfo,
    evidence: list[EvidenceEvent],
    detection: DetectionOutput,
    investigation: InvestigationOutput,
    forensics: ForensicsOutput | None,
) -> DecisionOutput:
    outputs = {"detection": detection, "investigation": investigation, "forensics": forensics}
    # Spec: the decision agent reads all outputs and the evidence they cited.
    cited = {i for out in outputs.values() if out is not None for i in cited_ids(out)}
    shown = [e for e in evidence if e.id in cited]
    skipped = (
        "Forensics was skipped because the investigation ruled the activity benign.\n"
        if forensics is None
        else ""
    )
    task = (
        f"{incident.describe()}\n"
        f"{skipped}"
        "Write the final assessment: propose a status and severity, a summary of at most "
        "two sentences, a Markdown report, and recommendations."
    )
    return ask(
        client,
        "decision",
        task,
        untrusted_text(shown, outputs),
        DecisionOutput,
        {e.id for e in evidence},
    )
