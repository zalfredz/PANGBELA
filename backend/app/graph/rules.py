"""Rules gate and citation check (spec section 9).

Code computes the facts and the maximum allowed status; agents only interpret.
Nothing here calls the LLM, and only the rules node writes incidents.status.
"""

import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import timedelta

from pydantic import BaseModel

from app.agents.schemas import DecisionOutput, Finding, InvestigationOutput
from app.config import Settings
from app.evidence.store import EvidenceEvent

ORDER = ["benign", "suspected", "attempted", "confirmed"]

# DRAFT (Q7). Severity follows the rules status only; agents cannot pick it.
SEVERITY = {
    ("rce", "confirmed"): "critical",
    ("rce", "attempted"): "medium",
    ("rce", "suspected"): "low",
    ("rce", "benign"): "none",
    ("brute_force", "confirmed"): "high",
    ("brute_force", "attempted"): "medium",
    ("brute_force", "suspected"): "low",
    ("brute_force", "benign"): "none",
    ("unknown", "suspected"): "low",
    ("unknown", "benign"): "none",
}

REQUIRED_SOURCES = {
    "rce": ("suricata", "access_log", "process"),
    # Auth log only: the team expects brute force without any Suricata alert, so a
    # missing alert is not missing telemetry.
    "brute_force": ("auth_log",),
    # Not in the spec: an unclassified alert has only Suricata to stand on.
    "unknown": ("suricata",),
}

# DRAFT heuristic, not a calibrated probability: coverage minus these penalties.
CONFLICT_PENALTY = 0.2
PARTIAL_PENALTY = 0.2

VERIFIED = "verified"
PARTIAL = "partially_verified"
INSUFFICIENT = "insufficient_telemetry"

# Any bracketed ev_ reference, not just well-formed ids: a made-up id must be caught.
_REPORT_REF = re.compile(r"\[(ev_[^\]\s]+)\]")


@dataclass(frozen=True)
class Facts:
    payload_logged: bool = False
    host_available: bool = False
    # A web server child process in a request's window whose request_id matches it.
    exec_linked: bool = False
    # One in a request's window without that match: timing and parent alone don't
    # prove the request caused it (team answer Q6).
    exec_unlinked: bool = False
    # An unlinked one fell in the window of more than one request.
    ambiguous: bool = False
    # Among linked executions, what the lab's own execution policy said: not allowed
    # (unauthorized), allowed, or not stated at all. Linkage alone is not proof.
    exec_unauthorized: bool = False
    exec_authorized: bool = False
    exec_unverified: bool = False
    # A matching request the app marked as a pre-approved operation after verifying a
    # signed approval. Only then may an IDS hit be called benign.
    approved_operation: bool = False
    failures: int = 0
    success_after: bool = False
    # Among the successes after the first failure: one the lab marked authorized=false,
    # and one with no authorized field at all.
    unauthorized_success: bool = False
    unmarked_success: bool = False
    sources_available: frozenset[str] = field(default_factory=frozenset)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["sources_available"] = sorted(self.sources_available)
        return d


@dataclass(frozen=True)
class GateResult:
    allowed: str
    status: str
    severity: str
    confidence: float
    confidence_level: str
    evidence_coverage: float
    verification: str
    conflict: str | None


def _path(url: str) -> str:
    return url.split("?", 1)[0]


def _is_web_server(exe: object, web_server_exes: frozenset[str]) -> bool:
    if not isinstance(exe, str) or not exe:
        return False
    return exe in web_server_exes or os.path.basename(exe) in web_server_exes


def max_failures_in_window(failure_times: list, window: timedelta):
    """Largest number of failures inside any window of the given length, and the
    time of the first failure of the earliest such window."""
    times = sorted(failure_times)
    best, best_first, lo = 0, None, 0
    for hi, t in enumerate(times):
        while t - times[lo] > window:
            lo += 1
        if hi - lo + 1 > best:
            best, best_first = hi - lo + 1, times[lo]
    return best, best_first


def compute_facts(
    src_ip: str,
    evidence: list[EvidenceEvent],
    cfg: Settings,
    readable: Mapping[str, bool],
) -> Facts:
    """readable says, per log source, whether the log exists and we can parse it, so a
    source with no matching lines still counts as checked rather than missing."""
    by_source: dict[str, list[EvidenceEvent]] = {}
    for e in evidence:
        by_source.setdefault(e.source, []).append(e)

    sources_available = frozenset(
        s
        for s in ("suricata", "access_log", "auth_log", "process")
        if by_source.get(s) or readable.get(s, False)
    )

    # RCE. Matched on path, not full URL: Suricata and the web server can encode the
    # query string differently, and the payload usually sits in the query.
    alert_paths = {
        _path(e.fields["http_url"])
        for e in by_source.get("suricata", [])
        if isinstance(e.fields.get("http_url"), str)
    }
    requests = [
        e
        for e in by_source.get("access_log", [])
        if e.src_ip == src_ip and e.fields.get("path") in alert_paths
    ]
    approved_operation = any(e.fields.get("policy") == "approved" for e in requests)
    before = timedelta(seconds=cfg.CORRELATION_WINDOW_BEFORE_SECONDS)
    after = timedelta(seconds=cfg.CORRELATION_WINDOW_SECONDS)
    exec_linked = exec_unlinked = ambiguous = False
    exec_authorized = exec_unauthorized = exec_unverified = False
    for p in by_source.get("process", []):
        if not _is_web_server(p.fields.get("parent_exe"), cfg.web_server_exes):
            continue
        candidates = [r for r in requests if r.ts - before <= p.ts <= r.ts + after]
        if not candidates:
            continue
        rid = p.fields.get("request_id")
        if rid and any(r.fields.get("request_id") == rid for r in candidates):
            exec_linked = True
            allowed = p.fields.get("authorized")
            if allowed is False:
                exec_unauthorized = True
            elif allowed is True:
                exec_authorized = True
            else:
                exec_unverified = True
        else:
            exec_unlinked = True
            ambiguous = ambiguous or len(candidates) > 1

    # Brute force.
    auth = [e for e in by_source.get("auth_log", []) if e.src_ip == src_ip]
    failures, first_failure = max_failures_in_window(
        [e.ts for e in auth if e.fields.get("result") == "failure"],
        timedelta(seconds=cfg.BRUTE_FORCE_WINDOW_SECONDS),
    )
    successes = [
        e
        for e in auth
        if first_failure is not None
        and e.fields.get("result") == "success"
        and e.ts > first_failure
    ]

    return Facts(
        payload_logged=len(requests) > 0,
        host_available="process" in sources_available,
        exec_linked=exec_linked,
        exec_unlinked=exec_unlinked,
        ambiguous=ambiguous,
        exec_unauthorized=exec_unauthorized,
        exec_authorized=exec_authorized,
        exec_unverified=exec_unverified,
        approved_operation=approved_operation,
        failures=failures,
        success_after=bool(successes),
        unauthorized_success=any(e.fields.get("authorized") is False for e in successes),
        unmarked_success=any(e.fields.get("authorized") is None for e in successes),
        sources_available=sources_available,
    )


def max_status(attack_type: str, f: Facts, cfg: Settings) -> str:
    if attack_type == "rce":
        # Linkage proves a request and an execution are related. Only the lab's own
        # execution policy can say the execution was not allowed.
        if f.exec_unauthorized:
            return "confirmed"
        if f.exec_linked and f.exec_authorized and f.approved_operation:
            # A real alert, a real execution, and a verified approved operation.
            return "benign"
        if f.exec_linked or f.payload_logged:
            return "attempted"
        return "suspected"
    if attack_type == "brute_force":
        # A successful login alone is not proof of an unauthorized one (team answer Q6):
        # only a success the lab's auth service marked authorized=false confirms.
        if f.failures >= cfg.BRUTE_FORCE_MIN_FAILURES:
            return "confirmed" if f.unauthorized_success else "attempted"
        return "benign"
    return "suspected"


def evidence_coverage(attack_type: str, f: Facts) -> float:
    """Share of the attack type's required sources that are available."""
    required = REQUIRED_SOURCES[attack_type]
    return round(sum(s in f.sources_available for s in required) / len(required), 2)


def verification_state(attack_type: str, f: Facts) -> str:
    """Whether the evidence settles the question, kept apart from the status so that
    missing telemetry never reads as "the attack failed"."""
    if any(s not in f.sources_available for s in REQUIRED_SOURCES[attack_type]):
        return INSUFFICIENT
    if attack_type == "unknown":
        return PARTIAL  # the attack type itself is unresolved
    if attack_type == "rce" and f.exec_linked and f.exec_unverified:
        # The execution happened, but no trusted policy says whether it was allowed.
        return PARTIAL
    if attack_type == "rce" and f.exec_unlinked and not f.exec_linked:
        return PARTIAL
    if attack_type == "brute_force" and f.unmarked_success and not f.unauthorized_success:
        # A success with no authorized field: whether the account was compromised
        # can't be settled from the log.
        return PARTIAL
    return VERIFIED


def confidence(coverage: float, verification: str, conflict: str | None) -> tuple[float, str]:
    """DRAFT: (heuristic score 0-1, level). The level follows the team's definitions:
    low when needed sources are missing, high when verified with no contradiction."""
    score = coverage
    if verification == PARTIAL:
        score -= PARTIAL_PENALTY
    if conflict:
        score -= CONFLICT_PENALTY
    if verification == INSUFFICIENT or (verification == PARTIAL and conflict):
        level = "low"
    elif verification == VERIFIED and not conflict:
        level = "high"
    else:
        level = "medium"
    return round(max(score, 0.0), 2), level


def rules_gate(
    attack_type: str,
    facts: Facts,
    proposed: str,
    investigation: InvestigationOutput,
    cfg: Settings,
) -> GateResult:
    """The rules decide the status; the agents only propose one.

    A different proposal is recorded as a conflict but never changes the verdict. In
    particular there is no LLM-driven downgrade to benign: cited evidence ids prove an
    event exists, not that the model's reading of it is right, so a benign verdict may
    only come from max_status() and its deterministic facts. `investigation` stays in
    the signature for callers, but is not evidence the gate may trust.
    """
    allowed = max_status(attack_type, facts, cfg)
    final = allowed
    conflict = f"proposed {proposed}, rules allow {allowed}" if proposed != allowed else None
    coverage = evidence_coverage(attack_type, facts)
    verification = verification_state(attack_type, facts)
    score, level = confidence(coverage, verification, conflict)
    return GateResult(
        allowed=allowed,
        status=final,
        severity=SEVERITY[(attack_type, final)],
        confidence=score,
        confidence_level=level,
        evidence_coverage=coverage,
        verification=verification,
        conflict=conflict,
    )


@dataclass(frozen=True)
class Provisional:
    status: str
    severity: str
    verification: str


def provisional(attack_type: str, facts: Facts, cfg: Settings) -> Provisional:
    """The rules' answer before any agent has read the evidence: the highest status
    the facts allow. Used for early warnings; the pipeline's verdict replaces it."""
    status = max_status(attack_type, facts, cfg)
    return Provisional(
        status, SEVERITY[(attack_type, status)], verification_state(attack_type, facts)
    )


def cited_ids(output: BaseModel) -> list[str]:
    """Every evidence id cited by any Finding in output, plus the [ev_...] references in a
    decision's report_md, in order, without duplicates."""
    found: list[str] = []

    def walk(value: object) -> None:
        if isinstance(value, Finding):
            found.extend(i for i in value.evidence_ids if i not in found)
        elif isinstance(value, DecisionOutput):
            # Only report_md: the prompt asks it to cite ids in square brackets. Claims
            # elsewhere can quote attacker text, and a forged "[ev_...]" in a URL must
            # not be able to make every output invalid.
            found.extend(i for i in _REPORT_REF.findall(value.report_md) if i not in found)
        elif isinstance(value, BaseModel):
            for name in type(value).model_fields:
                walk(getattr(value, name))
        elif isinstance(value, list | tuple):
            for item in value:
                walk(item)

    walk(output)
    return found


def check_citations(output: BaseModel, known_ids: Iterable[str]) -> list[str]:
    """Raise ValueError if output cites an id not in this incident's evidence."""
    known = set(known_ids)
    cited = cited_ids(output)
    unknown = [i for i in cited if i not in known]
    if unknown:
        # The ids are model output; cap their length since this text goes back to the model.
        shown = ", ".join(repr(i[:40]) for i in unknown[:10])
        raise ValueError(
            f"cites {len(unknown)} evidence id(s) that are not in the evidence list: {shown}. "
            "Cite only ids shown in square brackets in the evidence."
        )
    return cited
