"""Every branch of max_status, rules_gate, compute_facts, verification, confidence and
the citation check, plus the rules-level shape of T1 to T9 from the team baseline.

Evidence below is built in memory only to shape facts; it is never stored.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.agents.schemas import (
    DecisionOutput,
    DetectionOutput,
    EvidenceRequest,
    Finding,
    ForensicsOutput,
    InvestigationOutput,
)
from app.config import Settings
from app.evidence.store import EvidenceEvent
from app.graph.rules import (
    INSUFFICIENT,
    PARTIAL,
    VERIFIED,
    Facts,
    check_citations,
    cited_ids,
    compute_facts,
    confidence,
    evidence_coverage,
    max_status,
    provisional,
    rules_gate,
    verification_state,
)

ATTACKER = "198.51.100.23"
T0 = datetime(2026, 11, 11, 2, 0, 0, tzinfo=UTC)
INCIDENT = uuid4()

CFG = Settings(
    CORRELATION_WINDOW_BEFORE_SECONDS=2,
    CORRELATION_WINDOW_SECONDS=10,
    BRUTE_FORCE_MIN_FAILURES=10,
    BRUTE_FORCE_WINDOW_SECONDS=120,
    WEB_SERVER_EXES="gunicorn,/usr/sbin/apache2",
)
ALL_READABLE = {"access_log": True, "auth_log": True, "process": True}
RCE_SOURCES = frozenset({"suricata", "access_log", "process"})


def ev(source, seconds=0.0, ip=ATTACKER, **fields) -> EvidenceEvent:
    return EvidenceEvent(
        incident_id=INCIDENT,
        source=source,
        ts=T0 + timedelta(seconds=seconds),
        src_ip=ip,
        summary=source,
        raw="",
        fields=fields,
    )


def alert(url="/ping?host=1;id") -> EvidenceEvent:
    return ev("suricata", 0, http_url=url)


def request(seconds=0.0, path="/ping", ip=ATTACKER, request_id="req-1") -> EvidenceEvent:
    return ev("access_log", seconds, ip=ip, path=path, query="host=1;id", request_id=request_id)


def proc(seconds, parent="/usr/local/bin/gunicorn", request_id="req-1") -> EvidenceEvent:
    return ev("process", seconds, ip=None, parent_exe=parent, exe="/bin/sh", request_id=request_id)


def auth(seconds, result, ip=ATTACKER, authorized=None) -> EvidenceEvent:
    return ev(
        "auth_log",
        seconds,
        ip=ip,
        result=result,
        username="admin",
        service="web",
        authorized=authorized,
    )


def facts(evidence, readable=ALL_READABLE) -> Facts:
    return compute_facts(ATTACKER, evidence, CFG, readable)


def investigation(ruled_benign=False, findings=True) -> InvestigationOutput:
    return InvestigationOutput(
        hypothesis_holds=not ruled_benign,
        findings=[Finding(claim="c", evidence_ids=["ev_1"])] if findings else [],
        counter_evidence=[],
        scanner_likely=False,
        ruled_benign=ruled_benign,
        evidence_requests=[],
        proposed_status="benign" if ruled_benign else "attempted",
    )


# --- max_status: every branch ---------------------------------------------------------


@pytest.mark.parametrize(
    ("f", "expected"),
    [
        (Facts(exec_linked=True, payload_logged=True), "confirmed"),
        (Facts(exec_linked=True), "confirmed"),
        (Facts(exec_unlinked=True, payload_logged=True), "attempted"),
        (Facts(payload_logged=True), "attempted"),
        (Facts(exec_unlinked=True), "suspected"),
        (Facts(), "suspected"),
    ],
)
def test_max_status_rce(f, expected):
    assert max_status("rce", f, CFG) == expected


@pytest.mark.parametrize(
    ("f", "expected"),
    [
        (Facts(failures=10, success_after=True, unauthorized_success=True), "confirmed"),
        # A success with no authorized=false does not confirm.
        (Facts(failures=10, success_after=True, unmarked_success=True), "attempted"),
        (Facts(failures=10, success_after=True), "attempted"),
        (Facts(failures=10), "attempted"),
        (Facts(failures=25), "attempted"),
        (Facts(failures=9, success_after=True, unauthorized_success=True), "benign"),
        (Facts(), "benign"),
    ],
)
def test_max_status_brute_force(f, expected):
    assert max_status("brute_force", f, CFG) == expected


def test_max_status_unknown_is_suspected_whatever_the_facts():
    assert max_status("unknown", Facts(exec_linked=True, failures=99), CFG) == "suspected"


def test_threshold_comes_from_config():
    cfg = CFG.model_copy(update={"BRUTE_FORCE_MIN_FAILURES": 3})
    assert max_status("brute_force", Facts(failures=3), cfg) == "attempted"


# --- rules_gate: every branch ---------------------------------------------------------

RCE_ATTEMPTED = Facts(payload_logged=True, sources_available=frozenset({"suricata", "access_log"}))
RCE_CONFIRMED = Facts(
    payload_logged=True, exec_linked=True, host_available=True, sources_available=RCE_SOURCES
)


def test_gate_agrees_no_conflict():
    g = rules_gate("rce", RCE_ATTEMPTED, "attempted", investigation(), CFG)
    assert (g.status, g.severity, g.conflict) == ("attempted", "medium", None)


def test_gate_overrides_upgrade_and_records_conflict():
    g = rules_gate("rce", RCE_ATTEMPTED, "confirmed", investigation(), CFG)
    assert g.status == "attempted"
    assert g.conflict == "proposed confirmed, rules allow attempted"


def test_gate_overrides_downgrade_that_is_not_benign():
    g = rules_gate("rce", RCE_CONFIRMED, "attempted", investigation(), CFG)
    assert g.status == "confirmed"
    assert g.severity == "critical"
    assert g.conflict == "proposed attempted, rules allow confirmed"


def test_gate_rejects_llm_only_benign_downgrade():
    # Cited findings prove events exist, not that the model read them right. A benign
    # verdict needs deterministic facts, so the proposal is recorded as a conflict.
    g = rules_gate("rce", RCE_ATTEMPTED, "benign", investigation(ruled_benign=True), CFG)
    assert (g.status, g.severity, g.allowed) == ("attempted", "medium", "attempted")
    assert g.conflict == "proposed benign, rules allow attempted"


def test_gate_never_downgrades_confirmed_to_benign():
    g = rules_gate("rce", RCE_CONFIRMED, "benign", investigation(ruled_benign=True), CFG)
    assert g.status == "confirmed"
    assert g.conflict == "proposed benign, rules allow confirmed"


def test_gate_refuses_benign_when_investigation_did_not_rule_benign():
    g = rules_gate("rce", RCE_ATTEMPTED, "benign", investigation(ruled_benign=False), CFG)
    assert g.status == "attempted"
    assert g.conflict is not None


def test_gate_refuses_benign_without_findings():
    inv = investigation(ruled_benign=True, findings=False)
    g = rules_gate("rce", RCE_ATTEMPTED, "benign", inv, CFG)
    assert g.status == "attempted"
    assert g.conflict is not None


def test_gate_unknown_attack_type():
    f = Facts(sources_available=frozenset({"suricata"}))
    assert rules_gate("unknown", f, "suspected", investigation(), CFG).severity == "low"
    g = rules_gate("unknown", f, "benign", investigation(ruled_benign=True), CFG)
    assert (g.status, g.severity) == ("suspected", "low")
    assert g.conflict is not None


@pytest.mark.parametrize(
    ("attack_type", "status", "severity"),
    [
        ("rce", "confirmed", "critical"),
        ("rce", "attempted", "medium"),
        ("rce", "suspected", "low"),
        ("brute_force", "confirmed", "high"),
        ("brute_force", "attempted", "medium"),
        ("brute_force", "benign", "none"),
    ],
)
def test_severity_map(attack_type, status, severity):
    f = {
        ("rce", "confirmed"): Facts(exec_linked=True),
        ("rce", "attempted"): Facts(payload_logged=True),
        ("rce", "suspected"): Facts(),
        ("brute_force", "confirmed"): Facts(
            failures=10, success_after=True, unauthorized_success=True
        ),
        ("brute_force", "attempted"): Facts(failures=10),
        ("brute_force", "benign"): Facts(),
    }[(attack_type, status)]
    assert rules_gate(attack_type, f, status, investigation(), CFG).severity == severity


def test_gate_reports_verification_coverage_and_level():
    g = rules_gate("rce", RCE_ATTEMPTED, "attempted", investigation(), CFG)
    assert (g.verification, g.evidence_coverage, g.confidence, g.confidence_level) == (
        INSUFFICIENT,
        0.67,
        0.67,
        "low",
    )


# --- coverage, verification, confidence -----------------------------------------------


def test_coverage_is_share_of_required_sources():
    assert evidence_coverage("rce", RCE_CONFIRMED) == 1.0
    assert evidence_coverage("rce", RCE_ATTEMPTED) == 0.67
    assert evidence_coverage("brute_force", Facts()) == 0.0
    # Brute force needs only the auth log: no Suricata alert is not missing telemetry.
    assert evidence_coverage("brute_force", Facts(sources_available=frozenset({"auth_log"}))) == 1


@pytest.mark.parametrize(
    ("attack_type", "f", "expected"),
    [
        ("rce", RCE_CONFIRMED, VERIFIED),
        ("rce", Facts(payload_logged=True, sources_available=RCE_SOURCES), VERIFIED),
        ("rce", Facts(exec_unlinked=True, sources_available=RCE_SOURCES), PARTIAL),
        (
            "rce",
            Facts(exec_linked=True, exec_unlinked=True, sources_available=RCE_SOURCES),
            VERIFIED,
        ),
        ("rce", RCE_ATTEMPTED, INSUFFICIENT),
        ("brute_force", Facts(failures=12, sources_available=frozenset({"auth_log"})), VERIFIED),
        (
            "brute_force",
            Facts(
                failures=12,
                success_after=True,
                unmarked_success=True,
                sources_available=frozenset({"auth_log"}),
            ),
            PARTIAL,
        ),
        (
            "brute_force",
            Facts(
                failures=12,
                success_after=True,
                unauthorized_success=True,
                unmarked_success=True,
                sources_available=frozenset({"auth_log"}),
            ),
            VERIFIED,
        ),
        (
            "brute_force",
            Facts(failures=12, success_after=True, sources_available=frozenset({"auth_log"})),
            VERIFIED,  # every success marked authorized=true: a legitimate login
        ),
        ("brute_force", Facts(sources_available=frozenset({"suricata"})), INSUFFICIENT),
        ("unknown", Facts(sources_available=frozenset({"suricata"})), PARTIAL),
    ],
)
def test_verification_state(attack_type, f, expected):
    assert verification_state(attack_type, f) == expected


@pytest.mark.parametrize(
    ("coverage", "verification", "conflict", "expected"),
    [
        (1.0, VERIFIED, None, (1.0, "high")),
        (1.0, VERIFIED, "x", (0.8, "medium")),
        (1.0, PARTIAL, None, (0.8, "medium")),
        (1.0, PARTIAL, "x", (0.6, "low")),
        (0.67, INSUFFICIENT, None, (0.67, "low")),
        (0.0, INSUFFICIENT, "x", (0.0, "low")),
    ],
)
def test_confidence(coverage, verification, conflict, expected):
    assert confidence(coverage, verification, conflict) == expected


def test_provisional_is_the_rules_maximum():
    p = provisional("rce", RCE_CONFIRMED, CFG)
    assert (p.status, p.severity, p.verification) == ("confirmed", "critical", VERIFIED)


# --- compute_facts: RCE ---------------------------------------------------------------


def test_payload_logged_when_access_log_has_alert_path():
    assert facts([alert(), request()]).payload_logged


def test_payload_matching_ignores_query_encoding_differences():
    assert facts([alert("/ping?host=1%3Bid"), request(path="/ping")]).payload_logged


def test_payload_not_logged_for_other_path_or_ip():
    f = facts([alert(), request(path="/ping-safe"), request(ip="198.51.100.99")])
    assert not f.payload_logged


def test_exec_linked_by_request_id_inside_window():
    f = facts([alert(), request(0), proc(10)])
    assert (f.exec_linked, f.exec_unlinked) == (True, False)


def test_window_runs_from_two_seconds_before_to_ten_after():
    assert facts([alert(), request(0), proc(-2)]).exec_linked
    assert facts([alert(), request(0), proc(10)]).exec_linked
    assert not facts([alert(), request(0), proc(-2.001)]).exec_linked
    assert not facts([alert(), request(0), proc(10.001)]).exec_linked


def test_timing_and_parent_without_request_id_is_not_linked():
    f = facts([alert(), request(0), proc(1, request_id=None)])
    assert (f.exec_linked, f.exec_unlinked, f.ambiguous) == (False, True, False)


def test_different_request_id_is_not_linked():
    f = facts([alert(), request(0, request_id="req-1"), proc(1, request_id="req-2")])
    assert (f.exec_linked, f.exec_unlinked) == (False, True)


def test_request_without_id_never_links():
    f = facts([alert(), request(0, request_id=None), proc(1, request_id=None)])
    assert (f.exec_linked, f.exec_unlinked) == (False, True)


def test_unlinked_process_in_two_requests_windows_is_ambiguous():
    reqs = [request(0, request_id="a"), request(3, request_id="b")]
    f = facts([alert(), *reqs, proc(4, request_id=None)])
    assert (f.exec_unlinked, f.ambiguous) == (True, True)


def test_link_requires_web_server_parent():
    f = facts([alert(), request(0), proc(1, parent="/usr/sbin/cron")])
    assert (f.exec_linked, f.exec_unlinked) == (False, False)


def test_link_matches_configured_full_path():
    assert facts([alert(), request(0), proc(1, parent="/usr/sbin/apache2")]).exec_linked


def test_link_needs_logged_request():
    f = facts([alert(), proc(1)])
    assert (f.exec_linked, f.exec_unlinked) == (False, False)


def test_no_web_server_configured_means_never_confirmed():
    cfg = CFG.model_copy(update={"WEB_SERVER_EXES": ""})
    f = compute_facts(ATTACKER, [alert(), request(0), proc(1)], cfg, ALL_READABLE)
    assert not f.exec_linked


# --- compute_facts: brute force -------------------------------------------------------


def test_failures_counted_in_sliding_window():
    burst = [auth(i * 10, "failure") for i in range(12)]  # 12 in 110 s
    assert facts(burst).failures == 12


def test_failures_spread_beyond_window_are_not_all_counted():
    spread = [auth(i * 30, "failure") for i in range(12)]  # one every 30 s
    assert facts(spread).failures == 5  # 0, 30, 60, 90, 120 fit in 120 s


def test_failures_from_other_ip_ignored():
    assert facts([auth(i, "failure", ip="198.51.100.99") for i in range(12)]).failures == 0


def test_success_after_first_failure():
    f = facts([*(auth(i, "failure") for i in range(10)), auth(11, "success")])
    assert f.success_after


def test_success_before_failures_does_not_count():
    f = facts([auth(-5, "success"), *(auth(i, "failure") for i in range(10))])
    assert not f.success_after


def test_success_without_failures_is_not_success_after():
    assert not facts([auth(0, "success")]).success_after


@pytest.mark.parametrize(
    ("authorized", "unauthorized", "unmarked"),
    [(False, True, False), (True, False, False), (None, False, True)],
)
def test_authorized_field_on_success_after(authorized, unauthorized, unmarked):
    f = facts(
        [*(auth(i, "failure") for i in range(10)), auth(11, "success", authorized=authorized)]
    )
    assert (f.success_after, f.unauthorized_success, f.unmarked_success) == (
        True,
        unauthorized,
        unmarked,
    )


def test_authorized_false_on_a_failure_is_ignored():
    f = facts([auth(i, "failure", authorized=False) for i in range(10)])
    assert not f.unauthorized_success


# --- compute_facts: sources -----------------------------------------------------------


def test_readable_log_counts_as_available_even_without_matches():
    f = facts([alert()], readable={"access_log": True, "process": True})
    assert f.sources_available == {"suricata", "access_log", "process"}
    assert f.host_available


def test_unreadable_source_without_evidence_is_missing():
    f = facts([alert()], readable={})
    assert f.sources_available == {"suricata"}
    assert not f.host_available


def test_process_evidence_alone_makes_host_available():
    assert facts([alert(), proc(1)], readable={}).host_available


# --- T1 to T9 at the rules level (team baseline, 11 Nov 2026) --------------------------
# Expected outcomes from the team's answer to Q15. These check the code path each
# scenario takes; the scenarios themselves run in the lab (M7) with real captures.


def gate(attack_type, evidence, proposed, inv=None, readable=ALL_READABLE):
    return rules_gate(attack_type, facts(evidence, readable), proposed, inv or investigation(), CFG)


def test_t1_successful_rce_confirmed_critical():
    g = gate("rce", [alert(), request(0), proc(1)], "confirmed")
    assert (g.status, g.severity, g.verification, g.confidence_level) == (
        "confirmed",
        "critical",
        VERIFIED,
        "high",
    )


def test_t2_failed_rce_attempted_medium():
    g = gate("rce", [alert(), request(0)], "attempted")
    assert (g.status, g.severity, g.verification) == ("attempted", "medium", VERIFIED)


def test_t3_scanner_sweep_without_classified_exploit_is_suspected():
    # A scanner signature is not in RCE_SIGNATURE_IDS, so code leaves the type
    # unknown, and unknown can't go above suspected whatever the agents say.
    g = gate("unknown", [alert("/admin"), request(0, path="/admin")], "attempted")
    assert (g.status, g.severity) == ("suspected", "low")


def test_t4_benign_request_triggering_ids_is_not_downgraded_by_the_llm():
    # Without a trusted benign source (an authorization policy, an approved-operation
    # list) the attempt stays attempted; the model's "this was benign" is a conflict.
    g = gate("rce", [alert(), request(0)], "benign", investigation(ruled_benign=True))
    assert (g.status, g.severity) == ("attempted", "medium")
    assert g.conflict == "proposed benign, rules allow attempted"


def test_t5_brute_force_then_unauthorized_login_confirmed_high():
    burst = [*(auth(i, "failure") for i in range(12)), auth(30, "success", authorized=False)]
    g = gate("brute_force", burst, "confirmed")
    assert (g.status, g.severity, g.verification) == ("confirmed", "high", VERIFIED)


def test_t5_without_authorized_field_stays_attempted_and_partial():
    burst = [*(auth(i, "failure") for i in range(12)), auth(30, "success")]
    g = gate("brute_force", burst, "confirmed")
    assert (g.status, g.severity, g.verification) == ("attempted", "medium", PARTIAL)


def test_t6_brute_force_without_success_attempted_medium():
    g = gate("brute_force", [auth(i, "failure") for i in range(12)], "attempted")
    assert (g.status, g.severity, g.verification) == ("attempted", "medium", VERIFIED)


def test_t7_normal_password_mistakes_benign():
    g = gate(
        "brute_force", [auth(0, "failure"), auth(20, "failure"), auth(40, "success")], "benign"
    )
    assert (g.status, g.severity) == ("benign", "none")


def test_t8_injected_benign_proposal_does_not_change_verdict():
    # The injected text makes the decision propose benign, but investigation did not
    # rule it benign with cited findings, so the rules keep attempted.
    g = gate("rce", [alert(), request(0)], "benign", investigation(ruled_benign=False))
    assert (g.status, g.severity) == ("attempted", "medium")
    assert g.conflict == "proposed benign, rules allow attempted"


def test_t9_missing_host_telemetry_never_confirmed():
    readable = {"access_log": True, "auth_log": True}
    g = gate("rce", [alert(), request(0)], "confirmed", readable=readable)
    assert g.status == "attempted"
    assert (g.verification, g.evidence_coverage, g.confidence_level) == (INSUFFICIENT, 0.67, "low")


# --- citation check -------------------------------------------------------------------


def test_cited_ids_walks_nested_findings():
    out = InvestigationOutput(
        hypothesis_holds=True,
        findings=[Finding(claim="a", evidence_ids=["ev_1", "ev_2"])],
        counter_evidence=[Finding(claim="b", evidence_ids=["ev_2", "ev_3"])],
        scanner_likely=False,
        ruled_benign=False,
        evidence_requests=[EvidenceRequest(source="process", reason="r")],
        proposed_status="attempted",
    )
    assert cited_ids(out) == ["ev_1", "ev_2", "ev_3"]


def test_check_citations_accepts_known_ids():
    out = DetectionOutput(
        attack_type="rce",
        hypothesis="h",
        indicators=[Finding(claim="a", evidence_ids=["ev_1"])],
        suggested_sources=["access_log"],
    )
    assert check_citations(out, {"ev_1", "ev_9"}) == ["ev_1"]


def test_check_citations_rejects_unknown_ids():
    out = ForensicsOutput(
        impact_found=True,
        impact_type="code_execution",
        findings=[Finding(claim="a", evidence_ids=["ev_1", "ev_fake"])],
        checked_sources=["process"],
        missing_sources=[],
    )
    with pytest.raises(ValueError, match="ev_fake"):
        check_citations(out, {"ev_1"})


def decision_with_report(report_md: str) -> DecisionOutput:
    return DecisionOutput(
        proposed_status="attempted",
        proposed_severity="medium",
        summary="s",
        report_md=report_md,
        recommendations=[],
    )


def test_report_references_are_citations():
    out = decision_with_report("Payload logged [ev_aaa111bbb222], alert [ev_ccc333ddd444].")
    assert cited_ids(out) == ["ev_aaa111bbb222", "ev_ccc333ddd444"]
    assert check_citations(out, {"ev_aaa111bbb222", "ev_ccc333ddd444"})


def test_unknown_report_reference_is_rejected():
    with pytest.raises(ValueError, match="ev_made_up"):
        check_citations(decision_with_report("See [ev_made_up]."), {"ev_aaa111bbb222"})


def test_bracketed_id_inside_a_claim_is_not_a_citation():
    # An attacker can put "[ev_x]" in a URL; an agent quoting it in a claim must not
    # make the output invalid. Only evidence_ids and report_md count.
    out = DetectionOutput(
        attack_type="rce",
        hypothesis="URL was /ping?x=[ev_attacker]",
        indicators=[Finding(claim="quoted [ev_attacker]", evidence_ids=["ev_1"])],
        suggested_sources=[],
    )
    assert check_citations(out, {"ev_1"}) == ["ev_1"]


def test_finding_without_evidence_is_invalid():
    with pytest.raises(ValueError):
        Finding(claim="no evidence", evidence_ids=[])
