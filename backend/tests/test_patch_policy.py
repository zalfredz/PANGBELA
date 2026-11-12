"""Every branch of the patch policy engine. No Docker, no DB: the executor is tested
separately against the real lab."""

import pytest

from app.pamela_patch import PatchConfig, Target, Template, check

INC = {
    "severity": "medium",
    "attack_type": "rce",
    "pipeline_state": "done",
    "verification_state": "verified",
}
TPL = Template("v1_sanitize_ping", "1", "abc123", "pangbela-lab-app")
TGT = Target("lab-web", "app", "pangbela-lab-app", "lab", managed=True)
ON = PatchConfig(enabled=True)


def run(inc=None, tpl=TPL, sha="abc123", target=TGT, cfg=ON):
    return check({**INC, **(inc or {})}, tpl, sha, target, cfg)


def test_low_and_medium_eligible_pass():
    assert run({"severity": "low"}).reason == "eligible"
    assert run({"severity": "medium"}).reason == "eligible"


def test_disabled_by_default():
    d = check(INC, TPL, "abc123", TGT, PatchConfig())
    assert (d.allowed, d.reason) == (False, "auto_patch_disabled")


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_high_and_critical_need_a_person(severity):
    d = run({"severity": severity})
    assert (d.allowed, d.reason) == (False, "needs_human")


def test_max_severity_can_lower_the_ceiling():
    d = run({"severity": "medium"}, cfg=PatchConfig(enabled=True, max_severity="low"))
    assert d.reason == "above_configured_max"


@pytest.mark.parametrize("severity", ["none", "unknown", None])
def test_ineligible_severity(severity):
    assert run({"severity": severity}).reason == "severity_not_eligible"


def test_only_the_patchable_attack_type():
    assert run({"attack_type": "brute_force"}).reason == "unsupported_attack"


def test_undecided_incident_is_denied():
    assert run({"pipeline_state": "queued"}).reason == "not_decided"


@pytest.mark.parametrize("verification", ["partially_verified", "insufficient_telemetry", None])
def test_unverified_evidence_is_denied(verification):
    assert run({"verification_state": verification}).reason == "unverified_evidence"


def test_unknown_template_is_denied():
    assert run(tpl=None, sha=None).reason == "unsupported_template"


def test_tampered_template_is_denied():
    assert run(sha="deadbeef").reason == "template_hash_mismatch"


def test_unmanaged_target_is_denied():
    assert run(target=Target("x", "app", "pangbela-lab-app", "lab", managed=False)).reason == (
        "unmanaged_target"
    )
    assert run(target=None).reason == "unmanaged_target"


def test_wrong_asset_class_is_denied():
    assert run(target=Target("db", "postgres", "pangbela-lab-app", "production", True)).reason == (
        "asset_not_eligible"
    )


def test_target_image_must_match_the_template():
    assert run(target=Target("lab-web", "app", "other-app", "lab", True)).reason == (
        "target_mismatch"
    )
