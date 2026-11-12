"""Patch policy engine (docs/security/PAMELA_PATCH_POLICY.md).

This is deliberately separate from `pamela.py`: containment actions (block, isolate,
reset) and patching have different risk and different approvals. Functions here are pure
so every denial case is unit-tested without Docker; the lab executor is
`lab/patch/apply.py` and only calls this engine.
"""

from dataclasses import dataclass

# Patching is only considered for these incident severities; high/critical always need a
# person. Order matters for the "above the configured maximum" check.
SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")
AUTO_SEVERITIES = ("low", "medium")
# Asset criticality values the lab policy allows an automatic patch to touch.
PATCHABLE_CRITICALITY = frozenset({"lab"})


@dataclass(frozen=True)
class Template:
    id: str
    version: str
    sha256: str
    applies_to: str


@dataclass(frozen=True)
class Target:
    id: str
    service: str
    image: str
    criticality: str
    managed: bool


@dataclass(frozen=True)
class PatchConfig:
    # Off until the safety gates pass; the lab executor must pass it explicitly.
    enabled: bool = False
    max_severity: str = "medium"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def check(
    incident: dict,
    template: Template | None,
    template_sha256: str | None,
    target: Target | None,
    cfg: PatchConfig,
) -> Decision:
    """Allow or deny one automatic patch. The first failing check wins, so the reason
    is stable and auditable."""
    if not cfg.enabled:
        return Decision(False, "auto_patch_disabled")
    severity = incident.get("severity")
    if severity in ("high", "critical"):
        return Decision(False, "needs_human")
    if severity not in AUTO_SEVERITIES:
        return Decision(False, "severity_not_eligible")
    if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(cfg.max_severity):
        return Decision(False, "above_configured_max")
    if incident.get("attack_type") != "rce":
        return Decision(False, "unsupported_attack")
    if incident.get("pipeline_state") != "done":
        return Decision(False, "not_decided")
    if incident.get("verification_state") != "verified":
        return Decision(False, "unverified_evidence")
    if template is None:
        return Decision(False, "unsupported_template")
    if template_sha256 != template.sha256:
        return Decision(False, "template_hash_mismatch")
    if target is None or not target.managed:
        return Decision(False, "unmanaged_target")
    if target.criticality not in PATCHABLE_CRITICALITY:
        return Decision(False, "asset_not_eligible")
    if target.image != template.applies_to:
        return Decision(False, "target_mismatch")
    return Decision(True, "eligible")
