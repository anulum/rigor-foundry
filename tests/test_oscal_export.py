# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — OSCAL assessment-results export tests
"""Verify deterministic OSCAL export of candidate observations without attestation."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import cast

import pytest
from signing_fixtures import pack_signature, trust_store

from rigor_foundry.compliance_maps import NON_CERTIFICATION_NOTICE, builtin_template
from rigor_foundry.control_assessment import ControlAssessment
from rigor_foundry.effective_profile import (
    AdapterLock,
    EffectiveControl,
    EffectiveProfileLock,
    PackVerification,
)
from rigor_foundry.models import canonical_digest
from rigor_foundry.oscal_export import OSCAL_VERSION, export_digest, report_oscal
from rigor_foundry.project_profile import (
    REQUIRED_INTENT_CATEGORIES,
    PackSelection,
    ProjectIntent,
    ProjectProfile,
    RequirementBinding,
    RequirementCategory,
)
from rigor_foundry.standard_pack import (
    ControlDefinition,
    EvidenceContract,
    RemediationContract,
    StandardPack,
)

GENERATED_AT = "2026-07-15T12:00:00Z"
MAPPED_DOMAIN = "application-security"
GAP_DOMAIN = "scientific-numerical-correctness"


def _control(control_id: str, domain: str) -> ControlDefinition:
    """Return one require-mode control definition in a chosen domain."""
    return ControlDefinition.build(
        control_id=control_id,
        version="1.0.0",
        title=f"Control for {domain}",
        domain=domain,
        severity="P1",
        target_level="production",
        mode="require",
        default_applicable=True,
        condition=None,
        evidence=EvidenceContract.build(
            contract_id=f"{control_id}/evidence",
            required_adapters=("scan-adapter",),
            evidence_types=("scan-report",),
            freshness_seconds=3600,
            minimum_independent_reviewers=1,
        ),
        remediation=RemediationContract.build(
            dependencies=(),
            procedure_ids=("fix",),
            acceptance_gates=("gate",),
            reopen_triggers=("source-change",),
            independent_verifier_required=True,
        ),
    )


def _pack() -> StandardPack:
    """Return a signed pack with a mapped-domain and a gap-domain control."""
    controls = (
        _control("core/app-security", MAPPED_DOMAIN),
        _control("core/numerics", GAP_DOMAIN),
    )
    source_digest = "1" * 64
    payload = StandardPack.payload_digest(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core",
        source_digest=source_digest,
        licence="MIT",
        controls=controls,
    )
    return StandardPack.build(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core",
        source_digest=source_digest,
        licence="MIT",
        signature=pack_signature(payload),
        controls=controls,
    )


def _adapter(domains: tuple[str, ...]) -> AdapterLock:
    """Return one adapter lock covering the chosen domains."""
    return AdapterLock.build(
        adapter_id="scan-adapter",
        version="1.0.0",
        executable_digest="5" * 64,
        config_digest="6" * 64,
        command_digest="7" * 64,
        environment_digest="8" * 64,
        domains=domains,
    )


def _lock() -> tuple[EffectiveProfileLock, tuple[EffectiveControl, ...]]:
    """Return one lock with a mapped-domain and a gap-domain effective control."""
    standard = _pack()
    requirements = tuple(
        RequirementBinding.build(cast(RequirementCategory, category), ("explicit",))
        for category in sorted(REQUIRED_INTENT_CATEGORIES)
    )
    intent = ProjectIntent.build(
        risk_class="production",
        regulatory_classes=(),
        target_maturity="production",
        requirements=requirements,
    )
    project = ProjectProfile.build(
        profile_id="rigor-foundry",
        intent=intent,
        packs=(
            PackSelection.build(
                pack_id=standard.pack_id,
                version=standard.version,
                source_digest=standard.source_digest,
                pack_digest=standard.pack_digest,
                trusted_key_ids=(standard.signature.key_id,),
            ),
        ),
        variables=(),
        assignments=(),
        applicability=(),
        overlays=(),
        waivers=(),
        created_by="profile-owner",
        created_at=GENERATED_AT,
    )
    verification = PackVerification.build(
        pack=standard,
        trust_store=trust_store("trusted-key"),
        verified_at="2026-07-15T11:50:00Z",
    )
    controls = tuple(
        EffectiveControl.build(
            source_pack=standard,
            control=definition,
            applicable=True,
            applicability_rationale="explicit assessment scope",
            target_level="production",
            mode="require",
            active_waiver_ids=(),
            missing_adapter_ids=(),
            risk_acceptance_waiver_ids=(),
        )
        for definition in standard.controls
    )
    lock = EffectiveProfileLock.build(
        profile=project,
        packs=(standard,),
        verifications=(verification,),
        adapters=(_adapter((MAPPED_DOMAIN, GAP_DOMAIN)),),
        variables=(),
        controls=controls,
        warnings=(),
        trust_store=trust_store("trusted-key"),
        toolchain_digest="9" * 64,
        resolved_at=GENERATED_AT,
    )
    return lock, controls


def _assessment(lock: EffectiveProfileLock, control: EffectiveControl) -> ControlAssessment:
    """Return one needs-evidence assessment for a control."""
    return ControlAssessment.build(
        lock,
        control,
        status="needs-evidence",
        assessor="assessor",
        assessed_at=GENERATED_AT,
        rationale="evidence collection pending",
    )


def _document(template_id: str = "iso-iec-27001-2022") -> dict[str, object]:
    """Return the parsed OSCAL document for the two-control lock."""
    lock, controls = _lock()
    assessments = tuple(_assessment(lock, control) for control in controls)
    template = builtin_template(template_id)
    return cast(
        dict[str, object], json.loads(report_oscal(lock, assessments, template, GENERATED_AT))
    )


def test_export_is_deterministic_and_digest_bound() -> None:
    """Two exports of the same inputs are byte-identical and digest-stable."""
    lock, controls = _lock()
    assessments = tuple(_assessment(lock, control) for control in controls)
    template = builtin_template("iso-iec-27001-2022")
    first = report_oscal(lock, assessments, template, GENERATED_AT)
    second = report_oscal(lock, assessments, template, GENERATED_AT)
    assert first == second
    assert first.endswith("\n")
    document = json.loads(first)
    assert export_digest(lock, assessments, template, GENERATED_AT) == canonical_digest(document)


def test_document_states_the_non_attestation_boundary() -> None:
    """The document names OSCAL 1.1.3, the boundary, and the non-certification notice."""
    results = cast(dict[str, object], _document()["assessment-results"])
    metadata = cast(dict[str, object], results["metadata"])
    assert metadata["oscal-version"] == OSCAL_VERSION
    assert metadata["remarks"] == NON_CERTIFICATION_NOTICE
    import_ap = cast(dict[str, object], results["import-ap"])
    assert cast(str, import_ap["href"]).endswith("compliance-maps.md#export-boundary")
    prop_names = {
        cast(str, prop["name"]) for prop in cast(list[dict[str, object]], metadata["props"])
    }
    assert "unsupported-field" in prop_names


def test_mapped_and_gap_observations_are_distinguished() -> None:
    """A mapped domain carries related-control props; a gap domain carries none."""
    results = cast(dict[str, object], _document()["assessment-results"])
    result = cast(list[dict[str, object]], results["results"])[0]
    observations = cast(list[dict[str, object]], result["observations"])
    by_domain: dict[str, dict[str, object]] = {}
    for observation in observations:
        props = cast(list[dict[str, object]], observation["props"])
        domain = next(
            cast(str, prop["value"]) for prop in props if prop["name"] == "rigor-foundry-domain"
        )
        by_domain[domain] = observation

    mapped_props = cast(list[dict[str, object]], by_domain[MAPPED_DOMAIN]["props"])
    assert any(prop["name"] == "related-control" for prop in mapped_props)
    assert "reference(s) mapped" in cast(str, by_domain[MAPPED_DOMAIN]["remarks"])

    gap_props = cast(list[dict[str, object]], by_domain[GAP_DOMAIN]["props"])
    assert not any(prop["name"] == "related-control" for prop in gap_props)
    assert "does not define a control" in cast(str, by_domain[GAP_DOMAIN]["remarks"])


def test_export_rejects_foreign_absent_and_duplicate_assessments() -> None:
    """Lock mismatch, absent control, and duplicate control all fail closed."""
    lock, controls = _lock()
    assessment = _assessment(lock, controls[0])
    template = builtin_template("aicpa-tsc-2017")

    foreign = replace(assessment, lock_digest="0" * 64)
    with pytest.raises(ValueError, match="lock digest does not match"):
        report_oscal(lock, (foreign,), template, GENERATED_AT)

    absent = replace(assessment, effective_control_digest="0" * 64)
    with pytest.raises(ValueError, match="absent from the lock"):
        report_oscal(lock, (absent,), template, GENERATED_AT)

    with pytest.raises(ValueError, match="duplicated in the export"):
        report_oscal(lock, (assessment, assessment), template, GENERATED_AT)


def test_export_rejects_non_utc_generated_at() -> None:
    """A non-UTC generation timestamp fails closed."""
    lock, controls = _lock()
    assessments = (_assessment(lock, controls[0]),)
    template = builtin_template("aicpa-tsc-2017")
    with pytest.raises(ValueError, match="UTC"):
        report_oscal(lock, assessments, template, "2026-07-15T12:00:00+02:00")
