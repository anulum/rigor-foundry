# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed standard-pack tests
"""Verify exact, licensed, digest-bound standard control packs."""

from __future__ import annotations

from copy import deepcopy

import pytest
from signing_fixtures import pack_signature

from rigor_foundry.condition_language import ConditionExpression
from rigor_foundry.standard_pack import (
    PACK_COMPONENT_SCHEMA_VERSION,
    PACK_SCHEMA_VERSION,
    PACK_SIGNATURE_SCHEMA_VERSION,
    ControlDefinition,
    EvidenceContract,
    RemediationContract,
    StandardPack,
)
from rigor_foundry.trust import STANDARD_PACK_SIGNATURE_DOMAIN

SOURCE_DIGEST = "1" * 64


def control(*, control_id: str = "core/no-godfiles") -> ControlDefinition:
    """Return one complete architecture control."""
    evidence = EvidenceContract.build(
        contract_id="evidence/no-godfiles",
        required_adapters=("python-loc",),
        evidence_types=("loc-report",),
        freshness_seconds=3600,
        minimum_independent_reviewers=1,
    )
    remediation = RemediationContract.build(
        dependencies=(),
        procedure_ids=("split-module",),
        acceptance_gates=("focused-tests", "loc-gate"),
        reopen_triggers=("source-tree-changed",),
        independent_verifier_required=True,
    )
    return ControlDefinition.build(
        control_id=control_id,
        version="1.0.0",
        title="Production modules remain below the GodFile threshold",
        domain="godfile-responsibility",
        severity="P1",
        target_level="production",
        mode="require",
        default_applicable=True,
        condition=ConditionExpression.build(
            "eq",
            reference="profile.risk_class",
            value="production",
        ),
        evidence=evidence,
        remediation=remediation,
    )


def pack(*, pack_id: str = "core") -> StandardPack:
    """Return one signed pack whose metadata binds its canonical payload."""
    controls = (control(control_id=f"{pack_id}/no-godfiles"),)
    payload_digest = StandardPack.payload_digest(
        pack_id=pack_id,
        version="1.2.3",
        source_uri="https://standards.example/core/1.2.3",
        source_digest=SOURCE_DIGEST,
        licence="MIT",
        controls=controls,
    )
    signature = pack_signature(payload_digest, "standards-key-1")
    return StandardPack.build(
        pack_id=pack_id,
        version="1.2.3",
        source_uri="https://standards.example/core/1.2.3",
        source_digest=SOURCE_DIGEST,
        licence="MIT",
        signature=signature,
        controls=controls,
    )


def test_complete_pack_round_trips_with_all_nested_digests() -> None:
    """Signed pack, control, condition, and contracts survive exact parsing."""
    expected = pack()
    serialised = expected.to_dict()
    assert serialised["schema_version"] == PACK_SCHEMA_VERSION
    assert serialised["signature_domain"] == STANDARD_PACK_SIGNATURE_DOMAIN
    assert expected.signature.schema_version == PACK_SIGNATURE_SCHEMA_VERSION
    assert expected.signature.signature_domain == STANDARD_PACK_SIGNATURE_DOMAIN
    assert expected.controls[0].to_dict()["schema_version"] == (PACK_COMPONENT_SCHEMA_VERSION)
    assert expected.signature.payload_digest == StandardPack.payload_digest(
        pack_id=expected.pack_id,
        version=expected.version,
        source_uri=expected.source_uri,
        source_digest=expected.source_digest,
        licence=expected.licence,
        controls=expected.controls,
    )
    assert StandardPack.from_dict(serialised) == expected
    assert ControlDefinition.from_dict(expected.controls[0].to_dict()) == expected.controls[0]
    assert EvidenceContract.from_dict(expected.controls[0].evidence.to_dict()) == (
        expected.controls[0].evidence
    )
    assert RemediationContract.from_dict(expected.controls[0].remediation.to_dict()) == (
        expected.controls[0].remediation
    )


def test_tampering_and_unbound_signature_fail_closed() -> None:
    """Changing nested content or supplying a signature for another payload is rejected."""
    expected = pack()
    tampered = deepcopy(expected.to_dict())
    tampered["licence"] = "Apache-2.0"
    with pytest.raises(ValueError, match="signature"):
        StandardPack.from_dict(tampered)
    with pytest.raises(ValueError, match="signature"):
        StandardPack.build(
            pack_id=expected.pack_id,
            version=expected.version,
            source_uri=expected.source_uri,
            source_digest=expected.source_digest,
            licence=expected.licence,
            signature=pack_signature("0" * 64, "standards-key-1"),
            controls=expected.controls,
        )


def test_pack_namespace_and_contract_completeness_are_mandatory() -> None:
    """Controls cannot escape their pack namespace or omit evidence/acceptance clauses."""
    foreign = control(control_id="foreign/no-godfiles")
    payload = StandardPack.payload_digest
    with pytest.raises(ValueError, match="namespace"):
        payload(
            pack_id="core",
            version="1.0.0",
            source_uri="https://standards.example/core",
            source_digest=SOURCE_DIGEST,
            licence="MIT",
            controls=(foreign,),
        )
    with pytest.raises(ValueError, match="at least 1"):
        EvidenceContract.build(
            contract_id="empty",
            required_adapters=(),
            evidence_types=("report",),
            freshness_seconds=1,
            minimum_independent_reviewers=1,
        )
    with pytest.raises(ValueError, match="at least 1"):
        RemediationContract.build(
            dependencies=(),
            procedure_ids=(),
            acceptance_gates=(),
            reopen_triggers=("changed",),
            independent_verifier_required=True,
        )


def test_nested_pack_schemas_and_digests_fail_closed() -> None:
    """Every nested contract, control, and pack envelope checks schema and content digest."""
    expected = pack()
    evidence = expected.controls[0].evidence
    remediation = expected.controls[0].remediation
    cases: list[tuple[object, object, str]] = []
    evidence_schema = deepcopy(evidence.to_dict())
    evidence_schema["schema_version"] = "9.0"
    cases.append((EvidenceContract.from_dict, evidence_schema, "schema"))
    evidence_digest = deepcopy(evidence.to_dict())
    evidence_digest["contract_digest"] = "0" * 64
    cases.append((EvidenceContract.from_dict, evidence_digest, "digest"))
    remediation_schema = deepcopy(remediation.to_dict())
    remediation_schema["schema_version"] = "9.0"
    cases.append((RemediationContract.from_dict, remediation_schema, "schema"))
    remediation_digest = deepcopy(remediation.to_dict())
    remediation_digest["contract_digest"] = "0" * 64
    cases.append((RemediationContract.from_dict, remediation_digest, "digest"))
    control_schema = deepcopy(expected.controls[0].to_dict())
    control_schema["schema_version"] = "9.0"
    cases.append((ControlDefinition.from_dict, control_schema, "schema"))
    control_digest = deepcopy(expected.controls[0].to_dict())
    control_digest["control_digest"] = "0" * 64
    cases.append((ControlDefinition.from_dict, control_digest, "control digest"))
    pack_schema = deepcopy(expected.to_dict())
    pack_schema["schema_version"] = "9.0"
    cases.append((StandardPack.from_dict, pack_schema, "schema"))
    pack_fields = deepcopy(expected.to_dict())
    pack_fields.pop("signature_domain")
    cases.append((StandardPack.from_dict, pack_fields, "fields"))
    pack_domain = deepcopy(expected.to_dict())
    pack_domain["signature_domain"] = "rigor-foundry.reviewer-attestation.v1"
    cases.append((StandardPack.from_dict, pack_domain, "signature domain"))
    pack_array = deepcopy(expected.to_dict())
    pack_array["controls"] = "all"
    cases.append((StandardPack.from_dict, pack_array, "array"))
    pack_digest = deepcopy(expected.to_dict())
    pack_digest["pack_digest"] = "0" * 64
    cases.append((StandardPack.from_dict, pack_digest, "pack digest"))
    for parser, value, message in cases:
        with pytest.raises(ValueError, match=message):
            parser(value)


def test_control_and_pack_validation_rejects_unsupported_or_ambiguous_inputs() -> None:
    """Unsupported maturity/severity/domain/mode and ambiguous pack payloads are rejected."""
    expected = pack()
    item = expected.controls[0]
    base = {
        "control_id": item.control_id,
        "version": item.version,
        "title": item.title,
        "domain": item.domain,
        "severity": item.severity,
        "target_level": item.target_level,
        "mode": item.mode,
        "default_applicable": item.default_applicable,
        "condition": item.condition,
        "evidence": item.evidence,
        "remediation": item.remediation,
    }
    for change, message in (
        ({"target_level": "ultimate"}, "target_level"),
        ({"severity": "P9"}, "severity"),
        ({"domain": "architecture"}, "domain"),
        ({"mode": "allow"}, "mode"),
    ):
        with pytest.raises(ValueError, match=message):
            ControlDefinition.build(**{**base, **change})
    with pytest.raises(ValueError, match="must not be empty"):
        StandardPack.payload_digest(
            pack_id="core",
            version="1.0.0",
            source_uri="https://standards.example/core",
            source_digest=SOURCE_DIGEST,
            licence="MIT",
            controls=(),
        )
    with pytest.raises(ValueError, match="unique"):
        StandardPack.payload_digest(
            pack_id="core",
            version="1.0.0",
            source_uri="https://standards.example/core",
            source_digest=SOURCE_DIGEST,
            licence="MIT",
            controls=(item, item),
        )
    with pytest.raises(ValueError, match="whitespace"):
        StandardPack.payload_digest(
            pack_id="core",
            version="1.0.0",
            source_uri="https://standards.example/core latest",
            source_digest=SOURCE_DIGEST,
            licence="MIT",
            controls=(item,),
        )
