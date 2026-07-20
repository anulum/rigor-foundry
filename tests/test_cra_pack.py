# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA StandardPack tests
"""Verify fixed mapping identity, real signatures, CLI, and honest gaps."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from signing_fixtures import private_key, trust_store

from rigor_foundry.cli import main
from rigor_foundry.compliance_maps import builtin_template
from rigor_foundry.control_assessment import ControlAssessment
from rigor_foundry.cra_pack import (
    CRA_PACK_ID,
    build_cra_pack,
    cra_controls,
    cra_pack_payload_digest,
    cra_source_digest,
)
from rigor_foundry.cra_policy import CraPolicy
from rigor_foundry.effective_profile import (
    AdapterLock,
    EffectiveControl,
    EffectiveProfileLock,
    PackVerification,
)
from rigor_foundry.project_profile import (
    REQUIRED_INTENT_CATEGORIES,
    PackSelection,
    ProjectIntent,
    ProjectProfile,
    RequirementBinding,
    RequirementCategory,
)
from rigor_foundry.standard_pack import PackSignature, StandardPack
from rigor_foundry.trust import STANDARD_PACK_SIGNATURE_DOMAIN, ed25519_signature_message


def signature(key_id: str = "cra-pack-test") -> PackSignature:
    """Sign the exact fixed mapping with a real test-only Ed25519 key."""
    payload = cra_pack_payload_digest()
    return PackSignature.build(
        key_id=key_id,
        payload_digest=payload,
        signature_hex=private_key(key_id)
        .sign(
            ed25519_signature_message(
                signature_domain=STANDARD_PACK_SIGNATURE_DOMAIN,
                payload_digest=payload,
            )
        )
        .hex(),
    )


def test_cra_pack_is_fixed_signed_and_control_assessment_ready() -> None:
    """Every named CRA provision has one evidence-bound signed control."""
    controls = cra_controls()
    assert len(controls) == 9
    assert len({item.versioned_id for item in controls}) == len(controls)
    assert {item.control_id.rsplit("/", 1)[1] for item in controls} == {
        "annex-I-part-I-2-a",
        "annex-I-part-II-1",
        "annex-I-part-II-2",
        "annex-I-part-II-3",
        "annex-I-part-II-4",
        "annex-I-part-II-5",
        "annex-I-part-II-6",
        "annex-I-part-II-7-8",
        "article-14",
    }
    pack = build_cra_pack(signature())
    assert pack.pack_id == CRA_PACK_ID
    assert pack.signature.payload_digest == cra_pack_payload_digest()
    assert StandardPack.from_dict(pack.to_dict()) == pack
    assert len(cra_source_digest()) == 64
    with pytest.raises(ValueError, match="bind"):
        build_cra_pack(
            PackSignature.build(
                key_id="wrong",
                payload_digest="0" * 64,
                signature_hex="0" * 128,
            )
        )


def test_cra_compliance_map_has_supporting_partial_and_explicit_gaps() -> None:
    """The legal crosswalk never converts unsupported domains into coverage."""
    template = builtin_template("eu-cra-2024-2847")
    relations = {
        reference.relation for mapping in template.mappings for reference in mapping.references
    }
    assert {"supporting", "partial"}.issubset(relations)
    assert template.mapping_for("godfile-responsibility").supported is False
    assert template.mapping_for("api-abi-schema-compatibility").unsupported_reason
    assert "not a certification" in template.non_certification_notice


def test_cra_control_enters_assessment_as_needs_evidence_not_a_verdict() -> None:
    """A CRA control uses the ordinary lock/assessment path and cannot self-pass."""
    pack = build_cra_pack(signature())
    requirements = tuple(
        RequirementBinding.build(cast(RequirementCategory, category), ("explicit",))
        for category in sorted(REQUIRED_INTENT_CATEGORIES)
    )
    intent = ProjectIntent.build(
        risk_class="production",
        regulatory_classes=("eu-cra-2024-2847",),
        target_maturity="production",
        requirements=requirements,
    )
    profile = ProjectProfile.build(
        profile_id="cra-widget",
        intent=intent,
        packs=(
            PackSelection.build(
                pack_id=pack.pack_id,
                version=pack.version,
                source_digest=pack.source_digest,
                pack_digest=pack.pack_digest,
                trusted_key_ids=(pack.signature.key_id,),
            ),
        ),
        variables=(),
        assignments=(),
        applicability=(),
        overlays=(),
        waivers=(),
        created_by="owner",
        created_at="2026-07-20T10:00:00Z",
    )
    verification = PackVerification.build(
        pack=pack,
        trust_store=trust_store("cra-pack-test"),
        verified_at="2026-07-20T10:00:00Z",
    )
    adapter = AdapterLock.build(
        adapter_id="rigor-scan",
        version="1.17.0",
        executable_digest="1" * 64,
        config_digest="2" * 64,
        command_digest="3" * 64,
        environment_digest="4" * 64,
        domains=("application-security",),
    )
    effective = EffectiveControl.build(
        source_pack=pack,
        control=pack.controls[0],
        applicable=True,
        applicability_rationale="explicit CRA policy",
        target_level="production",
        mode="require",
        active_waiver_ids=(),
        missing_adapter_ids=(),
    )
    lock = EffectiveProfileLock.build(
        profile=profile,
        packs=(pack,),
        verifications=(verification,),
        adapters=(adapter,),
        variables=(),
        controls=(effective,),
        warnings=(),
        trust_store=trust_store("cra-pack-test"),
        toolchain_digest="5" * 64,
        resolved_at="2026-07-20T10:00:00Z",
        cra_policy=CraPolicy.build(
            applicability="required",
            rationale="explicit CRA policy",
            product_key="widget",
            disclosure_policy_path="SECURITY.md",
            state_evidence_id="cra-state",
        ),
    )
    assessment = ControlAssessment.build(
        lock,
        effective,
        status="needs-evidence",
        assessor="operator",
        assessed_at="2026-07-20T10:00:00Z",
        rationale="No independently reviewed evidence has been supplied.",
    )
    assert assessment.status == "needs-evidence"
    assert assessment.control_id.endswith("annex-I-part-I-2-a@1.0.0")


def test_cra_pack_cli_uses_external_key_and_never_overwrites(tmp_path: Path) -> None:
    """The real CLI signs with a bounded caller key and create-only output."""
    key_path = tmp_path / "pack-key.pem"
    key_path.write_bytes(
        private_key("cli-cra-pack").private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    output = tmp_path / "cra-pack.json"
    argv = [
        "cra-pack",
        "--out",
        str(output),
        "--signing-key",
        str(key_path),
        "--key-id",
        "cli-cra-pack",
    ]
    assert main(argv) == 0
    pack = StandardPack.from_dict(json.loads(output.read_text(encoding="utf-8")))
    assert pack.signature.key_id == "cli-cra-pack"
    assert main(argv) == 2


def test_cra_pack_cli_rejects_wrong_or_encrypted_key_types(tmp_path: Path) -> None:
    """Only stable unencrypted Ed25519 PEM material is accepted."""
    invalid = tmp_path / "invalid.pem"
    invalid.write_text("not a key\n", encoding="utf-8")
    invalid.chmod(0o600)
    argv = [
        "cra-pack",
        "--out",
        str(tmp_path / "out.json"),
        "--signing-key",
        str(invalid),
        "--key-id",
        "key",
    ]
    assert main(argv) == 2
    invalid.write_bytes(
        rsa.generate_private_key(public_exponent=65_537, key_size=2048).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    assert main(argv) == 2


def test_cra_pack_cli_rejects_exposed_private_key_permissions(tmp_path: Path) -> None:
    """A POSIX signing key cannot be readable or writable by group or other users."""
    key_path = tmp_path / "exposed.pem"
    key_path.write_bytes(
        private_key("exposed-cra-pack").private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o644)
    assert (
        main(
            [
                "cra-pack",
                "--out",
                str(tmp_path / "out.json"),
                "--signing-key",
                str(key_path),
                "--key-id",
                "exposed-cra-pack",
            ]
        )
        == 2
    )


def test_cra_pack_cli_rejects_key_identity_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pathname identity change around the stable key read aborts signing."""
    key_path = tmp_path / "changing.pem"
    key_path.write_bytes(
        private_key("changing-cra-pack").private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    decoy = tmp_path / "decoy.pem"
    decoy.write_bytes(key_path.read_bytes())
    decoy.chmod(0o600)
    absolute = key_path.absolute()
    real_stat = Path.stat
    observations = 0

    def changed_second_stat(
        path: Path,
        *,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal observations
        if path == absolute:
            observations += 1
            if observations == 2:
                return real_stat(decoy, follow_symlinks=follow_symlinks)
        return real_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", changed_second_stat)
    assert (
        main(
            [
                "cra-pack",
                "--out",
                str(tmp_path / "out.json"),
                "--signing-key",
                str(key_path),
                "--key-id",
                "changing-cra-pack",
            ]
        )
        == 2
    )
    assert observations == 2
