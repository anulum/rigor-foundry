# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — compliance evidence-map template tests
"""Verify evidence-map templates cover every domain without claiming compliance."""

from __future__ import annotations

import pytest

from rigor_foundry.compliance_maps import (
    NON_CERTIFICATION_NOTICE,
    ComplianceMapTemplate,
    ComplianceStandard,
    ControlReference,
    DomainMapping,
    builtin_template,
    builtin_template_ids,
    builtin_templates,
)
from rigor_foundry.models import AUDIT_DOMAINS


def standard() -> ComplianceStandard:
    """Return one valid standard descriptor."""
    return ComplianceStandard.build(
        standard_id="demo-standard-1",
        title="Demo Standard",
        version="2026",
        publisher="Demo Body",
        licence="demo licence",
        source_url="https://standards.example/demo",
    )


def full_mappings() -> tuple[DomainMapping, ...]:
    """Return one mapping per audit domain, mixing supported and gap decisions."""
    mappings: list[DomainMapping] = []
    for index, domain in enumerate(AUDIT_DOMAINS):
        if index == 0:
            mappings.append(
                DomainMapping.build(
                    rigor_domain=domain,
                    unsupported_reason="no external control for this domain",
                )
            )
        else:
            mappings.append(
                DomainMapping.build(
                    rigor_domain=domain,
                    references=(
                        ControlReference.build(
                            reference=f"X.{index}",
                            relation="supporting",
                            rationale="relevant evidence",
                        ),
                    ),
                )
            )
    return tuple(mappings)


def template() -> ComplianceMapTemplate:
    """Return one complete template covering every audit domain."""
    return ComplianceMapTemplate.build(
        template_id="demo-standard-1",
        template_version="1.0.0",
        standard=standard(),
        mappings=full_mappings(),
    )


def test_standard_round_trips_and_rejects_digest_and_scheme() -> None:
    """A standard serialises, round-trips, and rejects tampering and bad URLs."""
    original = standard()
    assert ComplianceStandard.from_dict(original.to_dict()) == original
    tampered = original.to_dict()
    tampered["standard_digest"] = "0" * 64
    with pytest.raises(ValueError, match="standard digest"):
        ComplianceStandard.from_dict(tampered)
    with pytest.raises(ValueError, match="https URL"):
        ComplianceStandard.build(
            standard_id="demo-standard-1",
            title="Demo",
            version="2026",
            publisher="Body",
            licence="licence",
            source_url="http://insecure.example/demo",
        )


def test_control_reference_round_trips_and_validates_relation() -> None:
    """A control reference round-trips and rejects an unknown relation."""
    reference = ControlReference.build(
        reference="A.8.28",
        relation="partial",
        rationale="informs secure coding",
    )
    assert ControlReference.from_dict(reference.to_dict()) == reference
    with pytest.raises(ValueError, match="supporting, partial, context"):
        ControlReference.build(reference="A.8.28", relation="mandatory", rationale="x")


def test_domain_mapping_supported_and_gap_paths() -> None:
    """A domain either binds references or declares an explicit gap, never both."""
    mapped = DomainMapping.build(
        rigor_domain="application-security",
        references=(
            ControlReference.build(reference="A.8.28", relation="supporting", rationale="x"),
        ),
    )
    assert mapped.supported is True
    assert DomainMapping.from_dict(mapped.to_dict()) == mapped

    gap = DomainMapping.build(
        rigor_domain="application-security",
        unsupported_reason="out of scope",
    )
    assert gap.supported is False
    assert DomainMapping.from_dict(gap.to_dict()) == gap


def test_domain_mapping_rejects_invalid_shapes() -> None:
    """Domain, duplicate, both-set, empty-gap, and non-array shapes fail closed."""
    reference = ControlReference.build(reference="A.8.28", relation="supporting", rationale="x")
    with pytest.raises(ValueError, match="mandatory audit domain"):
        DomainMapping.build(rigor_domain="not-a-domain", references=(reference,))
    with pytest.raises(ValueError, match="unique identifiers"):
        DomainMapping.build(rigor_domain="application-security", references=(reference, reference))
    with pytest.raises(ValueError, match="must not also declare"):
        DomainMapping.build(
            rigor_domain="application-security",
            references=(reference,),
            unsupported_reason="conflicting reason",
        )
    with pytest.raises(ValueError, match="non-empty string"):
        DomainMapping.build(rigor_domain="application-security")
    with pytest.raises(ValueError, match="must be an array"):
        DomainMapping.from_dict(
            {"rigor_domain": "application-security", "references": "x", "unsupported_reason": ""}
        )


def test_template_round_trips_and_resolves_domains() -> None:
    """A complete template round-trips and resolves every audit domain."""
    original = template()
    assert ComplianceMapTemplate.from_dict(original.to_dict()) == original
    assert original.non_certification_notice == NON_CERTIFICATION_NOTICE
    for domain in AUDIT_DOMAINS:
        assert original.mapping_for(domain).rigor_domain == domain
    with pytest.raises(KeyError):
        original.mapping_for("not-a-domain")


def test_template_requires_total_unique_domain_coverage() -> None:
    """Missing or duplicated domains are rejected before a template is built."""
    partial = full_mappings()[:-1]
    with pytest.raises(ValueError, match="every audit domain exactly once"):
        ComplianceMapTemplate.build(
            template_id="demo-standard-1",
            template_version="1.0.0",
            standard=standard(),
            mappings=partial,
        )
    duplicated = (*full_mappings(), full_mappings()[1])
    with pytest.raises(ValueError, match="every audit domain exactly once"):
        ComplianceMapTemplate.build(
            template_id="demo-standard-1",
            template_version="1.0.0",
            standard=standard(),
            mappings=duplicated,
        )


def test_template_from_dict_rejects_tampering() -> None:
    """Schema, notice, mappings shape, and digest tampering all fail closed."""
    good = template().to_dict()

    bad_schema = dict(good)
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="schema version"):
        ComplianceMapTemplate.from_dict(bad_schema)

    bad_notice = dict(good)
    bad_notice["non_certification_notice"] = "we are certified"
    with pytest.raises(ValueError, match="non-certification notice"):
        ComplianceMapTemplate.from_dict(bad_notice)

    bad_mappings = dict(good)
    bad_mappings["mappings"] = "not-a-list"
    with pytest.raises(ValueError, match="mappings must be an array"):
        ComplianceMapTemplate.from_dict(bad_mappings)

    bad_digest = dict(good)
    bad_digest["template_digest"] = "0" * 64
    with pytest.raises(ValueError, match="template digest"):
        ComplianceMapTemplate.from_dict(bad_digest)


def test_builtin_templates_are_complete_and_honest() -> None:
    """Both built-in templates cover every domain and name their source editions."""
    assert builtin_template_ids() == ("aicpa-tsc-2017", "iso-iec-27001-2022")
    by_id = {template.template_id: template for template in builtin_templates()}
    for identifier, template_object in by_id.items():
        covered = {mapping.rigor_domain for mapping in template_object.mappings}
        assert covered == set(AUDIT_DOMAINS)
        assert template_object.non_certification_notice == NON_CERTIFICATION_NOTICE
        assert builtin_template(identifier) is template_object

    iso = by_id["iso-iec-27001-2022"]
    assert "2022" in iso.standard.version
    assert iso.standard.source_url.startswith("https://www.iso.org")
    soc2 = by_id["aicpa-tsc-2017"]
    assert "2017" in soc2.standard.version
    assert soc2.mapping_for("documentation-claims-ip").supported is False


def test_builtin_template_rejects_unknown_identifier() -> None:
    """An unknown template identifier fails closed."""
    with pytest.raises(ValueError, match="unknown compliance-map template"):
        builtin_template("nonexistent")
