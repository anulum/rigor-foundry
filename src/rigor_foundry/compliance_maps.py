# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — compliance evidence-map templates
"""Relate audit-domain evidence to named external controls without claiming compliance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .model_primitives import require_identifier, require_semantic_version
from .models import AUDIT_DOMAINS, canonical_digest, require_mapping, require_string

COMPLIANCE_MAP_SCHEMA_VERSION = "1.0"

NON_CERTIFICATION_NOTICE = (
    "RigorFoundry evidence maps relate static audit-domain evidence to named "
    "external control identifiers for triage only. They are not a certification, "
    "an attestation, or a claim of compliance with any standard."
)

MappingRelation = Literal["supporting", "partial", "context"]
_RELATIONS: frozenset[str] = frozenset({"supporting", "partial", "context"})
_AUDIT_DOMAIN_ORDER: dict[str, int] = {domain: index for index, domain in enumerate(AUDIT_DOMAINS)}


def _require_https_url(value: object, field: str) -> str:
    """Return one non-empty ``https`` source-of-record URL."""
    text = require_string(value, field)
    if not text.startswith("https://"):
        raise ValueError(f"{field} must be an https URL")
    return text


def _require_relation(value: object, field: str) -> MappingRelation:
    """Return one supported evidence-to-control relation."""
    text = require_string(value, field)
    if text not in _RELATIONS:
        raise ValueError(f"{field} must be one of supporting, partial, context")
    return cast(MappingRelation, text)


@dataclass(frozen=True)
class ComplianceStandard:
    """Identity and source of record for one external control standard.

    Parameters
    ----------
    standard_id:
        Portable identifier for the standard edition.
    title:
        Neutral standard title.
    version:
        Published edition or revision label named at source.
    publisher:
        Standards body that maintains the edition.
    licence:
        Licence or usage terms of the source standard.
    source_url:
        ``https`` source-of-record URL verified at authoring time.

    """

    standard_id: str
    title: str
    version: str
    publisher: str
    licence: str
    source_url: str
    standard_digest: str

    @classmethod
    def build(
        cls,
        *,
        standard_id: str,
        title: str,
        version: str,
        publisher: str,
        licence: str,
        source_url: str,
    ) -> ComplianceStandard:
        """Build one validated, content-addressed standard descriptor."""
        fields: dict[str, object] = {
            "standard_id": require_identifier(standard_id, "standard.standard_id"),
            "title": require_string(title, "standard.title"),
            "version": require_string(version, "standard.version"),
            "publisher": require_string(publisher, "standard.publisher"),
            "licence": require_string(licence, "standard.licence"),
            "source_url": _require_https_url(source_url, "standard.source_url"),
        }
        return cls(
            standard_id=cast(str, fields["standard_id"]),
            title=cast(str, fields["title"]),
            version=cast(str, fields["version"]),
            publisher=cast(str, fields["publisher"]),
            licence=cast(str, fields["licence"]),
            source_url=cast(str, fields["source_url"]),
            standard_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one standard descriptor."""
        return {
            "standard_id": self.standard_id,
            "title": self.title,
            "version": self.version,
            "publisher": self.publisher,
            "licence": self.licence,
            "source_url": self.source_url,
            "standard_digest": self.standard_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ComplianceStandard:
        """Parse and integrity-check one standard descriptor."""
        data = require_mapping(value, "standard")
        standard = cls.build(
            standard_id=require_string(data.get("standard_id"), "standard.standard_id"),
            title=require_string(data.get("title"), "standard.title"),
            version=require_string(data.get("version"), "standard.version"),
            publisher=require_string(data.get("publisher"), "standard.publisher"),
            licence=require_string(data.get("licence"), "standard.licence"),
            source_url=require_string(data.get("source_url"), "standard.source_url"),
        )
        if data.get("standard_digest") != standard.standard_digest:
            raise ValueError("standard digest does not match its content")
        return standard


@dataclass(frozen=True)
class ControlReference:
    """One external control identifier and its relation to domain evidence.

    Parameters
    ----------
    reference:
        Opaque external control identifier such as ``A.8.28`` or ``CC7.1``.
    relation:
        Honest strength of the evidence-to-control relation.
    rationale:
        Neutral, original description of why the domain evidence is relevant.

    """

    reference: str
    relation: MappingRelation
    rationale: str

    @classmethod
    def build(cls, *, reference: str, relation: str, rationale: str) -> ControlReference:
        """Build one validated control reference."""
        return cls(
            reference=require_identifier(reference, "reference.reference"),
            relation=_require_relation(relation, "reference.relation"),
            rationale=require_string(rationale, "reference.rationale"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one control reference."""
        return {
            "reference": self.reference,
            "relation": self.relation,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, value: object) -> ControlReference:
        """Parse one control reference."""
        data = require_mapping(value, "reference")
        return cls.build(
            reference=require_string(data.get("reference"), "reference.reference"),
            relation=require_string(data.get("relation"), "reference.relation"),
            rationale=require_string(data.get("rationale"), "reference.rationale"),
        )


@dataclass(frozen=True)
class DomainMapping:
    """Mapping of one RigorFoundry audit domain to external control references.

    A domain either binds one or more control references or declares an explicit
    unsupported gap; a silent gap is never permitted.

    Parameters
    ----------
    rigor_domain:
        Mandatory audit domain from :data:`AUDIT_DOMAINS`.
    references:
        Control references relevant to the domain, empty for an unsupported gap.
    unsupported_reason:
        Non-empty explanation required when and only when ``references`` is empty.

    """

    rigor_domain: str
    references: tuple[ControlReference, ...]
    unsupported_reason: str

    @classmethod
    def build(
        cls,
        *,
        rigor_domain: str,
        references: tuple[ControlReference, ...] = (),
        unsupported_reason: str = "",
    ) -> DomainMapping:
        """Build one validated domain mapping with an explicit coverage decision."""
        if rigor_domain not in _AUDIT_DOMAIN_ORDER:
            raise ValueError("mapping.rigor_domain is not a mandatory audit domain")
        identifiers = tuple(item.reference for item in references)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("mapping references must have unique identifiers")
        if references:
            if unsupported_reason.strip():
                raise ValueError("mapped domains must not also declare an unsupported reason")
            reason = ""
        else:
            reason = require_string(unsupported_reason, "mapping.unsupported_reason")
        return cls(
            rigor_domain=rigor_domain,
            references=references,
            unsupported_reason=reason,
        )

    @property
    def supported(self) -> bool:
        """Return whether the domain binds at least one control reference."""
        return bool(self.references)

    def to_dict(self) -> dict[str, object]:
        """Serialise one domain mapping."""
        return {
            "rigor_domain": self.rigor_domain,
            "references": [item.to_dict() for item in self.references],
            "unsupported_reason": self.unsupported_reason,
        }

    @classmethod
    def from_dict(cls, value: object) -> DomainMapping:
        """Parse one domain mapping."""
        data = require_mapping(value, "mapping")
        raw = data.get("references")
        if not isinstance(raw, list):
            raise ValueError("mapping.references must be an array")
        references = tuple(ControlReference.from_dict(item) for item in cast(list[object], raw))
        return cls.build(
            rigor_domain=require_string(data.get("rigor_domain"), "mapping.rigor_domain"),
            references=references,
            unsupported_reason=require_string(
                data.get("unsupported_reason", ""),
                "mapping.unsupported_reason",
                allow_empty=True,
            ),
        )


@dataclass(frozen=True)
class ComplianceMapTemplate:
    """Complete evidence-map template covering every audit domain exactly once.

    Parameters
    ----------
    template_id:
        Portable identifier for the template.
    template_version:
        Semantic version of the template content.
    standard:
        External standard the template references.
    mappings:
        One :class:`DomainMapping` per mandatory audit domain, in registry order.

    """

    template_id: str
    template_version: str
    standard: ComplianceStandard
    mappings: tuple[DomainMapping, ...]
    non_certification_notice: str
    template_digest: str

    @classmethod
    def build(
        cls,
        *,
        template_id: str,
        template_version: str,
        standard: ComplianceStandard,
        mappings: tuple[DomainMapping, ...],
    ) -> ComplianceMapTemplate:
        """Build one validated template with total, non-duplicated domain coverage."""
        domains = tuple(mapping.rigor_domain for mapping in mappings)
        if set(domains) != set(AUDIT_DOMAINS) or len(domains) != len(AUDIT_DOMAINS):
            raise ValueError("template mappings must cover every audit domain exactly once")
        ordered = tuple(
            sorted(mappings, key=lambda mapping: _AUDIT_DOMAIN_ORDER[mapping.rigor_domain])
        )
        fields: dict[str, object] = {
            "schema_version": COMPLIANCE_MAP_SCHEMA_VERSION,
            "template_id": require_identifier(template_id, "template.template_id"),
            "template_version": require_semantic_version(
                template_version,
                "template.template_version",
            ),
            "standard": standard.to_dict(),
            "mappings": [mapping.to_dict() for mapping in ordered],
            "non_certification_notice": NON_CERTIFICATION_NOTICE,
        }
        return cls(
            template_id=cast(str, fields["template_id"]),
            template_version=cast(str, fields["template_version"]),
            standard=standard,
            mappings=ordered,
            non_certification_notice=NON_CERTIFICATION_NOTICE,
            template_digest=canonical_digest(fields),
        )

    def mapping_for(self, rigor_domain: str) -> DomainMapping:
        """Return the domain mapping for one audit domain."""
        for mapping in self.mappings:
            if mapping.rigor_domain == rigor_domain:
                return mapping
        raise KeyError(rigor_domain)

    def to_dict(self) -> dict[str, object]:
        """Serialise one complete template."""
        return {
            "schema_version": COMPLIANCE_MAP_SCHEMA_VERSION,
            "template_id": self.template_id,
            "template_version": self.template_version,
            "standard": self.standard.to_dict(),
            "mappings": [mapping.to_dict() for mapping in self.mappings],
            "non_certification_notice": self.non_certification_notice,
            "template_digest": self.template_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ComplianceMapTemplate:
        """Parse and integrity-check one complete template."""
        data = require_mapping(value, "template")
        if data.get("schema_version") != COMPLIANCE_MAP_SCHEMA_VERSION:
            raise ValueError("unsupported compliance-map schema version")
        if data.get("non_certification_notice") != NON_CERTIFICATION_NOTICE:
            raise ValueError("template must carry the exact non-certification notice")
        raw = data.get("mappings")
        if not isinstance(raw, list):
            raise ValueError("template.mappings must be an array")
        template = cls.build(
            template_id=require_string(data.get("template_id"), "template.template_id"),
            template_version=require_string(
                data.get("template_version"),
                "template.template_version",
            ),
            standard=ComplianceStandard.from_dict(data.get("standard")),
            mappings=tuple(DomainMapping.from_dict(item) for item in cast(list[object], raw)),
        )
        if data.get("template_digest") != template.template_digest:
            raise ValueError("template digest does not match its content")
        return template


def _mapping(rigor_domain: str, *references: tuple[str, str, str]) -> DomainMapping:
    """Build a supported domain mapping from compact reference tuples."""
    return DomainMapping.build(
        rigor_domain=rigor_domain,
        references=tuple(
            ControlReference.build(reference=reference, relation=relation, rationale=rationale)
            for reference, relation, rationale in references
        ),
    )


def _gap(rigor_domain: str, unsupported_reason: str) -> DomainMapping:
    """Build an explicitly unsupported domain mapping."""
    return DomainMapping.build(rigor_domain=rigor_domain, unsupported_reason=unsupported_reason)


_ISO_27001_STANDARD = ComplianceStandard.build(
    standard_id="iso-iec-27001-2022",
    title="ISO/IEC 27001 Information security management systems — Requirements",
    version="2022 (including Amendment 1:2024, climate action)",
    publisher="ISO/IEC",
    licence="ISO/IEC copyright; control text not reproduced, identifiers referenced only",
    source_url="https://www.iso.org/standard/27001",
)

_ISO_27001_TEMPLATE = ComplianceMapTemplate.build(
    template_id="iso-iec-27001-2022",
    template_version="1.0.0",
    standard=_ISO_27001_STANDARD,
    mappings=(
        _mapping(
            "test-authenticity",
            (
                "A.8.29",
                "supporting",
                "Evidence that tests exercise real boundaries supports security testing in development and acceptance.",
            ),
            (
                "A.8.25",
                "partial",
                "Authentic test evidence is one input to a secure development life cycle.",
            ),
        ),
        _mapping(
            "architecture-and-wiring",
            (
                "A.8.27",
                "supporting",
                "Wiring and boundary evidence supports secure system architecture and engineering principles.",
            ),
        ),
        _mapping(
            "godfile-responsibility",
            (
                "A.8.27",
                "partial",
                "Single-responsibility evidence is one signal of sound engineering structure.",
            ),
            (
                "A.8.28",
                "partial",
                "Bounded module responsibility reduces the surface governed by secure coding.",
            ),
        ),
        _mapping(
            "application-security",
            (
                "A.8.28",
                "supporting",
                "Static application-security signals support secure coding control objectives.",
            ),
            (
                "A.8.25",
                "supporting",
                "Application-security evidence supports the secure development life cycle.",
            ),
            ("A.8.26", "partial", "Findings inform application security requirements review."),
        ),
        _mapping(
            "supply-chain",
            (
                "A.5.21",
                "supporting",
                "Dependency and provenance evidence supports managing information security in the ICT supply chain.",
            ),
            (
                "A.8.30",
                "partial",
                "Provenance evidence is one input to overseeing outsourced development.",
            ),
        ),
        _mapping(
            "api-abi-schema-compatibility",
            (
                "A.8.26",
                "partial",
                "Interface and schema compatibility evidence informs application security requirements.",
            ),
        ),
        _gap(
            "scientific-numerical-correctness",
            "ISO/IEC 27001 is an information-security management standard and does not define a control for numerical or scientific correctness.",
        ),
        _mapping(
            "reliability-and-concurrency",
            (
                "A.5.30",
                "context",
                "Reliability and concurrency evidence is contextual input to ICT readiness for business continuity.",
            ),
        ),
        _mapping(
            "performance-and-reproducibility",
            (
                "A.8.6",
                "context",
                "Performance and reproducibility evidence is contextual input to capacity management.",
            ),
        ),
        _mapping(
            "data-and-privacy",
            (
                "A.5.34",
                "supporting",
                "Data and privacy handling evidence supports privacy and protection of personally identifiable information.",
            ),
            ("A.8.11", "partial", "Data-handling evidence informs data masking controls."),
            (
                "A.8.12",
                "partial",
                "Data-handling evidence informs data leakage prevention controls.",
            ),
        ),
        _mapping(
            "operations-and-observability",
            ("A.8.15", "supporting", "Logging evidence supports the logging control objective."),
            ("A.8.16", "supporting", "Observability evidence supports monitoring activities."),
        ),
        _mapping(
            "packaging-deployment-iac",
            (
                "A.8.9",
                "supporting",
                "Packaging and infrastructure-as-code evidence supports configuration management.",
            ),
            (
                "A.8.19",
                "partial",
                "Deployment evidence informs installation of software on operational systems.",
            ),
            ("A.8.32", "partial", "Deployment change evidence informs change management."),
        ),
        _mapping(
            "documentation-claims-ip",
            (
                "A.5.32",
                "partial",
                "Documentation and claims evidence informs intellectual property rights obligations.",
            ),
        ),
        _mapping(
            "ownership-and-maintenance",
            (
                "A.5.2",
                "context",
                "Ownership evidence is contextual input to information security roles and responsibilities.",
            ),
            ("A.8.32", "partial", "Maintenance evidence informs change management."),
        ),
    ),
)


_SOC2_STANDARD = ComplianceStandard.build(
    standard_id="aicpa-tsc-2017",
    title="AICPA Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy",
    version="2017 (with revised points of focus, 2022)",
    publisher="AICPA Assurance Services Executive Committee",
    licence="AICPA copyright; criteria text not reproduced, identifiers referenced only",
    source_url="https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
)

_SOC2_TEMPLATE = ComplianceMapTemplate.build(
    template_id="aicpa-tsc-2017",
    template_version="1.0.0",
    standard=_SOC2_STANDARD,
    mappings=(
        _mapping(
            "test-authenticity",
            (
                "CC8.1",
                "supporting",
                "Authentic test evidence supports authorising, designing, developing, and testing changes.",
            ),
        ),
        _mapping(
            "architecture-and-wiring",
            (
                "CC8.1",
                "partial",
                "Architecture and wiring evidence informs change design and development.",
            ),
        ),
        _mapping(
            "godfile-responsibility",
            (
                "CC8.1",
                "context",
                "Module responsibility evidence is contextual input to sound change development.",
            ),
        ),
        _mapping(
            "application-security",
            (
                "CC8.1",
                "supporting",
                "Application-security evidence supports secure change development and testing.",
            ),
            (
                "CC7.1",
                "partial",
                "Static findings inform detection of configuration and vulnerability changes.",
            ),
        ),
        _mapping(
            "supply-chain",
            (
                "CC9.2",
                "partial",
                "Dependency and provenance evidence informs vendor and business-partner risk management.",
            ),
        ),
        _mapping(
            "api-abi-schema-compatibility",
            (
                "CC8.1",
                "partial",
                "Interface and schema compatibility evidence informs change management.",
            ),
        ),
        _gap(
            "scientific-numerical-correctness",
            "The Trust Services Criteria do not define a control for numerical or scientific correctness; RigorFoundry static evidence does not attest processing-integrity outcomes.",
        ),
        _mapping(
            "reliability-and-concurrency",
            (
                "A1.1",
                "context",
                "Reliability and concurrency evidence is contextual input to availability capacity objectives.",
            ),
        ),
        _mapping(
            "performance-and-reproducibility",
            (
                "A1.1",
                "context",
                "Performance and reproducibility evidence is contextual input to availability capacity objectives.",
            ),
        ),
        _mapping(
            "data-and-privacy",
            (
                "C1.1",
                "partial",
                "Data and privacy handling evidence informs identifying and maintaining confidential information.",
            ),
            (
                "C1.2",
                "context",
                "Data-handling evidence is contextual input to disposing of confidential information.",
            ),
        ),
        _mapping(
            "operations-and-observability",
            (
                "CC7.2",
                "supporting",
                "Observability evidence supports monitoring system components for anomalies.",
            ),
            ("CC7.3", "partial", "Event evidence informs evaluation of security events."),
        ),
        _mapping(
            "packaging-deployment-iac",
            (
                "CC8.1",
                "supporting",
                "Packaging and deployment evidence supports change management.",
            ),
        ),
        _gap(
            "documentation-claims-ip",
            "The Trust Services Criteria do not define an intellectual-property control; documentation and IP claims are out of the SOC 2 common-criteria scope.",
        ),
        _mapping(
            "ownership-and-maintenance",
            (
                "CC1.3",
                "context",
                "Ownership evidence is contextual input to establishing structures, reporting lines, and authorities.",
            ),
            ("CC8.1", "partial", "Maintenance evidence informs change management."),
        ),
    ),
)


_BUILTIN_TEMPLATES: dict[str, ComplianceMapTemplate] = {
    template.template_id: template for template in (_ISO_27001_TEMPLATE, _SOC2_TEMPLATE)
}


def builtin_template_ids() -> tuple[str, ...]:
    """Return the sorted identifiers of the built-in evidence-map templates."""
    return tuple(sorted(_BUILTIN_TEMPLATES))


def builtin_template(template_id: str) -> ComplianceMapTemplate:
    """Return one built-in evidence-map template by identifier."""
    try:
        return _BUILTIN_TEMPLATES[template_id]
    except KeyError as exc:
        raise ValueError(f"unknown compliance-map template: {template_id}") from exc


def builtin_templates() -> tuple[ComplianceMapTemplate, ...]:
    """Return every built-in template in stable identifier order."""
    return tuple(_BUILTIN_TEMPLATES[identifier] for identifier in builtin_template_ids())
