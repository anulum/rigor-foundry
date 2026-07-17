# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project desired-state profiles
"""Define digest-bound project intent, variables, overlays, and waivers."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal, cast

from .audit_primitives import require_exact_fields
from .model_primitives import (
    JsonScalar,
    VariableAssignment,
    VariableDefinition,
    parse_utc_timestamp,
    require_boolean,
    require_digest,
    require_identifier,
    require_json_scalar,
    require_semantic_version,
    require_unique_strings,
    require_utc_timestamp,
    validate_unique_strings,
)
from .models import canonical_digest, require_mapping, require_string
from .protocol_fields import PROJECT_INTENT_FIELDS, PROJECT_PROFILE_FIELDS
from .standard_pack import ControlMode, TargetLevel, _target_level

PROFILE_SCHEMA_VERSION = "1.0"

RequirementCategory = Literal[
    "topology",
    "deployment-targets",
    "compatibility",
    "trust-boundaries",
    "data-classification",
    "quality-and-performance",
    "reliability-and-operations",
    "packaging-provenance-licence-ip",
    "accessibility",
    "ownership-and-review",
    "prohibited-shortcuts",
]

REQUIRED_INTENT_CATEGORIES: frozenset[str] = frozenset(
    {
        "topology",
        "deployment-targets",
        "compatibility",
        "trust-boundaries",
        "data-classification",
        "quality-and-performance",
        "reliability-and-operations",
        "packaging-provenance-licence-ip",
        "accessibility",
        "ownership-and-review",
        "prohibited-shortcuts",
    }
)


def _object_array(value: object, field: str) -> list[object]:
    """Return one JSON object array without coercion."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return cast(list[object], value)


@dataclass(frozen=True)
class RequirementBinding:
    """One explicit desired-state requirement category."""

    category: RequirementCategory
    requirements: tuple[str, ...]

    @classmethod
    def build(
        cls,
        category: RequirementCategory,
        requirements: tuple[str, ...],
    ) -> RequirementBinding:
        """Build one non-empty requirement category."""
        if category not in REQUIRED_INTENT_CATEGORIES:
            raise ValueError("intent requirement category is unsupported")
        return cls(
            category=category,
            requirements=validate_unique_strings(
                requirements,
                f"intent.{category}",
                minimum=1,
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one requirement category."""
        return {"category": self.category, "requirements": list(self.requirements)}

    @classmethod
    def from_dict(cls, value: object) -> RequirementBinding:
        """Parse one desired-state requirement category."""
        data = require_mapping(value, "intent.requirement")
        category = require_string(data.get("category"), "intent.requirement.category")
        return cls.build(
            cast(RequirementCategory, category),
            require_unique_strings(
                data.get("requirements"),
                "intent.requirement.requirements",
                minimum=1,
            ),
        )


@dataclass(frozen=True)
class ProjectIntent:
    """Explicit project/product target context bound by a profile."""

    risk_class: str
    regulatory_classes: tuple[str, ...]
    target_maturity: TargetLevel
    requirements: tuple[RequirementBinding, ...]
    intent_digest: str

    @classmethod
    def build(
        cls,
        *,
        risk_class: str,
        regulatory_classes: tuple[str, ...],
        target_maturity: TargetLevel,
        requirements: tuple[RequirementBinding, ...],
    ) -> ProjectIntent:
        """Build a complete desired-state context with no omitted category."""
        categories = tuple(item.category for item in requirements)
        if len(categories) != len(set(categories)):
            raise ValueError("intent requirement categories must be unique")
        missing = REQUIRED_INTENT_CATEGORIES.difference(categories)
        if missing:
            raise ValueError("intent is missing categories: " + ", ".join(sorted(missing)))
        fields: dict[str, object] = {
            "schema_version": PROFILE_SCHEMA_VERSION,
            "risk_class": require_string(risk_class, "intent.risk_class"),
            "regulatory_classes": list(
                validate_unique_strings(regulatory_classes, "intent.regulatory_classes")
            ),
            "target_maturity": _target_level(target_maturity, "intent.target_maturity"),
            "requirements": [item.to_dict() for item in requirements],
        }
        return cls(
            risk_class=cast(str, fields["risk_class"]),
            regulatory_classes=tuple(cast(list[str], fields["regulatory_classes"])),
            target_maturity=cast(TargetLevel, fields["target_maturity"]),
            requirements=requirements,
            intent_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete project intent."""
        return {
            "schema_version": PROFILE_SCHEMA_VERSION,
            "risk_class": self.risk_class,
            "regulatory_classes": list(self.regulatory_classes),
            "target_maturity": self.target_maturity,
            "requirements": [item.to_dict() for item in self.requirements],
            "intent_digest": self.intent_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ProjectIntent:
        """Parse and integrity-check one complete project intent."""
        data = require_mapping(value, "intent")
        require_exact_fields(data, PROJECT_INTENT_FIELDS, "project-intent")
        if data.get("schema_version") != PROFILE_SCHEMA_VERSION:
            raise ValueError("unsupported project-intent schema version")
        intent = cls.build(
            risk_class=require_string(data.get("risk_class"), "intent.risk_class"),
            regulatory_classes=require_unique_strings(
                data.get("regulatory_classes"),
                "intent.regulatory_classes",
            ),
            target_maturity=_target_level(
                data.get("target_maturity"),
                "intent.target_maturity",
            ),
            requirements=tuple(
                RequirementBinding.from_dict(item)
                for item in _object_array(data.get("requirements"), "intent.requirements")
            ),
        )
        if data.get("intent_digest") != intent.intent_digest:
            raise ValueError("project-intent digest does not match its content")
        return intent


@dataclass(frozen=True)
class PackSelection:
    """Exact pack source, version, digest, and trusted signing keys."""

    pack_id: str
    version: str
    source_digest: str
    pack_digest: str
    trusted_key_ids: tuple[str, ...]
    selection_digest: str

    @classmethod
    def build(
        cls,
        *,
        pack_id: str,
        version: str,
        source_digest: str,
        pack_digest: str,
        trusted_key_ids: tuple[str, ...],
    ) -> PackSelection:
        """Build one exact pack selection without ranges or latest tags."""
        fields: dict[str, object] = {
            "pack_id": require_identifier(pack_id, "pack_selection.pack_id"),
            "version": require_semantic_version(version, "pack_selection.version"),
            "source_digest": require_digest(
                source_digest,
                "pack_selection.source_digest",
            ),
            "pack_digest": require_digest(pack_digest, "pack_selection.pack_digest"),
            "trusted_key_ids": list(
                validate_unique_strings(
                    trusted_key_ids,
                    "pack_selection.trusted_key_ids",
                    minimum=1,
                )
            ),
        }
        return cls(
            pack_id=cast(str, fields["pack_id"]),
            version=cast(str, fields["version"]),
            source_digest=cast(str, fields["source_digest"]),
            pack_digest=cast(str, fields["pack_digest"]),
            trusted_key_ids=tuple(cast(list[str], fields["trusted_key_ids"])),
            selection_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one exact pack selection."""
        return {
            "pack_id": self.pack_id,
            "version": self.version,
            "source_digest": self.source_digest,
            "pack_digest": self.pack_digest,
            "trusted_key_ids": list(self.trusted_key_ids),
            "selection_digest": self.selection_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> PackSelection:
        """Parse and integrity-check one exact pack selection."""
        data = require_mapping(value, "pack_selection")
        selection = cls.build(
            pack_id=require_identifier(data.get("pack_id"), "pack_selection.pack_id"),
            version=require_semantic_version(
                data.get("version"),
                "pack_selection.version",
            ),
            source_digest=require_digest(
                data.get("source_digest"),
                "pack_selection.source_digest",
            ),
            pack_digest=require_digest(
                data.get("pack_digest"),
                "pack_selection.pack_digest",
            ),
            trusted_key_ids=require_unique_strings(
                data.get("trusted_key_ids"),
                "pack_selection.trusted_key_ids",
                minimum=1,
            ),
        )
        if data.get("selection_digest") != selection.selection_digest:
            raise ValueError("pack-selection digest does not match its content")
        return selection


@dataclass(frozen=True)
class ApplicabilityDecision:
    """Explicit project applicability decision with factual rationale."""

    control_id: str
    applicable: bool
    rationale: str
    decision_digest: str

    @classmethod
    def build(
        cls,
        *,
        control_id: str,
        applicable: bool,
        rationale: str,
    ) -> ApplicabilityDecision:
        """Build one explicit applicability decision."""
        checked_control_id = require_identifier(
            control_id,
            "applicability.control_id",
        )
        checked_applicable = require_boolean(applicable, "applicability.applicable")
        checked_rationale = require_string(rationale, "applicability.rationale")
        fields = {
            "control_id": checked_control_id,
            "applicable": checked_applicable,
            "rationale": checked_rationale,
        }
        return cls(
            control_id=checked_control_id,
            applicable=checked_applicable,
            rationale=checked_rationale,
            decision_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one applicability decision."""
        return asdict(self)

    @classmethod
    def from_dict(cls, value: object) -> ApplicabilityDecision:
        """Parse and integrity-check an applicability decision."""
        data = require_mapping(value, "applicability")
        decision = cls.build(
            control_id=require_identifier(
                data.get("control_id"),
                "applicability.control_id",
            ),
            applicable=require_boolean(data.get("applicable"), "applicability.applicable"),
            rationale=require_string(data.get("rationale"), "applicability.rationale"),
        )
        if data.get("decision_digest") != decision.decision_digest:
            raise ValueError("applicability digest does not match its content")
        return decision


@dataclass(frozen=True)
class ControlOverlay:
    """Project-local control strengthening or deny decision."""

    control_id: str
    target_level: TargetLevel
    mode: ControlMode
    source: str
    overlay_digest: str

    @classmethod
    def build(
        cls,
        *,
        control_id: str,
        target_level: TargetLevel,
        mode: ControlMode,
        source: str,
    ) -> ControlOverlay:
        """Build one project-local policy overlay."""
        if mode not in {"require", "deny"}:
            raise ValueError("overlay.mode is unsupported")
        fields = {
            "control_id": require_identifier(control_id, "overlay.control_id"),
            "target_level": _target_level(target_level, "overlay.target_level"),
            "mode": mode,
            "source": require_string(source, "overlay.source"),
        }
        return cls(
            control_id=fields["control_id"],
            target_level=cast(TargetLevel, fields["target_level"]),
            mode=mode,
            source=fields["source"],
            overlay_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise one project-local overlay."""
        return cast(dict[str, str], asdict(self))

    @classmethod
    def from_dict(cls, value: object) -> ControlOverlay:
        """Parse and integrity-check one project control overlay."""
        data = require_mapping(value, "overlay")
        mode = require_string(data.get("mode"), "overlay.mode")
        overlay = cls.build(
            control_id=require_identifier(data.get("control_id"), "overlay.control_id"),
            target_level=_target_level(data.get("target_level"), "overlay.target_level"),
            mode=cast(ControlMode, mode),
            source=require_string(data.get("source"), "overlay.source"),
        )
        if data.get("overlay_digest") != overlay.overlay_digest:
            raise ValueError("overlay digest does not match its content")
        return overlay


@dataclass(frozen=True)
class ExceptionWaiver:
    """Authorized, evidence-bound, expiring weakening of one control field."""

    waiver_id: str
    control_id: str
    field: str
    from_value: JsonScalar
    to_value: JsonScalar
    owner: str
    authorized_by: str
    rationale: str
    evidence_digest: str
    created_at: str
    expires_at: str
    waiver_digest: str

    @classmethod
    def build(
        cls,
        *,
        waiver_id: str,
        control_id: str,
        field: str,
        from_value: JsonScalar,
        to_value: JsonScalar,
        owner: str,
        authorized_by: str,
        rationale: str,
        evidence_digest: str,
        created_at: str,
        expires_at: str,
    ) -> ExceptionWaiver:
        """Build one authorized weakening with a finite validity window."""
        created = require_utc_timestamp(created_at, "waiver.created_at")
        expires = require_utc_timestamp(expires_at, "waiver.expires_at")
        if parse_utc_timestamp(expires, "waiver.expires_at") <= parse_utc_timestamp(
            created,
            "waiver.created_at",
        ):
            raise ValueError("waiver.expires_at must be later than created_at")
        fields: dict[str, object] = {
            "waiver_id": require_identifier(waiver_id, "waiver.waiver_id"),
            "control_id": require_identifier(control_id, "waiver.control_id"),
            "field": require_identifier(field, "waiver.field"),
            "from_value": require_json_scalar(from_value, "waiver.from_value"),
            "to_value": require_json_scalar(to_value, "waiver.to_value"),
            "owner": require_string(owner, "waiver.owner"),
            "authorized_by": require_string(authorized_by, "waiver.authorized_by"),
            "rationale": require_string(rationale, "waiver.rationale"),
            "evidence_digest": require_digest(evidence_digest, "waiver.evidence_digest"),
            "created_at": created,
            "expires_at": expires,
        }
        return cls(
            waiver_id=cast(str, fields["waiver_id"]),
            control_id=cast(str, fields["control_id"]),
            field=cast(str, fields["field"]),
            from_value=cast(JsonScalar, fields["from_value"]),
            to_value=cast(JsonScalar, fields["to_value"]),
            owner=cast(str, fields["owner"]),
            authorized_by=cast(str, fields["authorized_by"]),
            rationale=cast(str, fields["rationale"]),
            evidence_digest=cast(str, fields["evidence_digest"]),
            created_at=created,
            expires_at=expires,
            waiver_digest=canonical_digest(fields),
        )

    def active_at(self, instant: datetime) -> bool:
        """Return whether the waiver is active at one UTC instant."""
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("waiver evaluation time must be timezone-aware")
        return (
            parse_utc_timestamp(self.created_at, "waiver.created_at")
            <= instant
            < parse_utc_timestamp(
                self.expires_at,
                "waiver.expires_at",
            )
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one authorized exception waiver."""
        return {
            "waiver_id": self.waiver_id,
            "control_id": self.control_id,
            "field": self.field,
            "from_value": self.from_value,
            "to_value": self.to_value,
            "owner": self.owner,
            "authorized_by": self.authorized_by,
            "rationale": self.rationale,
            "evidence_digest": self.evidence_digest,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "waiver_digest": self.waiver_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ExceptionWaiver:
        """Parse and integrity-check one authorized exception waiver."""
        data = require_mapping(value, "waiver")
        waiver = cls.build(
            waiver_id=require_identifier(data.get("waiver_id"), "waiver.waiver_id"),
            control_id=require_identifier(data.get("control_id"), "waiver.control_id"),
            field=require_identifier(data.get("field"), "waiver.field"),
            from_value=require_json_scalar(data.get("from_value"), "waiver.from_value"),
            to_value=require_json_scalar(data.get("to_value"), "waiver.to_value"),
            owner=require_string(data.get("owner"), "waiver.owner"),
            authorized_by=require_string(data.get("authorized_by"), "waiver.authorized_by"),
            rationale=require_string(data.get("rationale"), "waiver.rationale"),
            evidence_digest=require_digest(
                data.get("evidence_digest"),
                "waiver.evidence_digest",
            ),
            created_at=require_utc_timestamp(data.get("created_at"), "waiver.created_at"),
            expires_at=require_utc_timestamp(data.get("expires_at"), "waiver.expires_at"),
        )
        if data.get("waiver_digest") != waiver.waiver_digest:
            raise ValueError("waiver digest does not match its content")
        return waiver


@dataclass(frozen=True)
class ProjectProfile:
    """Selected packs plus project intent, variables, overlays, and waivers."""

    profile_id: str
    intent: ProjectIntent
    packs: tuple[PackSelection, ...]
    variables: tuple[VariableDefinition, ...]
    assignments: tuple[VariableAssignment, ...]
    applicability: tuple[ApplicabilityDecision, ...]
    overlays: tuple[ControlOverlay, ...]
    waivers: tuple[ExceptionWaiver, ...]
    created_by: str
    created_at: str
    profile_digest: str

    @classmethod
    def build(
        cls,
        *,
        profile_id: str,
        intent: ProjectIntent,
        packs: tuple[PackSelection, ...],
        variables: tuple[VariableDefinition, ...],
        assignments: tuple[VariableAssignment, ...],
        applicability: tuple[ApplicabilityDecision, ...],
        overlays: tuple[ControlOverlay, ...],
        waivers: tuple[ExceptionWaiver, ...],
        created_by: str,
        created_at: str,
    ) -> ProjectProfile:
        """Build a complete profile and reject ambiguous duplicate records."""
        if not packs:
            raise ValueError("profile must select at least one standard pack")
        cls._unique((item.pack_id for item in packs), "profile pack ids")
        cls._unique((item.variable_id for item in variables), "profile variable ids")
        cls._unique((item.variable_id for item in assignments), "profile assignment ids")
        cls._unique((item.control_id for item in applicability), "applicability controls")
        cls._unique((item.control_id for item in overlays), "overlay controls")
        cls._unique((item.waiver_id for item in waivers), "waiver ids")
        definitions = {item.variable_id: item for item in variables}
        if any(item.variable_id not in definitions for item in assignments):
            raise ValueError("profile assignment references an unknown variable")
        assigned = {item.variable_id for item in assignments}
        for assignment in assignments:
            definition = definitions[assignment.variable_id]
            rebuilt = VariableAssignment.build(
                definition,
                value=assignment.value,
                secret_ref=assignment.secret_ref,
                source=assignment.source,
            )
            if rebuilt.assignment_digest != assignment.assignment_digest:
                raise ValueError("profile assignment digest is inconsistent")
        unresolved = tuple(
            definition.variable_id
            for definition in variables
            if definition.required
            and definition.variable_id not in assigned
            and definition.default_value is None
            and definition.default_secret_ref is None
        )
        if unresolved:
            raise ValueError("required profile variables are unresolved: " + ", ".join(unresolved))
        fields: dict[str, object] = {
            "schema_version": PROFILE_SCHEMA_VERSION,
            "profile_id": require_identifier(profile_id, "profile.profile_id"),
            "intent": intent.to_dict(),
            "packs": [item.to_dict() for item in packs],
            "variables": [item.to_dict() for item in variables],
            "assignments": [
                item.to_dict(definitions[item.variable_id].definition_digest)
                for item in assignments
            ],
            "applicability": [item.to_dict() for item in applicability],
            "overlays": [item.to_dict() for item in overlays],
            "waivers": [item.to_dict() for item in waivers],
            "created_by": require_string(created_by, "profile.created_by"),
            "created_at": require_utc_timestamp(created_at, "profile.created_at"),
        }
        return cls(
            profile_id=cast(str, fields["profile_id"]),
            intent=intent,
            packs=packs,
            variables=variables,
            assignments=assignments,
            applicability=applicability,
            overlays=overlays,
            waivers=waivers,
            created_by=cast(str, fields["created_by"]),
            created_at=cast(str, fields["created_at"]),
            profile_digest=canonical_digest(fields),
        )

    @staticmethod
    def _unique(values: Iterable[str], label: str) -> None:
        """Reject duplicate identifiers from one profile collection."""
        items = tuple(values)
        if len(items) != len(set(items)):
            raise ValueError(f"{label} must be unique")

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete desired-state project profile."""
        definitions = {item.variable_id: item for item in self.variables}
        return {
            "schema_version": PROFILE_SCHEMA_VERSION,
            "profile_id": self.profile_id,
            "intent": self.intent.to_dict(),
            "packs": [item.to_dict() for item in self.packs],
            "variables": [item.to_dict() for item in self.variables],
            "assignments": [
                item.to_dict(definitions[item.variable_id].definition_digest)
                for item in self.assignments
            ],
            "applicability": [item.to_dict() for item in self.applicability],
            "overlays": [item.to_dict() for item in self.overlays],
            "waivers": [item.to_dict() for item in self.waivers],
            "created_by": self.created_by,
            "created_at": self.created_at,
            "profile_digest": self.profile_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ProjectProfile:
        """Parse and integrity-check one complete desired-state profile."""
        data = require_mapping(value, "profile")
        require_exact_fields(data, PROJECT_PROFILE_FIELDS, "project-profile")
        if data.get("schema_version") != PROFILE_SCHEMA_VERSION:
            raise ValueError("unsupported project-profile schema version")
        variables = tuple(
            VariableDefinition.from_dict(item)
            for item in _object_array(data.get("variables"), "profile.variables")
        )
        definitions = {item.variable_id: item for item in variables}
        assignments: list[VariableAssignment] = []
        for item in _object_array(data.get("assignments"), "profile.assignments"):
            assignment_data = require_mapping(item, "assignment")
            variable_id = require_identifier(
                assignment_data.get("variable_id"),
                "assignment.variable_id",
            )
            if variable_id not in definitions:
                raise ValueError("profile assignment references an unknown variable")
            assignments.append(VariableAssignment.from_dict(item, definitions[variable_id]))
        profile = cls.build(
            profile_id=require_identifier(data.get("profile_id"), "profile.profile_id"),
            intent=ProjectIntent.from_dict(data.get("intent")),
            packs=tuple(
                PackSelection.from_dict(item)
                for item in _object_array(data.get("packs"), "profile.packs")
            ),
            variables=variables,
            assignments=tuple(assignments),
            applicability=tuple(
                ApplicabilityDecision.from_dict(item)
                for item in _object_array(data.get("applicability"), "profile.applicability")
            ),
            overlays=tuple(
                ControlOverlay.from_dict(item)
                for item in _object_array(data.get("overlays"), "profile.overlays")
            ),
            waivers=tuple(
                ExceptionWaiver.from_dict(item)
                for item in _object_array(data.get("waivers"), "profile.waivers")
            ),
            created_by=require_string(data.get("created_by"), "profile.created_by"),
            created_at=require_utc_timestamp(data.get("created_at"), "profile.created_at"),
        )
        recorded = require_digest(data.get("profile_digest"), "profile.profile_digest")
        if recorded != profile.profile_digest:
            raise ValueError("profile digest does not match its content")
        return profile
