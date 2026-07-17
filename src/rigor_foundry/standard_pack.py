# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — versioned standard packs
"""Define signed control packs with explicit evidence and remediation contracts."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Literal, cast

from .audit_primitives import require_exact_fields
from .condition_language import ConditionExpression
from .model_primitives import (
    require_boolean,
    require_digest,
    require_identifier,
    require_semantic_version,
    require_unique_strings,
    validate_unique_strings,
)
from .models import (
    AUDIT_DOMAINS,
    Severity,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
)
from .protocol_fields import CONTROL_DEFINITION_FIELDS, EVIDENCE_CONTRACT_FIELDS
from .trust import (
    ED25519_ALGORITHM,
    ED25519_SIGNATURE_HEX_LENGTH,
    STANDARD_PACK_SIGNATURE_DOMAIN,
    require_lower_hex,
)

PACK_COMPONENT_SCHEMA_VERSION = "1.0"
PACK_SCHEMA_VERSION = "1.1"
PACK_SIGNATURE_SCHEMA_VERSION = "1.0"

TargetLevel = Literal["baseline", "production", "enterprise", "industrial-safety"]
ControlMode = Literal["require", "deny"]

TARGET_LEVEL_ORDER: dict[TargetLevel, int] = {
    "baseline": 0,
    "production": 1,
    "enterprise": 2,
    "industrial-safety": 3,
}


def _target_level(value: object, field: str) -> TargetLevel:
    """Return one supported maturity target."""
    text = require_string(value, field)
    if text not in TARGET_LEVEL_ORDER:
        raise ValueError(f"{field} is unsupported")
    return text


def _severity(value: object, field: str) -> Severity:
    """Return one supported finding severity."""
    text = require_string(value, field)
    if text not in {"P0", "P1", "P2", "P3", "P4"}:
        raise ValueError(f"{field} is unsupported")
    return cast(Severity, text)


@dataclass(frozen=True)
class PackSignature:
    """Detached Ed25519 signature over a canonical pack payload digest."""

    schema_version: str
    algorithm: str
    signature_domain: str
    key_id: str
    payload_digest: str
    signature_hex: str
    signature_digest: str

    @classmethod
    def build(
        cls,
        *,
        key_id: str,
        payload_digest: str,
        signature_hex: str,
        signature_domain: str = STANDARD_PACK_SIGNATURE_DOMAIN,
        algorithm: str = ED25519_ALGORITHM,
    ) -> PackSignature:
        """Build signature metadata from actual detached signature bytes."""
        if algorithm != ED25519_ALGORITHM:
            raise ValueError("signature.algorithm must be ed25519")
        if signature_domain != STANDARD_PACK_SIGNATURE_DOMAIN:
            raise ValueError("signature.signature_domain must be the standard-pack v1 domain")
        signature = require_lower_hex(
            signature_hex,
            "signature.signature_hex",
            length=ED25519_SIGNATURE_HEX_LENGTH,
        )
        return cls(
            schema_version=PACK_SIGNATURE_SCHEMA_VERSION,
            algorithm=algorithm,
            signature_domain=signature_domain,
            key_id=require_identifier(key_id, "signature.key_id"),
            payload_digest=require_digest(payload_digest, "signature.payload_digest"),
            signature_hex=signature,
            signature_digest=sha256(bytes.fromhex(signature)).hexdigest(),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise detached signature metadata."""
        return {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "signature_domain": self.signature_domain,
            "key_id": self.key_id,
            "payload_digest": self.payload_digest,
            "signature_hex": self.signature_hex,
            "signature_digest": self.signature_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> PackSignature:
        """Parse detached signature metadata."""
        data = require_mapping(value, "signature")
        expected = frozenset(
            {
                "schema_version",
                "algorithm",
                "signature_domain",
                "key_id",
                "payload_digest",
                "signature_hex",
                "signature_digest",
            }
        )
        if frozenset(data) != expected:
            raise ValueError("pack signature fields do not match schema")
        if data.get("schema_version") != PACK_SIGNATURE_SCHEMA_VERSION:
            raise ValueError("unsupported pack-signature schema version")
        signature = cls.build(
            algorithm=require_identifier(data.get("algorithm"), "signature.algorithm"),
            signature_domain=require_string(
                data.get("signature_domain"),
                "signature.signature_domain",
            ),
            key_id=require_identifier(data.get("key_id"), "signature.key_id"),
            payload_digest=require_digest(
                data.get("payload_digest"),
                "signature.payload_digest",
            ),
            signature_hex=require_string(
                data.get("signature_hex"),
                "signature.signature_hex",
            ),
        )
        if data.get("signature_digest") != signature.signature_digest:
            raise ValueError("signature digest does not match detached signature bytes")
        return signature


@dataclass(frozen=True)
class EvidenceContract:
    """Evidence that must exist before one control can pass."""

    contract_id: str
    required_adapters: tuple[str, ...]
    evidence_types: tuple[str, ...]
    freshness_seconds: int
    minimum_independent_reviewers: int
    contract_digest: str

    @classmethod
    def build(
        cls,
        *,
        contract_id: str,
        required_adapters: tuple[str, ...],
        evidence_types: tuple[str, ...],
        freshness_seconds: int,
        minimum_independent_reviewers: int,
    ) -> EvidenceContract:
        """Build a fail-closed evidence contract."""
        fields: dict[str, object] = {
            "schema_version": PACK_COMPONENT_SCHEMA_VERSION,
            "contract_id": require_identifier(contract_id, "evidence.contract_id"),
            "required_adapters": list(
                validate_unique_strings(
                    required_adapters,
                    "evidence.required_adapters",
                    minimum=1,
                )
            ),
            "evidence_types": list(
                validate_unique_strings(
                    evidence_types,
                    "evidence.evidence_types",
                    minimum=1,
                )
            ),
            "freshness_seconds": require_integer(
                freshness_seconds,
                "evidence.freshness_seconds",
                minimum=1,
            ),
            "minimum_independent_reviewers": require_integer(
                minimum_independent_reviewers,
                "evidence.minimum_independent_reviewers",
                minimum=1,
            ),
        }
        return cls(
            contract_id=cast(str, fields["contract_id"]),
            required_adapters=tuple(cast(list[str], fields["required_adapters"])),
            evidence_types=tuple(cast(list[str], fields["evidence_types"])),
            freshness_seconds=cast(int, fields["freshness_seconds"]),
            minimum_independent_reviewers=cast(
                int,
                fields["minimum_independent_reviewers"],
            ),
            contract_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the integrity-bound evidence contract."""
        return {
            "schema_version": PACK_COMPONENT_SCHEMA_VERSION,
            "contract_id": self.contract_id,
            "required_adapters": list(self.required_adapters),
            "evidence_types": list(self.evidence_types),
            "freshness_seconds": self.freshness_seconds,
            "minimum_independent_reviewers": self.minimum_independent_reviewers,
            "contract_digest": self.contract_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> EvidenceContract:
        """Parse and integrity-check one evidence contract."""
        data = require_mapping(value, "evidence_contract")
        require_exact_fields(data, EVIDENCE_CONTRACT_FIELDS, "evidence-contract")
        if data.get("schema_version") != PACK_COMPONENT_SCHEMA_VERSION:
            raise ValueError("unsupported evidence-contract schema version")
        contract = cls.build(
            contract_id=require_identifier(data.get("contract_id"), "evidence.contract_id"),
            required_adapters=require_unique_strings(
                data.get("required_adapters"),
                "evidence.required_adapters",
                minimum=1,
            ),
            evidence_types=require_unique_strings(
                data.get("evidence_types"),
                "evidence.evidence_types",
                minimum=1,
            ),
            freshness_seconds=require_integer(
                data.get("freshness_seconds"),
                "evidence.freshness_seconds",
                minimum=1,
            ),
            minimum_independent_reviewers=require_integer(
                data.get("minimum_independent_reviewers"),
                "evidence.minimum_independent_reviewers",
                minimum=1,
            ),
        )
        recorded = require_digest(data.get("contract_digest"), "evidence.contract_digest")
        if recorded != contract.contract_digest:
            raise ValueError("evidence-contract digest does not match its content")
        return contract


@dataclass(frozen=True)
class RemediationContract:
    """Required dependency, acceptance, review, and reopen semantics."""

    dependencies: tuple[str, ...]
    procedure_ids: tuple[str, ...]
    acceptance_gates: tuple[str, ...]
    reopen_triggers: tuple[str, ...]
    independent_verifier_required: bool
    contract_digest: str

    @classmethod
    def build(
        cls,
        *,
        dependencies: tuple[str, ...],
        procedure_ids: tuple[str, ...],
        acceptance_gates: tuple[str, ...],
        reopen_triggers: tuple[str, ...],
        independent_verifier_required: bool,
    ) -> RemediationContract:
        """Build one complete remediation acceptance contract."""
        fields: dict[str, object] = {
            "schema_version": PACK_COMPONENT_SCHEMA_VERSION,
            "dependencies": list(
                validate_unique_strings(dependencies, "remediation.dependencies")
            ),
            "procedure_ids": list(
                validate_unique_strings(procedure_ids, "remediation.procedure_ids")
            ),
            "acceptance_gates": list(
                validate_unique_strings(
                    acceptance_gates,
                    "remediation.acceptance_gates",
                    minimum=1,
                )
            ),
            "reopen_triggers": list(
                validate_unique_strings(
                    reopen_triggers,
                    "remediation.reopen_triggers",
                    minimum=1,
                )
            ),
            "independent_verifier_required": require_boolean(
                independent_verifier_required,
                "remediation.independent_verifier_required",
            ),
        }
        return cls(
            dependencies=tuple(cast(list[str], fields["dependencies"])),
            procedure_ids=tuple(cast(list[str], fields["procedure_ids"])),
            acceptance_gates=tuple(cast(list[str], fields["acceptance_gates"])),
            reopen_triggers=tuple(cast(list[str], fields["reopen_triggers"])),
            independent_verifier_required=cast(
                bool,
                fields["independent_verifier_required"],
            ),
            contract_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one remediation contract."""
        return {
            "schema_version": PACK_COMPONENT_SCHEMA_VERSION,
            "dependencies": list(self.dependencies),
            "procedure_ids": list(self.procedure_ids),
            "acceptance_gates": list(self.acceptance_gates),
            "reopen_triggers": list(self.reopen_triggers),
            "independent_verifier_required": self.independent_verifier_required,
            "contract_digest": self.contract_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> RemediationContract:
        """Parse and integrity-check one remediation contract."""
        data = require_mapping(value, "remediation_contract")
        if data.get("schema_version") != PACK_COMPONENT_SCHEMA_VERSION:
            raise ValueError("unsupported remediation-contract schema version")
        contract = cls.build(
            dependencies=require_unique_strings(
                data.get("dependencies"),
                "remediation.dependencies",
            ),
            procedure_ids=require_unique_strings(
                data.get("procedure_ids"),
                "remediation.procedure_ids",
            ),
            acceptance_gates=require_unique_strings(
                data.get("acceptance_gates"),
                "remediation.acceptance_gates",
                minimum=1,
            ),
            reopen_triggers=require_unique_strings(
                data.get("reopen_triggers"),
                "remediation.reopen_triggers",
                minimum=1,
            ),
            independent_verifier_required=require_boolean(
                data.get("independent_verifier_required"),
                "remediation.independent_verifier_required",
            ),
        )
        recorded = require_digest(data.get("contract_digest"), "remediation.contract_digest")
        if recorded != contract.contract_digest:
            raise ValueError("remediation-contract digest does not match its content")
        return contract


@dataclass(frozen=True)
class ControlDefinition:
    """One stable versioned control supplied by a standard pack."""

    control_id: str
    version: str
    title: str
    domain: str
    severity: Severity
    target_level: TargetLevel
    mode: ControlMode
    default_applicable: bool
    condition: ConditionExpression | None
    evidence: EvidenceContract
    remediation: RemediationContract
    control_digest: str

    @property
    def versioned_id(self) -> str:
        """Return the stable control identifier with its exact version."""
        return f"{self.control_id}@{self.version}"

    @classmethod
    def build(
        cls,
        *,
        control_id: str,
        version: str,
        title: str,
        domain: str,
        severity: Severity,
        target_level: TargetLevel,
        mode: ControlMode,
        default_applicable: bool,
        condition: ConditionExpression | None,
        evidence: EvidenceContract,
        remediation: RemediationContract,
    ) -> ControlDefinition:
        """Build one immutable control definition."""
        if domain not in AUDIT_DOMAINS:
            raise ValueError("control.domain is unsupported")
        if mode not in {"require", "deny"}:
            raise ValueError("control.mode is unsupported")
        fields: dict[str, object] = {
            "schema_version": PACK_COMPONENT_SCHEMA_VERSION,
            "control_id": require_identifier(control_id, "control.control_id"),
            "version": require_semantic_version(version, "control.version"),
            "title": require_string(title, "control.title"),
            "domain": domain,
            "severity": _severity(severity, "control.severity"),
            "target_level": _target_level(target_level, "control.target_level"),
            "mode": mode,
            "default_applicable": require_boolean(
                default_applicable,
                "control.default_applicable",
            ),
            "condition": condition.to_dict() if condition is not None else None,
            "evidence": evidence.to_dict(),
            "remediation": remediation.to_dict(),
        }
        return cls(
            control_id=cast(str, fields["control_id"]),
            version=cast(str, fields["version"]),
            title=cast(str, fields["title"]),
            domain=domain,
            severity=cast(Severity, fields["severity"]),
            target_level=cast(TargetLevel, fields["target_level"]),
            mode=mode,
            default_applicable=cast(bool, fields["default_applicable"]),
            condition=condition,
            evidence=evidence,
            remediation=remediation,
            control_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one versioned control definition."""
        return {
            "schema_version": PACK_COMPONENT_SCHEMA_VERSION,
            "control_id": self.control_id,
            "version": self.version,
            "title": self.title,
            "domain": self.domain,
            "severity": self.severity,
            "target_level": self.target_level,
            "mode": self.mode,
            "default_applicable": self.default_applicable,
            "condition": self.condition.to_dict() if self.condition is not None else None,
            "evidence": self.evidence.to_dict(),
            "remediation": self.remediation.to_dict(),
            "control_digest": self.control_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ControlDefinition:
        """Parse and integrity-check one control definition."""
        data = require_mapping(value, "control")
        require_exact_fields(data, CONTROL_DEFINITION_FIELDS, "control")
        if data.get("schema_version") != PACK_COMPONENT_SCHEMA_VERSION:
            raise ValueError("unsupported control schema version")
        raw_condition = data.get("condition")
        condition = None if raw_condition is None else ConditionExpression.from_dict(raw_condition)
        mode = require_string(data.get("mode"), "control.mode")
        if mode not in {"require", "deny"}:
            raise ValueError("control.mode is unsupported")
        control = cls.build(
            control_id=require_identifier(data.get("control_id"), "control.control_id"),
            version=require_semantic_version(data.get("version"), "control.version"),
            title=require_string(data.get("title"), "control.title"),
            domain=require_string(data.get("domain"), "control.domain"),
            severity=_severity(data.get("severity"), "control.severity"),
            target_level=_target_level(data.get("target_level"), "control.target_level"),
            mode=cast(ControlMode, mode),
            default_applicable=require_boolean(
                data.get("default_applicable"),
                "control.default_applicable",
            ),
            condition=condition,
            evidence=EvidenceContract.from_dict(data.get("evidence")),
            remediation=RemediationContract.from_dict(data.get("remediation")),
        )
        recorded = require_digest(data.get("control_digest"), "control.control_digest")
        if recorded != control.control_digest:
            raise ValueError("control digest does not match its content")
        return control


@dataclass(frozen=True)
class StandardPack:
    """Signed, licensed, source-pinned collection of versioned controls."""

    pack_id: str
    version: str
    source_uri: str
    source_digest: str
    licence: str
    signature: PackSignature
    controls: tuple[ControlDefinition, ...]
    pack_digest: str

    @staticmethod
    def payload_digest(
        *,
        pack_id: str,
        version: str,
        source_uri: str,
        source_digest: str,
        licence: str,
        controls: tuple[ControlDefinition, ...],
    ) -> str:
        """Return the exact digest a detached pack signature must cover."""
        payload = StandardPack._payload(
            pack_id=pack_id,
            version=version,
            source_uri=source_uri,
            source_digest=source_digest,
            licence=licence,
            controls=controls,
        )
        return canonical_digest(payload)

    @staticmethod
    def _payload(
        *,
        pack_id: str,
        version: str,
        source_uri: str,
        source_digest: str,
        licence: str,
        controls: tuple[ControlDefinition, ...],
    ) -> dict[str, object]:
        """Build the canonical signature payload after validating invariants."""
        validated_id = require_identifier(pack_id, "pack.pack_id")
        validated_version = require_semantic_version(version, "pack.version")
        validated_uri = require_string(source_uri, "pack.source_uri")
        if any(character.isspace() for character in validated_uri):
            raise ValueError("pack.source_uri must not contain whitespace")
        require_digest(source_digest, "pack.source_digest")
        require_string(licence, "pack.licence")
        if not controls:
            raise ValueError("pack.controls must not be empty")
        versioned_ids = tuple(control.versioned_id for control in controls)
        if len(versioned_ids) != len(set(versioned_ids)):
            raise ValueError("pack.controls must have unique versioned identifiers")
        prefix = f"{validated_id}/"
        if any(not control.control_id.startswith(prefix) for control in controls):
            raise ValueError("pack control identifiers must use the pack namespace")
        return {
            "schema_version": PACK_SCHEMA_VERSION,
            "signature_domain": STANDARD_PACK_SIGNATURE_DOMAIN,
            "pack_id": validated_id,
            "version": validated_version,
            "source_uri": validated_uri,
            "source_digest": source_digest,
            "licence": licence,
            "controls": [control.to_dict() for control in controls],
        }

    @classmethod
    def build(
        cls,
        *,
        pack_id: str,
        version: str,
        source_uri: str,
        source_digest: str,
        licence: str,
        signature: PackSignature,
        controls: tuple[ControlDefinition, ...],
    ) -> StandardPack:
        """Build one pack and require its signature to bind the payload."""
        payload = cls._payload(
            pack_id=pack_id,
            version=version,
            source_uri=source_uri,
            source_digest=source_digest,
            licence=licence,
            controls=controls,
        )
        payload_digest = canonical_digest(payload)
        validated_signature = PackSignature.from_dict(signature.to_dict())
        if validated_signature.payload_digest != payload_digest:
            raise ValueError("pack signature does not bind the canonical payload")
        body = {**payload, "signature": validated_signature.to_dict()}
        return cls(
            pack_id=cast(str, payload["pack_id"]),
            version=cast(str, payload["version"]),
            source_uri=cast(str, payload["source_uri"]),
            source_digest=cast(str, payload["source_digest"]),
            licence=cast(str, payload["licence"]),
            signature=validated_signature,
            controls=controls,
            pack_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the signed pack and its complete integrity digest."""
        return {
            "schema_version": PACK_SCHEMA_VERSION,
            "signature_domain": STANDARD_PACK_SIGNATURE_DOMAIN,
            "pack_id": self.pack_id,
            "version": self.version,
            "source_uri": self.source_uri,
            "source_digest": self.source_digest,
            "licence": self.licence,
            "signature": self.signature.to_dict(),
            "controls": [control.to_dict() for control in self.controls],
            "pack_digest": self.pack_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> StandardPack:
        """Parse and integrity-check one signed standard pack."""
        data = require_mapping(value, "pack")
        expected = frozenset(
            {
                "schema_version",
                "signature_domain",
                "pack_id",
                "version",
                "source_uri",
                "source_digest",
                "licence",
                "signature",
                "controls",
                "pack_digest",
            }
        )
        if frozenset(data) != expected:
            raise ValueError("standard-pack fields do not match schema")
        if data.get("schema_version") != PACK_SCHEMA_VERSION:
            raise ValueError("unsupported pack schema version")
        if data.get("signature_domain") != STANDARD_PACK_SIGNATURE_DOMAIN:
            raise ValueError("standard-pack signature domain does not match schema")
        raw_controls = data.get("controls")
        if not isinstance(raw_controls, list):
            raise ValueError("pack.controls must be an array")
        pack = cls.build(
            pack_id=require_identifier(data.get("pack_id"), "pack.pack_id"),
            version=require_semantic_version(data.get("version"), "pack.version"),
            source_uri=require_string(data.get("source_uri"), "pack.source_uri"),
            source_digest=require_digest(data.get("source_digest"), "pack.source_digest"),
            licence=require_string(data.get("licence"), "pack.licence"),
            signature=PackSignature.from_dict(data.get("signature")),
            controls=tuple(
                ControlDefinition.from_dict(item) for item in cast(list[object], raw_controls)
            ),
        )
        recorded = require_digest(data.get("pack_digest"), "pack.pack_digest")
        if recorded != pack.pack_digest:
            raise ValueError("pack digest does not match its content")
        return pack
