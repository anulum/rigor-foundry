# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — effective desired-state locks
"""Resolve exact packs and project overlays into a fail-closed profile lock."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from .model_primitives import (
    SecretReference,
    VariableAssignment,
    VariableDefinition,
    VariableValue,
    require_boolean,
    require_digest,
    require_identifier,
    require_semantic_version,
    require_utc_timestamp,
    serialise_variable_value,
    validate_unique_strings,
)
from .models import AUDIT_DOMAINS, canonical_digest, require_mapping, require_string
from .project_profile import ProjectProfile
from .standard_pack import (
    TARGET_LEVEL_ORDER,
    ControlDefinition,
    ControlMode,
    StandardPack,
    TargetLevel,
)
from .trust import VerificationTrustStore


def _object_array(value: object, field: str) -> list[object]:
    """Return one JSON array of objects for protocol parsing."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return cast(list[object], value)


LOCK_SCHEMA_VERSION = "1.0"
PACK_VERIFICATION_SCHEMA_VERSION = "1.0"
RESOLVER_VERSION = "0.1.0"


@dataclass(frozen=True)
class AdapterLock:
    """Exact executable, configuration, command, environment, and domain lock."""

    adapter_id: str
    version: str
    executable_digest: str
    config_digest: str
    command_digest: str
    environment_digest: str
    domains: tuple[str, ...]
    adapter_digest: str

    @classmethod
    def build(
        cls,
        *,
        adapter_id: str,
        version: str,
        executable_digest: str,
        config_digest: str,
        command_digest: str,
        environment_digest: str,
        domains: tuple[str, ...],
    ) -> AdapterLock:
        """Build one exact adapter identity with no names-only shortcut."""
        validated_domains = validate_unique_strings(domains, "adapter.domains", minimum=1)
        unknown = set(validated_domains).difference(AUDIT_DOMAINS)
        if unknown:
            raise ValueError(
                "adapter.domains contains unsupported values: " + ", ".join(sorted(unknown))
            )
        fields: dict[str, object] = {
            "adapter_id": require_identifier(adapter_id, "adapter.adapter_id"),
            "version": require_semantic_version(version, "adapter.version"),
            "executable_digest": require_digest(
                executable_digest,
                "adapter.executable_digest",
            ),
            "config_digest": require_digest(config_digest, "adapter.config_digest"),
            "command_digest": require_digest(command_digest, "adapter.command_digest"),
            "environment_digest": require_digest(
                environment_digest,
                "adapter.environment_digest",
            ),
            "domains": list(validated_domains),
        }
        return cls(
            adapter_id=cast(str, fields["adapter_id"]),
            version=cast(str, fields["version"]),
            executable_digest=cast(str, fields["executable_digest"]),
            config_digest=cast(str, fields["config_digest"]),
            command_digest=cast(str, fields["command_digest"]),
            environment_digest=cast(str, fields["environment_digest"]),
            domains=validated_domains,
            adapter_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one complete adapter lock."""
        return {
            "adapter_id": self.adapter_id,
            "version": self.version,
            "executable_digest": self.executable_digest,
            "config_digest": self.config_digest,
            "command_digest": self.command_digest,
            "environment_digest": self.environment_digest,
            "domains": list(self.domains),
            "adapter_digest": self.adapter_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> AdapterLock:
        """Parse one adapter lock and rederive its content digest."""
        data = require_mapping(value, "adapter")
        raw_domains = data.get("domains")
        if not isinstance(raw_domains, list):
            raise ValueError("adapter.domains must be an array")
        adapter = cls.build(
            adapter_id=require_string(data.get("adapter_id"), "adapter.adapter_id"),
            version=require_string(data.get("version"), "adapter.version"),
            executable_digest=require_string(
                data.get("executable_digest"),
                "adapter.executable_digest",
            ),
            config_digest=require_string(data.get("config_digest"), "adapter.config_digest"),
            command_digest=require_string(data.get("command_digest"), "adapter.command_digest"),
            environment_digest=require_string(
                data.get("environment_digest"),
                "adapter.environment_digest",
            ),
            domains=tuple(require_string(item, "adapter.domains[]") for item in raw_domains),
        )
        if data.get("adapter_digest") != adapter.adapter_digest:
            raise ValueError("adapter digest does not match its content")
        return adapter


@dataclass(frozen=True)
class PackVerification:
    """Result of verifying one exact pack against an explicit trust store."""

    schema_version: str
    pack_digest: str
    key_id: str
    signature_domain: str
    signature_digest: str
    trust_store_digest: str
    verified_at: str
    verification_digest: str

    @classmethod
    def build(
        cls,
        *,
        pack: StandardPack,
        trust_store: VerificationTrustStore,
        verified_at: str,
    ) -> PackVerification:
        """Verify the actual detached signature before producing evidence."""
        rebuilt = StandardPack.build(
            pack_id=pack.pack_id,
            version=pack.version,
            source_uri=pack.source_uri,
            source_digest=pack.source_digest,
            licence=pack.licence,
            signature=pack.signature,
            controls=pack.controls,
        )
        if rebuilt != pack:
            raise ValueError("pack content or digest is internally inconsistent")
        if not trust_store.verify(
            key_id=pack.signature.key_id,
            algorithm=pack.signature.algorithm,
            signature_domain=pack.signature.signature_domain,
            payload_digest=pack.signature.payload_digest,
            signature_hex=pack.signature.signature_hex,
        ):
            raise ValueError("pack signature is not valid under the supplied trust store")
        fields: dict[str, object] = {
            "schema_version": PACK_VERIFICATION_SCHEMA_VERSION,
            "pack_digest": pack.pack_digest,
            "key_id": pack.signature.key_id,
            "signature_domain": pack.signature.signature_domain,
            "signature_digest": pack.signature.signature_digest,
            "trust_store_digest": trust_store.trust_store_digest,
            "verified_at": require_utc_timestamp(
                verified_at,
                "verification.verified_at",
            ),
        }
        return cls(
            schema_version=PACK_VERIFICATION_SCHEMA_VERSION,
            pack_digest=cast(str, fields["pack_digest"]),
            key_id=cast(str, fields["key_id"]),
            signature_domain=cast(str, fields["signature_domain"]),
            signature_digest=cast(str, fields["signature_digest"]),
            trust_store_digest=cast(str, fields["trust_store_digest"]),
            verified_at=cast(str, fields["verified_at"]),
            verification_digest=canonical_digest(fields),
        )

    def valid_for(
        self,
        pack: StandardPack,
        trust_store: VerificationTrustStore,
    ) -> bool:
        """Reverify every binding and the detached signature itself."""
        try:
            rebuilt = PackVerification.build(
                pack=pack,
                trust_store=trust_store,
                verified_at=self.verified_at,
            )
        except ValueError:
            return False
        return rebuilt == self

    def to_dict(self) -> dict[str, object]:
        """Serialise external signature-verification evidence."""
        return {
            "schema_version": self.schema_version,
            "pack_digest": self.pack_digest,
            "key_id": self.key_id,
            "signature_domain": self.signature_domain,
            "signature_digest": self.signature_digest,
            "trust_store_digest": self.trust_store_digest,
            "verified_at": self.verified_at,
            "verification_digest": self.verification_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> PackVerification:
        """Parse offline verification evidence and rederive its digest.

        This path rebinds serialised fields only. It does not re-check a pack
        signature; callers that need live signature validity must use
        :meth:`build` with the pack and trust store.
        """
        data = require_mapping(value, "verification")
        if data.get("schema_version") != PACK_VERIFICATION_SCHEMA_VERSION:
            raise ValueError("unsupported pack-verification schema version")
        fields: dict[str, object] = {
            "schema_version": PACK_VERIFICATION_SCHEMA_VERSION,
            "pack_digest": require_digest(data.get("pack_digest"), "verification.pack_digest"),
            "key_id": require_identifier(data.get("key_id"), "verification.key_id"),
            "signature_domain": require_string(
                data.get("signature_domain"),
                "verification.signature_domain",
            ),
            "signature_digest": require_digest(
                data.get("signature_digest"),
                "verification.signature_digest",
            ),
            "trust_store_digest": require_digest(
                data.get("trust_store_digest"),
                "verification.trust_store_digest",
            ),
            "verified_at": require_utc_timestamp(
                data.get("verified_at"),
                "verification.verified_at",
            ),
        }
        verification = cls(
            schema_version=PACK_VERIFICATION_SCHEMA_VERSION,
            pack_digest=cast(str, fields["pack_digest"]),
            key_id=cast(str, fields["key_id"]),
            signature_domain=cast(str, fields["signature_domain"]),
            signature_digest=cast(str, fields["signature_digest"]),
            trust_store_digest=cast(str, fields["trust_store_digest"]),
            verified_at=cast(str, fields["verified_at"]),
            verification_digest=canonical_digest(fields),
        )
        if data.get("verification_digest") != verification.verification_digest:
            raise ValueError("verification digest does not match its content")
        return verification


@dataclass(frozen=True)
class ResolvedVariable:
    """Exact variable value or opaque secret reference bound into the lock."""

    variable_id: str
    definition_digest: str
    assignment_digest: str
    sensitivity: str
    value: VariableValue | None
    secret_ref: SecretReference | None
    value_digest: str

    @classmethod
    def build(
        cls,
        definition: VariableDefinition,
        assignment: VariableAssignment | None,
    ) -> ResolvedVariable:
        """Resolve an explicit assignment or definition default without secret bytes."""
        if assignment is None:
            value = definition.default_value
            secret_ref = definition.default_secret_ref
            assignment_digest = canonical_digest(
                {
                    "definition_digest": definition.definition_digest,
                    "source": "definition-default",
                    "value": serialise_variable_value(value),
                    "secret_ref": secret_ref.to_dict() if secret_ref else None,
                }
            )
        else:
            rebuilt = VariableAssignment.build(
                definition,
                value=assignment.value,
                secret_ref=assignment.secret_ref,
                source=assignment.source,
            )
            if rebuilt.assignment_digest != assignment.assignment_digest:
                raise ValueError("variable assignment digest is inconsistent")
            value = assignment.value
            secret_ref = assignment.secret_ref
            assignment_digest = assignment.assignment_digest
        if definition.required and value is None and secret_ref is None:
            raise ValueError(f"required variable is unresolved: {definition.variable_id}")
        fields: dict[str, object] = {
            "variable_id": definition.variable_id,
            "definition_digest": definition.definition_digest,
            "assignment_digest": assignment_digest,
            "sensitivity": definition.sensitivity,
            "value": serialise_variable_value(value),
            "secret_ref": secret_ref.to_dict() if secret_ref else None,
        }
        return cls(
            variable_id=definition.variable_id,
            definition_digest=definition.definition_digest,
            assignment_digest=assignment_digest,
            sensitivity=definition.sensitivity,
            value=value,
            secret_ref=secret_ref,
            value_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the resolved value without ever rendering secret bytes."""
        return {
            "variable_id": self.variable_id,
            "definition_digest": self.definition_digest,
            "assignment_digest": self.assignment_digest,
            "sensitivity": self.sensitivity,
            "value": serialise_variable_value(self.value),
            "secret_ref": self.secret_ref.to_dict() if self.secret_ref else None,
            "value_digest": self.value_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ResolvedVariable:
        """Parse one resolved variable binding and rederive its value digest."""
        data = require_mapping(value, "variable")
        raw_value = data.get("value")
        if isinstance(raw_value, list):
            raw_value = tuple(cast(list[object], raw_value))
        if raw_value is not None and not isinstance(raw_value, (str, int, float, bool, tuple)):
            raise ValueError("variable.value has an unsupported type")
        if isinstance(raw_value, tuple) and any(not isinstance(item, str) for item in raw_value):
            raise ValueError("variable.value string-list members must be strings")
        raw_secret = data.get("secret_ref")
        secret_ref = None if raw_secret is None else SecretReference.from_dict(raw_secret)
        typed_value = cast(VariableValue | None, raw_value)
        fields: dict[str, object] = {
            "variable_id": require_identifier(data.get("variable_id"), "variable.variable_id"),
            "definition_digest": require_digest(
                data.get("definition_digest"),
                "variable.definition_digest",
            ),
            "assignment_digest": require_digest(
                data.get("assignment_digest"),
                "variable.assignment_digest",
            ),
            "sensitivity": require_string(data.get("sensitivity"), "variable.sensitivity"),
            "value": serialise_variable_value(typed_value),
            "secret_ref": secret_ref.to_dict() if secret_ref is not None else None,
        }
        resolved = cls(
            variable_id=cast(str, fields["variable_id"]),
            definition_digest=cast(str, fields["definition_digest"]),
            assignment_digest=cast(str, fields["assignment_digest"]),
            sensitivity=cast(str, fields["sensitivity"]),
            value=typed_value,
            secret_ref=secret_ref,
            value_digest=canonical_digest(fields),
        )
        if data.get("value_digest") != resolved.value_digest:
            raise ValueError("variable value digest does not match its content")
        return resolved


@dataclass(frozen=True)
class PolicyContradiction:
    """One reproducible policy composition conflict or warning."""

    code: str
    subject: str
    sources: tuple[str, ...]
    detail: str
    blocking: bool
    contradiction_digest: str

    @classmethod
    def build(
        cls,
        *,
        code: str,
        subject: str,
        sources: tuple[str, ...],
        detail: str,
        blocking: bool = True,
    ) -> PolicyContradiction:
        """Build one deterministic contradiction record."""
        fields: dict[str, object] = {
            "code": require_identifier(code, "contradiction.code"),
            "subject": require_string(subject, "contradiction.subject"),
            "sources": list(validate_unique_strings(sources, "contradiction.sources", minimum=1)),
            "detail": require_string(detail, "contradiction.detail"),
            "blocking": require_boolean(blocking, "contradiction.blocking"),
        }
        return cls(
            code=cast(str, fields["code"]),
            subject=cast(str, fields["subject"]),
            sources=tuple(cast(list[str], fields["sources"])),
            detail=cast(str, fields["detail"]),
            blocking=cast(bool, fields["blocking"]),
            contradiction_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one contradiction or warning."""
        return {
            "code": self.code,
            "subject": self.subject,
            "sources": list(self.sources),
            "detail": self.detail,
            "blocking": self.blocking,
            "contradiction_digest": self.contradiction_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> PolicyContradiction:
        """Parse one contradiction and rederive its digest."""
        data = require_mapping(value, "contradiction")
        raw_sources = data.get("sources")
        if not isinstance(raw_sources, list):
            raise ValueError("contradiction.sources must be an array")
        contradiction = cls.build(
            code=require_string(data.get("code"), "contradiction.code"),
            subject=require_string(data.get("subject"), "contradiction.subject"),
            sources=tuple(require_string(item, "contradiction.sources[]") for item in raw_sources),
            detail=require_string(data.get("detail"), "contradiction.detail"),
            blocking=require_boolean(data.get("blocking"), "contradiction.blocking"),
        )
        if data.get("contradiction_digest") != contradiction.contradiction_digest:
            raise ValueError("contradiction digest does not match its content")
        return contradiction


@dataclass(frozen=True)
class EffectiveControl:
    """One resolved control with applicability, strength, and adapter gaps."""

    source_pack_id: str
    source_pack_digest: str
    control: ControlDefinition
    applicable: bool
    applicability_rationale: str
    target_level: TargetLevel
    mode: ControlMode
    active_waiver_ids: tuple[str, ...]
    risk_acceptance_waiver_ids: tuple[str, ...]
    missing_adapter_ids: tuple[str, ...]
    effective_digest: str

    @classmethod
    def build(
        cls,
        *,
        source_pack: StandardPack,
        control: ControlDefinition,
        applicable: bool,
        applicability_rationale: str,
        target_level: TargetLevel,
        mode: ControlMode,
        active_waiver_ids: tuple[str, ...],
        missing_adapter_ids: tuple[str, ...],
        risk_acceptance_waiver_ids: tuple[str, ...] = (),
    ) -> EffectiveControl:
        """Build one exact effective-control record."""
        matches = tuple(
            item for item in source_pack.controls if item.control_digest == control.control_digest
        )
        if len(matches) != 1 or matches[0] != control:
            raise ValueError("effective control is not a member of its source pack")
        if target_level not in TARGET_LEVEL_ORDER:
            raise ValueError("effective_control.target_level is unsupported")
        if mode not in {"require", "deny"}:
            raise ValueError("effective_control.mode is unsupported")
        policy_waivers = validate_unique_strings(
            active_waiver_ids,
            "effective_control.active_waiver_ids",
        )
        risk_waivers = validate_unique_strings(
            risk_acceptance_waiver_ids,
            "effective_control.risk_acceptance_waiver_ids",
        )
        if set(policy_waivers).intersection(risk_waivers):
            raise ValueError("policy and risk-acceptance waiver ids must be disjoint")
        fields: dict[str, object] = {
            "source_pack_id": source_pack.pack_id,
            "source_pack_digest": source_pack.pack_digest,
            "control": control.to_dict(),
            "applicable": require_boolean(applicable, "effective_control.applicable"),
            "applicability_rationale": require_string(
                applicability_rationale,
                "effective_control.applicability_rationale",
            ),
            "target_level": target_level,
            "mode": mode,
            "active_waiver_ids": list(policy_waivers),
            "risk_acceptance_waiver_ids": list(risk_waivers),
            "missing_adapter_ids": list(
                validate_unique_strings(
                    missing_adapter_ids,
                    "effective_control.missing_adapter_ids",
                )
            ),
        }
        return cls(
            source_pack_id=source_pack.pack_id,
            source_pack_digest=source_pack.pack_digest,
            control=control,
            applicable=applicable,
            applicability_rationale=applicability_rationale,
            target_level=target_level,
            mode=mode,
            active_waiver_ids=tuple(cast(list[str], fields["active_waiver_ids"])),
            risk_acceptance_waiver_ids=tuple(
                cast(list[str], fields["risk_acceptance_waiver_ids"])
            ),
            missing_adapter_ids=tuple(cast(list[str], fields["missing_adapter_ids"])),
            effective_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one resolved control."""
        return {
            "source_pack_id": self.source_pack_id,
            "source_pack_digest": self.source_pack_digest,
            "control": self.control.to_dict(),
            "applicable": self.applicable,
            "applicability_rationale": self.applicability_rationale,
            "target_level": self.target_level,
            "mode": self.mode,
            "active_waiver_ids": list(self.active_waiver_ids),
            "risk_acceptance_waiver_ids": list(self.risk_acceptance_waiver_ids),
            "missing_adapter_ids": list(self.missing_adapter_ids),
            "effective_digest": self.effective_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> EffectiveControl:
        """Parse one effective control and rederive its content digest.

        Offline parse does not re-check source-pack membership; that binding is
        already sealed into the lock digest produced by :meth:`build`.
        """
        data = require_mapping(value, "effective_control")
        control = ControlDefinition.from_dict(data.get("control"))
        target_level = cast(
            TargetLevel,
            require_string(data.get("target_level"), "effective_control.target_level"),
        )
        mode = cast(ControlMode, require_string(data.get("mode"), "effective_control.mode"))
        if target_level not in TARGET_LEVEL_ORDER:
            raise ValueError("effective_control.target_level is unsupported")
        if mode not in {"require", "deny"}:
            raise ValueError("effective_control.mode is unsupported")
        policy_waivers = validate_unique_strings(
            tuple(
                require_string(item, "effective_control.active_waiver_ids[]")
                for item in _object_array(
                    data.get("active_waiver_ids"),
                    "effective_control.active_waiver_ids",
                )
            ),
            "effective_control.active_waiver_ids",
        )
        risk_waivers = validate_unique_strings(
            tuple(
                require_string(item, "effective_control.risk_acceptance_waiver_ids[]")
                for item in _object_array(
                    data.get("risk_acceptance_waiver_ids"),
                    "effective_control.risk_acceptance_waiver_ids",
                )
            ),
            "effective_control.risk_acceptance_waiver_ids",
        )
        if set(policy_waivers).intersection(risk_waivers):
            raise ValueError("policy and risk-acceptance waiver ids must be disjoint")
        missing = validate_unique_strings(
            tuple(
                require_string(item, "effective_control.missing_adapter_ids[]")
                for item in _object_array(
                    data.get("missing_adapter_ids"),
                    "effective_control.missing_adapter_ids",
                )
            ),
            "effective_control.missing_adapter_ids",
        )
        fields: dict[str, object] = {
            "source_pack_id": require_identifier(
                data.get("source_pack_id"),
                "effective_control.source_pack_id",
            ),
            "source_pack_digest": require_digest(
                data.get("source_pack_digest"),
                "effective_control.source_pack_digest",
            ),
            "control": control.to_dict(),
            "applicable": require_boolean(data.get("applicable"), "effective_control.applicable"),
            "applicability_rationale": require_string(
                data.get("applicability_rationale"),
                "effective_control.applicability_rationale",
            ),
            "target_level": target_level,
            "mode": mode,
            "active_waiver_ids": list(policy_waivers),
            "risk_acceptance_waiver_ids": list(risk_waivers),
            "missing_adapter_ids": list(missing),
        }
        effective = cls(
            source_pack_id=cast(str, fields["source_pack_id"]),
            source_pack_digest=cast(str, fields["source_pack_digest"]),
            control=control,
            applicable=cast(bool, fields["applicable"]),
            applicability_rationale=cast(str, fields["applicability_rationale"]),
            target_level=target_level,
            mode=mode,
            active_waiver_ids=tuple(policy_waivers),
            risk_acceptance_waiver_ids=tuple(risk_waivers),
            missing_adapter_ids=tuple(missing),
            effective_digest=canonical_digest(fields),
        )
        if data.get("effective_digest") != effective.effective_digest:
            raise ValueError("effective-control digest does not match its content")
        return effective


@dataclass(frozen=True)
class EffectiveProfileLock:
    """Fully resolved, contradiction-free audit input contract."""

    profile_digest: str
    intent_digest: str
    pack_digests: tuple[str, ...]
    verification_digests: tuple[str, ...]
    adapters: tuple[AdapterLock, ...]
    variables: tuple[ResolvedVariable, ...]
    controls: tuple[EffectiveControl, ...]
    warnings: tuple[PolicyContradiction, ...]
    toolchain_digest: str
    resolved_at: str
    lock_digest: str

    @classmethod
    def build(
        cls,
        *,
        profile: ProjectProfile,
        packs: tuple[StandardPack, ...],
        verifications: tuple[PackVerification, ...],
        adapters: tuple[AdapterLock, ...],
        variables: tuple[ResolvedVariable, ...],
        controls: tuple[EffectiveControl, ...],
        warnings: tuple[PolicyContradiction, ...],
        trust_store: VerificationTrustStore,
        toolchain_digest: str,
        resolved_at: str,
    ) -> EffectiveProfileLock:
        """Build a lock only after every blocking contradiction is absent."""
        if any(item.blocking for item in warnings):
            raise ValueError("effective profile lock cannot contain blocking contradictions")
        pack_ids = tuple(item.pack_id for item in packs)
        verification_packs = tuple(item.pack_digest for item in verifications)
        if len(pack_ids) != len(set(pack_ids)):
            raise ValueError("effective profile packs must have unique ids")
        if set(verification_packs) != {item.pack_digest for item in packs}:
            raise ValueError("effective profile requires one verification per pack")
        if len(verification_packs) != len(set(verification_packs)):
            raise ValueError("effective profile pack verifications must be unique and valid")
        pack_by_digest = {item.pack_digest: item for item in packs}
        if any(
            not item.valid_for(pack_by_digest[item.pack_digest], trust_store)
            for item in verifications
        ):
            raise ValueError("effective profile pack verifications must be unique and valid")
        for values, label in (
            ((item.adapter_id for item in adapters), "adapter ids"),
            ((item.variable_id for item in variables), "variable ids"),
            ((item.control.control_id for item in controls), "control ids"),
        ):
            identifiers = tuple(values)
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"effective profile {label} must be unique")
        pack_digests = {item.pack_digest for item in packs}
        if any(item.source_pack_digest not in pack_digests for item in controls):
            raise ValueError("effective control references an unlocked source pack")
        fields: dict[str, object] = {
            "schema_version": LOCK_SCHEMA_VERSION,
            "resolver_version": RESOLVER_VERSION,
            "profile_digest": profile.profile_digest,
            "intent_digest": profile.intent.intent_digest,
            "pack_digests": sorted(pack.pack_digest for pack in packs),
            "verification_digests": sorted(item.verification_digest for item in verifications),
            "adapters": [item.to_dict() for item in sorted(adapters, key=lambda x: x.adapter_id)],
            "variables": [
                item.to_dict() for item in sorted(variables, key=lambda x: x.variable_id)
            ],
            "controls": [
                item.to_dict() for item in sorted(controls, key=lambda x: x.control.versioned_id)
            ],
            "warnings": [item.to_dict() for item in warnings],
            "toolchain_digest": require_digest(toolchain_digest, "lock.toolchain_digest"),
            "resolved_at": require_utc_timestamp(resolved_at, "lock.resolved_at"),
        }
        return cls(
            profile_digest=profile.profile_digest,
            intent_digest=profile.intent.intent_digest,
            pack_digests=tuple(cast(list[str], fields["pack_digests"])),
            verification_digests=tuple(cast(list[str], fields["verification_digests"])),
            adapters=tuple(sorted(adapters, key=lambda item: item.adapter_id)),
            variables=tuple(sorted(variables, key=lambda item: item.variable_id)),
            controls=tuple(sorted(controls, key=lambda item: item.control.versioned_id)),
            warnings=warnings,
            toolchain_digest=cast(str, fields["toolchain_digest"]),
            resolved_at=cast(str, fields["resolved_at"]),
            lock_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete immutable effective-profile lock."""
        return {
            "schema_version": LOCK_SCHEMA_VERSION,
            "resolver_version": RESOLVER_VERSION,
            "profile_digest": self.profile_digest,
            "intent_digest": self.intent_digest,
            "pack_digests": list(self.pack_digests),
            "verification_digests": list(self.verification_digests),
            "adapters": [item.to_dict() for item in self.adapters],
            "variables": [item.to_dict() for item in self.variables],
            "controls": [item.to_dict() for item in self.controls],
            "warnings": [item.to_dict() for item in self.warnings],
            "toolchain_digest": self.toolchain_digest,
            "resolved_at": self.resolved_at,
            "lock_digest": self.lock_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> EffectiveProfileLock:
        """Parse one serialised lock and rederive its content digest.

        Offline parse rebinds the sealed lock content. It does not re-run pack
        signature verification or project-profile resolution; those remain the
        responsibility of :meth:`build` at lock-creation time.
        """
        data = require_mapping(value, "lock")
        if data.get("schema_version") != LOCK_SCHEMA_VERSION:
            raise ValueError("unsupported effective-profile lock schema version")
        if data.get("resolver_version") != RESOLVER_VERSION:
            raise ValueError("unsupported effective-profile resolver version")
        pack_digests = tuple(
            require_digest(item, "lock.pack_digests[]")
            for item in _object_array(data.get("pack_digests"), "lock.pack_digests")
        )
        verification_digests = tuple(
            require_digest(item, "lock.verification_digests[]")
            for item in _object_array(
                data.get("verification_digests"),
                "lock.verification_digests",
            )
        )
        adapters = tuple(
            AdapterLock.from_dict(item)
            for item in _object_array(data.get("adapters"), "lock.adapters")
        )
        variables = tuple(
            ResolvedVariable.from_dict(item)
            for item in _object_array(data.get("variables"), "lock.variables")
        )
        controls = tuple(
            EffectiveControl.from_dict(item)
            for item in _object_array(data.get("controls"), "lock.controls")
        )
        warnings = tuple(
            PolicyContradiction.from_dict(item)
            for item in _object_array(data.get("warnings"), "lock.warnings")
        )
        if any(item.blocking for item in warnings):
            raise ValueError("effective profile lock cannot contain blocking contradictions")
        for values, label in (
            ((item.adapter_id for item in adapters), "adapter ids"),
            ((item.variable_id for item in variables), "variable ids"),
            ((item.control.control_id for item in controls), "control ids"),
        ):
            identifiers = tuple(values)
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"effective profile {label} must be unique")
        pack_digest_set = set(pack_digests)
        if any(item.source_pack_digest not in pack_digest_set for item in controls):
            raise ValueError("effective control references an unlocked source pack")
        ordered_adapters = tuple(sorted(adapters, key=lambda item: item.adapter_id))
        ordered_variables = tuple(sorted(variables, key=lambda item: item.variable_id))
        ordered_controls = tuple(sorted(controls, key=lambda item: item.control.versioned_id))
        fields: dict[str, object] = {
            "schema_version": LOCK_SCHEMA_VERSION,
            "resolver_version": RESOLVER_VERSION,
            "profile_digest": require_digest(data.get("profile_digest"), "lock.profile_digest"),
            "intent_digest": require_digest(data.get("intent_digest"), "lock.intent_digest"),
            "pack_digests": sorted(pack_digests),
            "verification_digests": sorted(verification_digests),
            "adapters": [item.to_dict() for item in ordered_adapters],
            "variables": [item.to_dict() for item in ordered_variables],
            "controls": [item.to_dict() for item in ordered_controls],
            "warnings": [item.to_dict() for item in warnings],
            "toolchain_digest": require_digest(
                data.get("toolchain_digest"),
                "lock.toolchain_digest",
            ),
            "resolved_at": require_utc_timestamp(data.get("resolved_at"), "lock.resolved_at"),
        }
        lock = cls(
            profile_digest=cast(str, fields["profile_digest"]),
            intent_digest=cast(str, fields["intent_digest"]),
            pack_digests=tuple(cast(list[str], fields["pack_digests"])),
            verification_digests=tuple(cast(list[str], fields["verification_digests"])),
            adapters=ordered_adapters,
            variables=ordered_variables,
            controls=ordered_controls,
            warnings=warnings,
            toolchain_digest=cast(str, fields["toolchain_digest"]),
            resolved_at=cast(str, fields["resolved_at"]),
            lock_digest=canonical_digest(fields),
        )
        if data.get("lock_digest") != lock.lock_digest:
            raise ValueError("lock digest does not match its content")
        return lock


@dataclass(frozen=True)
class ProfileResolution:
    """Resolution result that preserves contradictions when no lock is possible."""

    profile_digest: str
    lock: EffectiveProfileLock | None
    contradictions: tuple[PolicyContradiction, ...]
    resolution_digest: str

    @property
    def ready(self) -> bool:
        """Return whether resolution produced an auditable lock."""
        return self.lock is not None and not any(item.blocking for item in self.contradictions)

    @classmethod
    def build(
        cls,
        *,
        profile_digest: str,
        lock: EffectiveProfileLock | None,
        contradictions: tuple[PolicyContradiction, ...],
    ) -> ProfileResolution:
        """Build one deterministic ready or rejected resolution result."""
        if lock is not None and any(item.blocking for item in contradictions):
            raise ValueError("blocking contradictions cannot accompany a profile lock")
        if lock is None and not any(item.blocking for item in contradictions):
            raise ValueError("missing profile lock requires a blocking contradiction")
        if lock is not None and lock.profile_digest != profile_digest:
            raise ValueError("resolution lock references a different project profile")
        fields: dict[str, object] = {
            "profile_digest": require_digest(profile_digest, "resolution.profile_digest"),
            "lock_digest": lock.lock_digest if lock else None,
            "contradictions": [item.to_dict() for item in contradictions],
        }
        return cls(
            profile_digest=profile_digest,
            lock=lock,
            contradictions=contradictions,
            resolution_digest=canonical_digest(fields),
        )
