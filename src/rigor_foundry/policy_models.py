# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository audit policy records
"""Define strict repository policy, audit-domain, and native-adapter records."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .audit_primitives import (
    AUDIT_DOMAINS,
    POLICY_FIELDS,
    POLICY_SCHEMA_VERSION,
    AdapterScope,
    DomainApplicability,
    EnforcementMode,
    _integer,
    _mapping,
    _string,
    _string_tuple,
    canonical_digest,
)
from .ignored_inventory import IgnoredInventoryDeclaration, parse_ignored_inventory


@dataclass(frozen=True)
class AuditDomainSpec:
    """Repository decision for one mandatory audit domain."""

    name: str
    applicability: DomainApplicability
    rationale: str

    def to_dict(self) -> dict[str, str]:
        """Serialise one domain decision."""
        return {
            "name": self.name,
            "applicability": self.applicability,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, value: object, index: int) -> AuditDomainSpec:
        """Parse one repository audit-domain decision."""
        data = _mapping(value, f"audit_domains[{index}]")
        name = _string(data.get("name"), f"audit_domains[{index}].name")
        if name not in AUDIT_DOMAINS:
            raise ValueError(f"audit_domains[{index}].name is unsupported")
        applicability = _string(
            data.get("applicability"),
            f"audit_domains[{index}].applicability",
        )
        if applicability not in {"required", "not-applicable"}:
            raise ValueError(f"audit_domains[{index}].applicability is unsupported")
        return cls(
            name=name,
            applicability=cast(DomainApplicability, applicability),
            rationale=_string(data.get("rationale"), f"audit_domains[{index}].rationale"),
        )


@dataclass(frozen=True)
class AdapterSpec:
    """One bounded repository-native argv audit command and its domain coverage."""

    name: str
    command: tuple[str, ...]
    timeout_seconds: int
    scope: AdapterScope
    working_directory: str
    required: bool
    domains: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialise one adapter specification."""
        return {
            "name": self.name,
            "command": list(self.command),
            "timeout_seconds": self.timeout_seconds,
            "scope": self.scope,
            "working_directory": self.working_directory,
            "required": self.required,
            "domains": list(self.domains),
        }

    @classmethod
    def from_dict(cls, value: object, index: int) -> AdapterSpec:
        """Parse one repository-native adapter specification."""
        data = _mapping(value, f"native_audits[{index}]")
        command = _string_tuple(data.get("command"), f"native_audits[{index}].command")
        if not command or any(not item for item in command):
            raise ValueError(f"native_audits[{index}].command must be non-empty argv")
        scope = _string(data.get("scope", "both"), f"native_audits[{index}].scope")
        if scope not in {"staged", "full", "both"}:
            raise ValueError(f"native_audits[{index}].scope is unsupported")
        required = data.get("required", True)
        if not isinstance(required, bool):
            raise ValueError(f"native_audits[{index}].required must be boolean")
        working_directory = _string(
            data.get("working_directory", "."),
            f"native_audits[{index}].working_directory",
        )
        working_path = Path(working_directory)
        if working_path.is_absolute() or ".." in working_path.parts:
            raise ValueError(
                f"native_audits[{index}].working_directory must be repository-relative"
            )
        domains = _string_tuple(data.get("domains", []), f"native_audits[{index}].domains")
        unknown_domains = sorted(set(domains).difference(AUDIT_DOMAINS))
        if unknown_domains:
            raise ValueError(
                f"native_audits[{index}].domains contains unsupported values: "
                + ", ".join(unknown_domains)
            )
        if len(domains) != len(set(domains)):
            raise ValueError(f"native_audits[{index}].domains must be unique")
        return cls(
            name=_string(data.get("name"), f"native_audits[{index}].name"),
            command=command,
            timeout_seconds=_integer(
                data.get("timeout_seconds", 300),
                f"native_audits[{index}].timeout_seconds",
                minimum=1,
            ),
            scope=cast(AdapterScope, scope),
            working_directory=working_directory,
            required=required,
            domains=domains,
        )


@dataclass(frozen=True)
class AuditPolicy:
    """Repository-local roots, thresholds, enforcement, domains, and native audits."""

    source_line_threshold: int = 1000
    test_line_threshold: int = 1000
    source_roots: tuple[str, ...] = ("src", "lib", "tools", "scripts")
    test_roots: tuple[str, ...] = ("tests", "test")
    production_packages: tuple[str, ...] = ()
    module_size_registries: tuple[str, ...] = ()
    canonical_todo: str = ".rigor/TODO.md"
    review_ledger: str = ".rigor/reviews.json"
    enforcement_mode: EnforcementMode = "observe"
    maturity_policy_digest: str | None = None
    audit_domains: tuple[AuditDomainSpec, ...] = ()
    native_audits: tuple[AdapterSpec, ...] = ()
    ignored_inventory: tuple[IgnoredInventoryDeclaration, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialise the policy deterministically."""
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "source_line_threshold": self.source_line_threshold,
            "test_line_threshold": self.test_line_threshold,
            "source_roots": list(self.source_roots),
            "test_roots": list(self.test_roots),
            "production_packages": list(self.production_packages),
            "module_size_registries": list(self.module_size_registries),
            "canonical_todo": self.canonical_todo,
            "review_ledger": self.review_ledger,
            "enforcement_mode": self.enforcement_mode,
            "maturity_policy_digest": self.maturity_policy_digest,
            "audit_domains": [domain.to_dict() for domain in self.audit_domains],
            "native_audits": [adapter.to_dict() for adapter in self.native_audits],
            "ignored_inventory": [item.to_dict() for item in self.ignored_inventory],
        }

    @property
    def policy_digest(self) -> str:
        """Return the canonical identity of this complete policy."""
        return canonical_digest(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> AuditPolicy:
        """Parse and validate a policy mapping."""
        data = _mapping(value, "policy")
        if frozenset(data) != POLICY_FIELDS:
            raise ValueError("repository audit-policy fields do not match schema")
        if data.get("schema_version") != POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported repository audit-policy schema version")
        mode = _string(data.get("enforcement_mode", "observe"), "enforcement_mode")
        if mode not in {"observe", "ratchet", "zero"}:
            raise ValueError("enforcement_mode is unsupported")
        raw_maturity_policy_digest = data.get("maturity_policy_digest")
        maturity_policy_digest = (
            None
            if raw_maturity_policy_digest is None
            else _string(raw_maturity_policy_digest, "maturity_policy_digest")
        )
        if maturity_policy_digest is not None and (
            len(maturity_policy_digest) != 64
            or any(character not in "0123456789abcdef" for character in maturity_policy_digest)
        ):
            raise ValueError("maturity_policy_digest must be a lowercase hexadecimal digest")
        if mode != "observe" and maturity_policy_digest is None:
            raise ValueError("ratchet and zero policy require maturity_policy_digest")
        raw_adapters = data.get("native_audits", [])
        if not isinstance(raw_adapters, list):
            raise ValueError("native_audits must be an array")
        raw_domains = data.get("audit_domains", [])
        if not isinstance(raw_domains, list):
            raise ValueError("audit_domains must be an array")
        audit_domains = tuple(
            AuditDomainSpec.from_dict(item, index) for index, item in enumerate(raw_domains)
        )
        domain_names = tuple(domain.name for domain in audit_domains)
        if len(domain_names) != len(set(domain_names)):
            raise ValueError("audit_domains names must be unique")
        canonical_todo = _string(
            data.get("canonical_todo", ".rigor/TODO.md"),
            "canonical_todo",
        )
        review_ledger = _string(
            data.get("review_ledger", ".rigor/reviews.json"),
            "review_ledger",
        )
        for field, path_text in (
            ("canonical_todo", canonical_todo),
            ("review_ledger", review_ledger),
        ):
            path = Path(path_text)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"{field} must be repository-relative")
        return cls(
            source_line_threshold=_integer(
                data.get("source_line_threshold", 1000),
                "source_line_threshold",
                minimum=1,
            ),
            test_line_threshold=_integer(
                data.get("test_line_threshold", 1000),
                "test_line_threshold",
                minimum=1,
            ),
            source_roots=_string_tuple(
                data.get("source_roots", ["src", "lib", "tools", "scripts"]),
                "source_roots",
            ),
            test_roots=_string_tuple(
                data.get("test_roots", ["tests", "test"]),
                "test_roots",
            ),
            production_packages=_string_tuple(
                data.get("production_packages", []),
                "production_packages",
            ),
            module_size_registries=_string_tuple(
                data.get("module_size_registries", []),
                "module_size_registries",
            ),
            canonical_todo=canonical_todo,
            review_ledger=review_ledger,
            enforcement_mode=cast(EnforcementMode, mode),
            maturity_policy_digest=maturity_policy_digest,
            audit_domains=audit_domains,
            native_audits=tuple(
                AdapterSpec.from_dict(item, index) for index, item in enumerate(raw_adapters)
            ),
            ignored_inventory=parse_ignored_inventory(data.get("ignored_inventory", [])),
        )

    @classmethod
    def from_path(cls, path: Path) -> AuditPolicy:
        """Read a policy from a UTF-8 JSON file."""
        try:
            return cls.from_json(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            raise ValueError(f"cannot read audit policy {path}") from exc

    @classmethod
    def from_json(cls, text: str) -> AuditPolicy:
        """Parse a policy from already bounded, provenance-checked UTF-8 text."""
        try:
            return cls.from_dict(json.loads(text))
        except json.JSONDecodeError as exc:
            raise ValueError("cannot parse audit policy JSON") from exc


# Preserve the established import and pickle identity while ``models`` re-exports
# these records from their smaller cohesive implementation owner.
AdapterSpec.__module__ = "rigor_foundry.models"
AuditDomainSpec.__module__ = "rigor_foundry.models"
AuditPolicy.__module__ = "rigor_foundry.models"
