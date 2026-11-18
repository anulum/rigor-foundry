# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Nested repository policy diagnostics
"""Collect independent diagnostics using the existing strict policy row owners."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import PurePosixPath
from typing import cast

from .audit_primitives import AUDIT_DOMAINS, canonical_digest
from .cra_policy import CRA_POLICY_SCHEMA_VERSION, CraPolicy
from .ignored_inventory import IgnoredInventoryDeclaration, parse_ignored_inventory
from .policy_models import AdapterSpec, AuditDomainSpec

PathParts = tuple[str, ...]
Row = dict[str, object]
Validator = Callable[[Row], object]


@dataclass(frozen=True, order=True)
class PolicyDiagnostic:
    """A deterministic, value-redacted defect with an exact RFC 6901 pointer."""

    pointer: str
    problem: str
    fix: str


@dataclass
class PolicyDiagnostics:
    """Accumulate independent input issues without constructing an admitted policy."""

    issues: list[PolicyDiagnostic] = field(default_factory=list)

    def add(self, location: PathParts, problem: str, fix: str) -> None:
        """Record the exact field location and a trusted static correction hint."""
        pointer = "".join("/" + part.replace("~", "~0").replace("/", "~1") for part in location)
        self.issues.append(PolicyDiagnostic(pointer, problem, fix))

    def mapping(self, value: object, location: PathParts) -> Row | None:
        """Report unusable object shapes and return a usable mapping when present."""
        if isinstance(value, dict) and all(isinstance(key, str) for key in value):
            return cast(Row, value)
        self.add(location, "Expected an object", "Supply a JSON object")
        return None

    def fields(
        self, data: Row, location: PathParts, allowed: set[str], required: set[str]
    ) -> None:
        """Point directly to unsupported and missing member names."""
        for key in sorted(data.keys() - allowed):
            self.add((*location, key), "Unexpected member", "Remove or correct the member name")
        for key in sorted(required - data.keys()):
            self.add((*location, key), "Required member is missing", "Add the required member")

    def probe(self, location: PathParts, operation: Callable[[], object], fix: str) -> bool:
        """Return a strict owner's validity and record a value-redacted diagnostic."""
        try:
            operation()
        except ValueError:
            self.add(location, "Invalid policy value", fix)
            return False
        return True

    def array_item_types(self, value: object, location: PathParts) -> bool:
        """Identify non-string entries before passing the vector to its strict owner."""
        if not isinstance(value, list):
            self.add(location, "Expected an array", "Supply a JSON array of strings")
            return False
        valid = True
        for index, item in enumerate(value):
            if not isinstance(item, str):
                self.add((*location, str(index)), "Expected a string", "Supply a JSON string")
                valid = False
        return valid


def repository_path(value: object, *, allow_root: bool = False) -> bool:
    """Accept a normalised scoped POSIX path with no platform-specific escape."""
    if not isinstance(value, str) or not value.strip():
        return False
    if value == ".":
        return allow_root
    if "\\" in value or ":" in value:
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and path.as_posix() == value


def validate_columns(
    issues: PolicyDiagnostics,
    data: Row,
    location: PathParts,
    reference: Row,
    validate: Validator,
    hints: dict[str, str],
) -> set[str]:
    """Probe editable fields through their owner and return those that failed."""
    invalid: set[str] = set()
    for key in sorted(reference.keys() & data.keys()):
        value = data[key]
        field_path = (*location, key)
        if isinstance(reference[key], list) and not issues.array_item_types(value, field_path):
            invalid.add(key)
            continue
        if not issues.probe(field_path, partial(validate, {**reference, key: value}), hints[key]):
            invalid.add(key)
    return invalid


_DOMAIN_HINTS = {
    "name": "Use one of the registered audit domain names",
    "applicability": "Use required or not-applicable",
    "rationale": "Explain the applicability decision in a non-empty string",
}
_ADAPTER_HINTS = {
    "name": "Use a non-empty display name",
    "command": "Supply at least one non-empty argv element",
    "profile": "Use an exact supported built-in adapter profile name",
    "configuration_path": "Give an exact repository-relative configuration path",
    "target_paths": "List unique, exact repository-relative targets appropriate to this profile",
    "timeout_seconds": "Use a positive integer number of seconds",
    "scope": "Use staged, full, or both",
    "working_directory": "Use a repository-relative directory or . for a built-in profile",
    "required": "Use a JSON boolean",
    "domains": "List unique registered domains covered by this adapter",
}
_IGNORED_HINTS = {
    "evidence_id": "Use a portable, unique evidence identifier",
    "path": "Use an exact repository-relative path without glob syntax",
    "capture": "Use presence, file-sha256, or directory-sha256",
}


def _field_duplicates(
    issues: PolicyDiagnostics, rows: list[object], section: str, field: str
) -> None:
    """Report each later occurrence of an identity at its indexed location."""
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict) or not isinstance(value := raw.get(field), str):
            continue
        if value in seen:
            issues.add(
                (section, str(index), field),
                "Duplicate identity",
                "Use a distinct identity or remove the duplicate row",
            )
        seen.add(value)


def _domain(issues: PolicyDiagnostics, row: Row, location: PathParts, index: int) -> None:
    """Validate every declared domain column against the real domain reader."""
    reference: Row = dict(
        AuditDomainSpec(AUDIT_DOMAINS[0], "required", "Reference applicability").to_dict()
    )
    expected = set(reference)
    issues.fields(row, location, expected, expected)
    validate_columns(
        issues,
        row,
        location,
        reference,
        lambda data: AuditDomainSpec.from_dict(data, index),
        _DOMAIN_HINTS,
    )


def _invalid_vector_item(key: str, value: str) -> bool:
    """Check an argv item, domain or path in the scope of its declared vector."""
    if key == "target_paths":
        return not repository_path(value, allow_root=True)
    if key == "domains":
        return value not in AUDIT_DOMAINS
    return not value


def _adapter_vector_issues(issues: PolicyDiagnostics, row: Row, location: PathParts) -> set[str]:
    """Report invalid vector values and later duplicates at their indices."""
    invalid: set[str] = set()
    for key in ("command", "domains", "target_paths"):
        values = row.get(key)
        if not isinstance(values, list):
            continue
        seen: set[str] = set()
        for index, item in enumerate(values):
            if not isinstance(item, str):
                continue
            field = (*location, key, str(index))
            if _invalid_vector_item(key, item):
                problem = (
                    "Invalid repository-relative target"
                    if key == "target_paths"
                    else "Invalid adapter array item"
                )
                issues.add(field, problem, _ADAPTER_HINTS[key])
                invalid.add(key)
            elif key != "command" and item in seen:
                issues.add(field, "Duplicate adapter array item", _ADAPTER_HINTS[key])
                invalid.add(key)
            seen.add(item)
        if key in invalid:
            issues.array_item_types(values, (*location, key))
    return invalid


def _adapter_path_issues(
    issues: PolicyDiagnostics, row: Row, location: PathParts
) -> frozenset[str]:
    """Isolate portable adapter path and list errors before probing scalar fields."""
    invalid = _adapter_vector_issues(issues, row, location)
    for key in ("configuration_path", "working_directory"):
        if isinstance(value := row.get(key), str) and not repository_path(
            value, allow_root=key == "working_directory"
        ):
            issues.add((*location, key), "Invalid repository-relative path", _ADAPTER_HINTS[key])
            invalid.add(key)
    return frozenset(invalid)


def _adapter(issues: PolicyDiagnostics, row: Row, location: PathParts, index: int) -> None:
    """Validate both adapter grammars, then evaluate their complete declared coupling."""
    if "profile" in row:
        baseline: Row = {
            "name": "reference",
            "profile": "semgrep-local-json-v1",
            "configuration_path": "rules.yml",
            "target_paths": ["src"],
            "timeout_seconds": 30,
            "scope": "both",
            "working_directory": ".",
            "required": True,
        }
        required = set(baseline)
    else:
        baseline = AdapterSpec("reference", ("tool",), 30, "both", ".", True, ()).to_dict()
        required = {"name", "command"}
    before = len(issues.issues)
    issues.fields(row, location, set(baseline), required)
    allowed = {key: row[key] for key in row.keys() & baseline.keys()}
    invalid_paths = _adapter_path_issues(issues, allowed, location)
    checked = {key: value for key, value in allowed.items() if key not in invalid_paths}
    validate = partial(AdapterSpec.from_dict, index=index)
    invalid = validate_columns(issues, checked, location, baseline, validate, _ADAPTER_HINTS)
    valid = checked.keys() - invalid
    if {"profile", "target_paths"} <= valid:
        profile_fields = {
            key: checked[key]
            for key in ("profile", "configuration_path", "target_paths")
            if key in valid
        }
        issues.probe(
            (*location, "target_paths"),
            partial(validate, {**baseline, **profile_fields}),
            "Make the selected adapter profile and target declarations compatible",
        )
    if len(issues.issues) == before:
        issues.probe(
            (*location, "target_paths") if "profile" in row else location,
            lambda: AdapterSpec.from_dict(row, index),
            "Make the selected adapter, configuration and target declarations compatible",
        )


def _ignored(issues: PolicyDiagnostics, row: Row, location: PathParts, index: int) -> None:
    """Reuse the ignored evidence declaration owner for each editable member."""
    baseline: Row = dict(
        IgnoredInventoryDeclaration("reference", ".rigor/evidence", "presence").to_dict()
    )
    issues.fields(row, location, set(baseline), set(baseline))
    checked = row
    if isinstance(path := row.get("path"), str) and not repository_path(path):
        issues.add((*location, "path"), "Invalid repository-relative path", _IGNORED_HINTS["path"])
        checked = {key: value for key, value in row.items() if key != "path"}
    validate_columns(
        issues,
        checked,
        location,
        baseline,
        lambda data: IgnoredInventoryDeclaration.from_dict(data, index),
        _IGNORED_HINTS,
    )


_ROW_CHECKS = {
    "audit_domains": _domain,
    "native_audits": _adapter,
    "ignored_inventory": _ignored,
}


def validate_rows(issues: PolicyDiagnostics, section: str, raw: object) -> None:
    """Diagnose all members of one known policy array and its row relationships."""
    if not isinstance(raw, list):
        issues.add((section,), "Expected an array", "Supply a JSON array of objects")
        return
    rows = cast(list[object], raw)
    before = len(issues.issues)
    for index, item in enumerate(rows):
        location = (section, str(index))
        row = issues.mapping(item, location)
        if row is not None:
            _ROW_CHECKS[section](issues, row, location, index)
    if section == "audit_domains":
        _field_duplicates(issues, rows, section, "name")
    if section == "ignored_inventory":
        _field_duplicates(issues, rows, section, "evidence_id")
        _field_duplicates(issues, rows, section, "path")
        if len(issues.issues) == before:
            issues.probe(
                (section,),
                lambda: parse_ignored_inventory(raw),
                "Sort ignored declarations by evidence_id, path, and capture",
            )


_CRA_HINTS = {
    "schema_version": f"Use CRA policy schema {CRA_POLICY_SCHEMA_VERSION}",
    "applicability": "Use required or not-applicable",
    "rationale": "Explain the applicability decision in a non-empty string",
    "product_key": "Use a portable product identifier when required, otherwise null",
    "disclosure_policy_path": "Use a repository-relative policy path when required, otherwise null",
    "state_evidence_id": "Use a portable ignored-evidence identifier when required, otherwise null",
    "cra_policy_digest": "Recompute the digest after correcting the CRA policy body",
}


def _with_cra_digest(value: Row) -> CraPolicy:
    """Validate a single CRA value while rebinding the temporary digest."""
    return CraPolicy.from_dict({**value, "cra_policy_digest": canonical_digest(value)})


def validate_cra(issues: PolicyDiagnostics, raw: object) -> None:
    """Diagnose the CRA block and check the digest of its actual complete body."""
    row = issues.mapping(raw, ("cra",))
    if row is None:
        return
    required = row.get("applicability") == "required"
    baseline = CraPolicy.build(
        applicability="required" if required else "not-applicable",
        rationale="Reference applicability",
        product_key="reference" if required else None,
        disclosure_policy_path="SECURITY.md" if required else None,
        state_evidence_id="cra-state" if required else None,
    ).to_dict()
    before = len(issues.issues)
    issues.fields(row, ("cra",), set(baseline), set(baseline))
    body = {key: item for key, item in baseline.items() if key != "cra_policy_digest"}
    checked = row
    if (
        required
        and isinstance(path := row.get("disclosure_policy_path"), str)
        and not repository_path(path)
    ):
        issues.add(
            ("cra", "disclosure_policy_path"),
            "Invalid repository-relative path",
            _CRA_HINTS["disclosure_policy_path"],
        )
        checked = {key: value for key, value in row.items() if key != "disclosure_policy_path"}
    validate_columns(issues, checked, ("cra",), body, _with_cra_digest, _CRA_HINTS)
    if len(issues.issues) == before:
        issues.probe(
            ("cra", "cra_policy_digest"),
            lambda: CraPolicy.from_dict(row),
            _CRA_HINTS["cra_policy_digest"],
        )
