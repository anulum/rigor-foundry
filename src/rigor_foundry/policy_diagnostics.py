# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Repository policy diagnostics
"""Diagnose policy fields and contradictions without installing policy authority."""

from __future__ import annotations

from typing import cast

from .audit_primitives import (
    LEGACY_POLICY_FIELDS,
    LEGACY_POLICY_SCHEMA_VERSION,
    POLICY_FIELDS,
    POLICY_SCHEMA_VERSION,
)
from .policy_diagnostic_rows import (
    PolicyDiagnostic,
    PolicyDiagnostics,
    Row,
    repository_path,
    validate_columns,
    validate_cra,
    validate_rows,
)
from .policy_models import AuditPolicy

_SIMPLE_HINTS = {
    "source_line_threshold": "Set a positive integer source line limit",
    "test_line_threshold": "Set a positive integer test line limit",
    "source_roots": "List repository-relative source roots",
    "test_roots": "List repository-relative test roots",
    "production_packages": "List package names as strings",
    "module_size_registries": "List repository-relative module registry files",
    "canonical_todo": "Use a normalised repository-relative TODO path",
    "review_ledger": "Use a normalised repository-relative review ledger path",
    "enforcement_mode": "Use observe, ratchet, or zero",
    "maturity_policy_digest": "Use a lowercase 64-digit SHA-256 digest or null in observe mode",
}

_ROOT_SCOPES = ("source_roots", "test_roots", "module_size_registries")
_ROW_SECTIONS = ("audit_domains", "native_audits", "ignored_inventory")


def _check_scopes(issues: PolicyDiagnostics, data: Row) -> frozenset[str]:
    """Diagnose portable path scope with array indices and no path resolution."""
    invalid: set[str] = set()
    for key in ("canonical_todo", "review_ledger"):
        if key in data and not repository_path(data[key]):
            issues.add((key,), "Invalid repository-relative path", _SIMPLE_HINTS[key])
            invalid.add(key)
    for section in _ROOT_SCOPES:
        value = data.get(section)
        if isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, str) and not repository_path(
                    item, allow_root=section != "module_size_registries"
                ):
                    issues.add(
                        (section, str(index)),
                        "Invalid repository-relative path",
                        _SIMPLE_HINTS[section],
                    )
    return frozenset(invalid)


def _validate_simple(issues: PolicyDiagnostics, data: Row) -> None:
    """Isolate scalar defects without borrowing authority from valid defaults."""
    invalid_paths = _check_scopes(issues, data)
    reference = AuditPolicy().to_dict()
    simple = {key: reference[key] for key in _SIMPLE_HINTS if key not in invalid_paths}

    def validate(values: Row) -> AuditPolicy:
        """Use a reference digest only to isolate enforcement-mode grammar."""
        if values["enforcement_mode"] in ("ratchet", "zero"):
            values["maturity_policy_digest"] = "0" * 64
        return AuditPolicy.from_dict({**reference, **values})

    validate_columns(issues, data, (), simple, validate, _SIMPLE_HINTS)
    if data.get("enforcement_mode") in ("ratchet", "zero") and (
        "maturity_policy_digest" in data and data["maturity_policy_digest"] is None
    ):
        issues.add(
            ("maturity_policy_digest",),
            "Enforcement mode requires a maturity policy digest",
            "Bind a reviewed maturity policy digest or use observe mode",
        )


def _check_cra_binding(issues: PolicyDiagnostics, data: Row) -> None:
    """Locate an unresolved or contradictory CRA ignored-evidence declaration."""
    raw_cra = data.get("cra")
    raw_ignored = data.get("ignored_inventory")
    if not isinstance(raw_cra, dict) or not isinstance(raw_ignored, list):
        return
    cra = cast(Row, raw_cra)
    evidence = cra.get("state_evidence_id")
    if cra.get("applicability") != "required" or not isinstance(evidence, str):
        return
    matches = [
        (index, cast(Row, row))
        for index, row in enumerate(raw_ignored)
        if isinstance(row, dict) and row.get("evidence_id") == evidence
    ]
    if len(matches) != 1:
        issues.add(
            ("cra", "state_evidence_id"),
            "Required CRA state does not name one ignored declaration",
            "Bind the identifier to one .rigor/cra directory-sha256 declaration",
        )
        return
    index, row = matches[0]
    for key, expected in (("path", ".rigor/cra"), ("capture", "directory-sha256")):
        if key in row and row[key] != expected:
            issues.add(
                ("ignored_inventory", str(index), key),
                "Declaration contradicts required CRA state",
                f"Set this member to {expected}",
            )


def diagnose_repository_policy(value: object) -> tuple[PolicyDiagnostic, ...]:
    """Return all independently diagnosable policy defects in pointer order.

    The existing runtime policy owner remains the final validity check. Failed
    shapes are isolated so a damaged section cannot suppress valid diagnoses
    in other sections. No diagnostic returns an operational policy or grant.
    """
    issues = PolicyDiagnostics()
    data = issues.mapping(value, ())
    if data is None:
        return tuple(issues.issues)
    version = data.get("schema_version")
    if "schema_version" in data and version not in (
        LEGACY_POLICY_SCHEMA_VERSION,
        POLICY_SCHEMA_VERSION,
    ):
        issues.add(
            ("schema_version",),
            "Unsupported repository policy schema",
            "Use repository policy schema 1.3 or 1.4",
        )
    if version == POLICY_SCHEMA_VERSION:
        expected = set(POLICY_FIELDS)
    else:
        expected = set(LEGACY_POLICY_FIELDS)
    issues.fields(data, (), expected, expected)
    _validate_simple(issues, data)
    for section in _ROW_SECTIONS:
        if section in data:
            validate_rows(issues, section, data[section])
    if "cra" in data:
        validate_cra(issues, data["cra"])
        _check_cra_binding(issues, data)
    if not issues.issues:
        issues.probe(
            (), lambda: AuditPolicy.from_dict(data), "Review the complete policy contract"
        )
    return tuple(sorted(issues.issues))
