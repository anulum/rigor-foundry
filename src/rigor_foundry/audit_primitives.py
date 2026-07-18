# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository-audit protocol primitives
"""Provide canonical values and strict validators for audit records."""

from __future__ import annotations

import hashlib
import json
from typing import Literal, cast

REPORT_SCHEMA_VERSION = "1.3"
REVIEW_SCHEMA_VERSION = "1.0"
SCHEMA_VERSION = REPORT_SCHEMA_VERSION
POLICY_SCHEMA_VERSION = "1.3"
SCANNER_VERSION = "0.3.0"
POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "source_line_threshold",
        "test_line_threshold",
        "source_roots",
        "test_roots",
        "production_packages",
        "module_size_registries",
        "canonical_todo",
        "review_ledger",
        "enforcement_mode",
        "maturity_policy_digest",
        "audit_domains",
        "native_audits",
        "ignored_inventory",
    }
)

Category = Literal[
    "test-authenticity",
    "architecture",
    "godfile",
    "governance",
    "application-security",
    "reliability",
    "supply-chain",
    "container",
    "data-privacy",
]
Confidence = Literal["low", "medium", "high"]
Decision = Literal["valid", "invalid", "accepted-boundary", "needs-evidence"]
Severity = Literal["P0", "P1", "P2", "P3", "P4"]
EnforcementMode = Literal["observe", "ratchet", "zero"]
AdapterScope = Literal["staged", "full", "both"]
DomainApplicability = Literal["required", "not-applicable"]

AUDIT_DOMAINS: tuple[str, ...] = (
    "test-authenticity",
    "architecture-and-wiring",
    "godfile-responsibility",
    "application-security",
    "supply-chain",
    "api-abi-schema-compatibility",
    "scientific-numerical-correctness",
    "reliability-and-concurrency",
    "performance-and-reproducibility",
    "data-and-privacy",
    "operations-and-observability",
    "packaging-deployment-iac",
    "documentation-claims-ip",
    "ownership-and-maintenance",
)


def _canonical_json(value: object) -> str:
    """Return deterministic compact JSON for identifiers and digests."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256(value: object) -> str:
    """Return the SHA-256 digest of one canonical JSON value."""
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _mapping(value: object, field: str) -> dict[str, object]:
    """Return ``value`` as a string-keyed mapping or reject it."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{field} must be an object with string keys")
    return cast(dict[str, object], value)


def _string(value: object, field: str, *, allow_empty: bool = False) -> str:
    """Return one validated string field."""
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    """Return one validated integer field."""
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}")
    return value


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    """Return one validated string-array field."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a string array")
    return tuple(cast(list[str], value))


def canonical_digest(value: object) -> str:
    """Return the canonical SHA-256 used by audit protocol records."""
    return _sha256(value)


def require_mapping(value: object, field: str) -> dict[str, object]:
    """Expose strict mapping validation to sibling protocol modules."""
    return _mapping(value, field)


def require_string(value: object, field: str, *, allow_empty: bool = False) -> str:
    """Expose strict string validation to sibling protocol modules."""
    return _string(value, field, allow_empty=allow_empty)


def require_integer(value: object, field: str, *, minimum: int = 0) -> int:
    """Expose strict integer validation to sibling protocol modules."""
    return _integer(value, field, minimum=minimum)


def require_string_tuple(value: object, field: str) -> tuple[str, ...]:
    """Expose strict string-array validation to sibling protocol modules."""
    return _string_tuple(value, field)


def require_exact_fields(
    value: dict[str, object],
    expected: frozenset[str],
    field: str,
) -> None:
    """Reject missing or unknown fields in one versioned protocol object."""
    if frozenset(value) != expected:
        raise ValueError(f"{field} fields do not match the schema")
