# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — public API compatibility tests
"""Ratchet exact exports, stability classes, and deprecation lead time."""

from __future__ import annotations

import json

import rigor_foundry
from rigor_foundry.api_stability import (
    API_STABILITY_SCHEMA_VERSION,
    DEPRECATED_PUBLIC_API,
    PROVISIONAL_PUBLIC_API,
    STABLE_PUBLIC_API,
    ApiDeprecation,
    public_api_contract_errors,
    public_api_manifest,
)

_EXPECTED_STABLE_API = frozenset(
    {
        "AuditPolicy",
        "AuditReport",
        "Candidate",
        "GitTrustPolicy",
        "ReviewRecord",
        "__version__",
        "report_markdown",
        "review_templates",
        "scan_repository",
        "validate_reviews",
    }
)


def test_exact_top_level_exports_have_one_stability_class() -> None:
    """Every current ``__all__`` name is importable and classified exactly once."""
    assert STABLE_PUBLIC_API == _EXPECTED_STABLE_API
    assert public_api_contract_errors(rigor_foundry.__all__) == ()
    assert set(rigor_foundry.__all__) == (
        STABLE_PUBLIC_API | PROVISIONAL_PUBLIC_API | {item.name for item in DEPRECATED_PUBLIC_API}
    )
    for name in rigor_foundry.__all__:
        assert getattr(rigor_foundry, name) is not None


def test_public_api_manifest_is_deterministic_machine_readable_json() -> None:
    """Consumers can persist an ordered stability inventory without imports-by-guess."""
    manifest = public_api_manifest()
    assert manifest["schema_version"] == API_STABILITY_SCHEMA_VERSION
    assert manifest["stable"] == sorted(STABLE_PUBLIC_API)
    assert manifest["provisional"] == sorted(PROVISIONAL_PUBLIC_API)
    assert json.loads(json.dumps(manifest, allow_nan=False, sort_keys=True)) == manifest


def test_contract_rejects_unclassified_overlap_and_unknown_names() -> None:
    """Compatibility edits cannot silently lose or multiply classifications."""
    assert public_api_contract_errors(
        ("stable",), stable=frozenset(), provisional=frozenset()
    ) == ("unclassified top-level exports: stable",)
    assert public_api_contract_errors(
        ("stable",),
        stable=frozenset({"stable"}),
        provisional=frozenset({"stable"}),
    ) == ("API stability classifications overlap: stable",)
    assert public_api_contract_errors(
        ("stable",),
        stable=frozenset({"stable", "absent"}),
        provisional=frozenset(),
    ) == ("classified names are not exported: absent",)


def test_deprecations_require_export_replacement_and_two_minor_releases() -> None:
    """Direct construction cannot bypass the documented deprecation window."""
    too_soon = ApiDeprecation("old", "1.2.0", "1.3.0", "new")
    errors = public_api_contract_errors(
        ("old", "new"),
        stable=frozenset({"new"}),
        provisional=frozenset(),
        deprecated=(too_soon,),
    )
    assert errors == ("old: removal_not_before must preserve at least two minor releases",)

    invalid = ApiDeprecation("old", "1.2.0-rc.1", "2.0.0", "missing")
    errors = public_api_contract_errors(
        ("old",),
        stable=frozenset(),
        provisional=frozenset(),
        deprecated=(invalid,),
    )
    assert "old: deprecated_in must be a final semantic version" in errors
    assert "old: replacement is not a classified top-level export" in errors


def test_contract_rejects_duplicate_and_malformed_lifecycle_records() -> None:
    """Every remaining validation branch rejects a concrete ambiguous contract."""
    duplicate = ApiDeprecation("old", "1.0.0", "1.2.0", "new")
    errors = public_api_contract_errors(
        ("old", "old", "new"),
        stable=frozenset({"new", "not valid"}),
        provisional=frozenset(),
        deprecated=(duplicate, duplicate),
    )
    assert "top-level exports must be unique" in errors
    assert "deprecated API names must be unique" in errors
    assert "classified API names must be Python identifiers: not valid" in errors

    malformed = ApiDeprecation("not valid", "latest", "1.0.0", "not valid")
    errors = public_api_contract_errors(
        ("not valid",),
        stable=frozenset(),
        provisional=frozenset(),
        deprecated=(malformed,),
    )
    assert "not valid: deprecated API name must be a Python identifier" in errors
    assert "not valid: deprecated_in must be a semantic version" in errors


def test_contract_accepts_lead_time_and_rejects_reverse_or_self_replacement() -> None:
    """Same-major lead time and major-version removal remain explicit boundaries."""
    for removal in ("1.4.0", "2.0.0"):
        assert (
            public_api_contract_errors(
                ("old", "new"),
                stable=frozenset({"new"}),
                provisional=frozenset(),
                deprecated=(ApiDeprecation("old", "1.2.0", removal, "new"),),
            )
            == ()
        )

    errors = public_api_contract_errors(
        ("old",),
        stable=frozenset(),
        provisional=frozenset(),
        deprecated=(ApiDeprecation("old", "1.2.0", "1.2.0", "old"),),
    )
    assert "old: removal_not_before must follow deprecated_in" in errors
    assert "old: deprecated API replacement must differ from its name" in errors
