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
    StableApiBinding,
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
    assert public_api_contract_errors(rigor_foundry.__all__, vars(rigor_foundry)) == ()
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
    assert set(manifest["stable_bindings"]) == STABLE_PUBLIC_API
    assert manifest["provisional"] == sorted(PROVISIONAL_PUBLIC_API)
    assert json.loads(json.dumps(manifest, allow_nan=False, sort_keys=True)) == manifest


def test_contract_rejects_unclassified_overlap_and_unknown_names() -> None:
    """Compatibility edits cannot silently lose or multiply classifications."""
    assert public_api_contract_errors(
        ("stable",),
        {"stable": "value"},
        stable=frozenset(),
        provisional=frozenset(),
        stable_bindings={},
    ) == ("unclassified top-level exports: stable",)
    assert public_api_contract_errors(
        ("stable",),
        {"stable": "value"},
        stable=frozenset({"stable"}),
        provisional=frozenset({"stable"}),
        stable_bindings={"stable": StableApiBinding("str", None, None)},
    ) == ("API stability classifications overlap: stable",)
    assert public_api_contract_errors(
        ("stable",),
        {"stable": "value"},
        stable=frozenset({"stable", "absent"}),
        provisional=frozenset(),
        stable_bindings={
            "absent": StableApiBinding("str", None, None),
            "stable": StableApiBinding("str", None, None),
        },
    ) == ("classified names are not exported: absent",)


def test_contract_rejects_incompatible_stable_export_rebinding() -> None:
    """A stable name cannot retain its spelling while changing runtime identity."""
    bindings = dict(vars(rigor_foundry))
    bindings["AuditPolicy"] = 7
    assert public_api_contract_errors(rigor_foundry.__all__, bindings) == (
        "AuditPolicy: stable export kind changed",
    )


def test_contract_rejects_missing_and_malformed_binding_records() -> None:
    """Binding metadata cannot be absent, extra, malformed, or identity-drifted."""

    class Replacement:
        pass

    missing = public_api_contract_errors(
        ("value",),
        {},
        stable=frozenset(),
        provisional=frozenset({"value"}),
        stable_bindings={},
    )
    assert missing == ("top-level export bindings are missing: value",)

    assert "stable binding contracts are missing: value" in public_api_contract_errors(
        ("value",),
        {"value": "value"},
        stable=frozenset({"value"}),
        provisional=frozenset(),
        stable_bindings={},
    )
    assert "stable binding contracts are unknown: extra" in public_api_contract_errors(
        (),
        {},
        stable=frozenset(),
        provisional=frozenset(),
        stable_bindings={"extra": StableApiBinding("str", None, None)},
    )
    assert "value: stable binding kind is invalid" in public_api_contract_errors(
        ("value",),
        {"value": "value"},
        stable=frozenset({"value"}),
        provisional=frozenset(),
        stable_bindings={"value": StableApiBinding("invalid", None, None)},
    )
    module_errors = public_api_contract_errors(
        ("value",),
        {"value": Replacement},
        stable=frozenset({"value"}),
        provisional=frozenset(),
        stable_bindings={"value": StableApiBinding("class", "wrong.module", "wrong")},
    )
    assert "value: stable export module changed" in module_errors
    assert "value: stable export qualified name changed" in module_errors


def test_deprecations_require_export_replacement_and_two_minor_releases() -> None:
    """Direct construction cannot bypass the documented deprecation window."""
    too_soon = ApiDeprecation("old", "1.2.0", "1.3.0", "new")
    errors = public_api_contract_errors(
        ("old", "new"),
        {"new": "new", "old": "old"},
        stable=frozenset({"new"}),
        provisional=frozenset(),
        deprecated=(too_soon,),
        stable_bindings={"new": StableApiBinding("str", None, None)},
    )
    assert errors == ("old: removal_not_before must preserve at least two minor releases",)

    invalid = ApiDeprecation("old", "1.2.0-rc.1", "2.0.0", "missing")
    errors = public_api_contract_errors(
        ("old",),
        {"old": "old"},
        stable=frozenset(),
        provisional=frozenset(),
        deprecated=(invalid,),
        stable_bindings={},
    )
    assert "old: deprecated_in must be a final semantic version" in errors
    assert "old: replacement is not a classified top-level export" in errors


def test_contract_rejects_duplicate_and_malformed_lifecycle_records() -> None:
    """Every remaining validation branch rejects a concrete ambiguous contract."""
    duplicate = ApiDeprecation("old", "1.0.0", "1.2.0", "new")
    errors = public_api_contract_errors(
        ("old", "old", "new"),
        {"new": "new", "old": "old"},
        stable=frozenset({"new", "not valid"}),
        provisional=frozenset(),
        deprecated=(duplicate, duplicate),
        stable_bindings={
            "new": StableApiBinding("str", None, None),
            "not valid": StableApiBinding("str", None, None),
        },
    )
    assert "top-level exports must be unique" in errors
    assert "deprecated API names must be unique" in errors
    assert "classified API names must be Python identifiers: not valid" in errors

    malformed = ApiDeprecation("not valid", "latest", "1.0.0", "not valid")
    errors = public_api_contract_errors(
        ("not valid",),
        {"not valid": "old"},
        stable=frozenset(),
        provisional=frozenset(),
        deprecated=(malformed,),
        stable_bindings={},
    )
    assert "not valid: deprecated API name must be a Python identifier" in errors
    assert "not valid: deprecated_in must be a semantic version" in errors


def test_contract_accepts_lead_time_and_rejects_reverse_or_self_replacement() -> None:
    """Same-major lead time and major-version removal remain explicit boundaries."""
    for removal in ("1.4.0", "2.0.0"):
        assert (
            public_api_contract_errors(
                ("old", "new"),
                {"new": "new", "old": "old"},
                stable=frozenset({"new"}),
                provisional=frozenset(),
                deprecated=(ApiDeprecation("old", "1.2.0", removal, "new"),),
                stable_bindings={"new": StableApiBinding("str", None, None)},
            )
            == ()
        )

    errors = public_api_contract_errors(
        ("old",),
        {"old": "old"},
        stable=frozenset(),
        provisional=frozenset(),
        deprecated=(ApiDeprecation("old", "1.2.0", "1.2.0", "old"),),
        stable_bindings={},
    )
    assert "old: removal_not_before must follow deprecated_in" in errors
    assert "old: deprecated API replacement must differ from its name" in errors
