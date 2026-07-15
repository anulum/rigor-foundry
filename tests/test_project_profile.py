# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-profile tests
"""Verify complete desired-state profiles, exact pack pins, and waivers."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import cast

import pytest

from rigor_foundry.model_primitives import (
    VariableAssignment,
    VariableConstraints,
    VariableDefinition,
)
from rigor_foundry.project_profile import (
    REQUIRED_INTENT_CATEGORIES,
    ApplicabilityDecision,
    ControlOverlay,
    ExceptionWaiver,
    PackSelection,
    ProjectIntent,
    ProjectProfile,
    RequirementBinding,
    RequirementCategory,
)

DIGEST = "a" * 64


def intent() -> ProjectIntent:
    """Return a project intent that explicitly covers every mandatory category."""
    requirements = tuple(
        RequirementBinding.build(
            cast(RequirementCategory, category),
            (f"verified requirement for {category}",),
        )
        for category in sorted(REQUIRED_INTENT_CATEGORIES)
    )
    return ProjectIntent.build(
        risk_class="production",
        regulatory_classes=("internal-policy",),
        target_maturity="enterprise",
        requirements=requirements,
    )


def variable() -> VariableDefinition:
    """Return one required, constrained project variable."""
    return VariableDefinition.build(
        variable_id="deployment.os",
        value_type="string",
        scope="project",
        sensitivity="public",
        required=True,
        constraints=VariableConstraints.build(allowed_values=("linux", "freebsd")),
        default_value=None,
        default_secret_ref=None,
        source="profile-contract",
    )


def profile() -> ProjectProfile:
    """Return one complete profile with assignment, overlay, and exact waiver."""
    definition = variable()
    assignment = VariableAssignment.build(
        definition,
        value="linux",
        secret_ref=None,
        source="project-owner",
    )
    return ProjectProfile.build(
        profile_id="rigor-foundry",
        intent=intent(),
        packs=(
            PackSelection.build(
                pack_id="core",
                version="1.2.3",
                source_digest="1" * 64,
                pack_digest="2" * 64,
                trusted_key_ids=("standards-key-1",),
            ),
        ),
        variables=(definition,),
        assignments=(assignment,),
        applicability=(
            ApplicabilityDecision.build(
                control_id="core/no-godfiles",
                applicable=True,
                rationale="Python production source is in scope",
            ),
        ),
        overlays=(
            ControlOverlay.build(
                control_id="core/no-godfiles",
                target_level="enterprise",
                mode="require",
                source="project architecture policy",
            ),
        ),
        waivers=(
            ExceptionWaiver.build(
                waiver_id="temporary-level-exception",
                control_id="core/legacy-control",
                field="target_level",
                from_value="enterprise",
                to_value="production",
                owner="migration-owner",
                authorized_by="independent-risk-owner",
                rationale="bounded migration window",
                evidence_digest=DIGEST,
                created_at="2026-07-01T00:00:00Z",
                expires_at="2026-08-01T00:00:00Z",
            ),
        ),
        created_by="architecture-owner",
        created_at="2026-07-15T12:00:00Z",
    )


def test_complete_profile_round_trips_with_exact_definition_binding() -> None:
    """All desired-state layers survive parsing with every digest intact."""
    expected = profile()
    assert ProjectProfile.from_dict(expected.to_dict()) == expected
    assert ProjectIntent.from_dict(expected.intent.to_dict()) == expected.intent
    assert PackSelection.from_dict(expected.packs[0].to_dict()) == expected.packs[0]
    assert ControlOverlay.from_dict(expected.overlays[0].to_dict()) == expected.overlays[0]
    assert ExceptionWaiver.from_dict(expected.waivers[0].to_dict()) == expected.waivers[0]
    assert expected.waivers[0].active_at(datetime(2026, 7, 15, tzinfo=UTC))

    tampered = deepcopy(expected.to_dict())
    tampered["created_by"] = "different-author"
    with pytest.raises(ValueError, match="profile digest"):
        ProjectProfile.from_dict(tampered)


def test_intent_cannot_omit_or_duplicate_required_categories() -> None:
    """Desired state is invalid when a mandatory category is missing or repeated."""
    complete = intent()
    with pytest.raises(ValueError, match="missing categories"):
        ProjectIntent.build(
            risk_class=complete.risk_class,
            regulatory_classes=complete.regulatory_classes,
            target_maturity=complete.target_maturity,
            requirements=complete.requirements[:-1],
        )
    with pytest.raises(ValueError, match="must be unique"):
        ProjectIntent.build(
            risk_class=complete.risk_class,
            regulatory_classes=complete.regulatory_classes,
            target_maturity=complete.target_maturity,
            requirements=(*complete.requirements, complete.requirements[0]),
        )


def test_profile_rejects_unresolved_and_ambiguous_records() -> None:
    """Required variables and every profile collection remain unambiguous."""
    expected = profile()
    with pytest.raises(ValueError, match="unresolved"):
        ProjectProfile.build(
            profile_id=expected.profile_id,
            intent=expected.intent,
            packs=expected.packs,
            variables=(variable(),),
            assignments=(),
            applicability=(),
            overlays=(),
            waivers=(),
            created_by=expected.created_by,
            created_at=expected.created_at,
        )
    with pytest.raises(ValueError, match="pack ids"):
        ProjectProfile.build(
            profile_id=expected.profile_id,
            intent=expected.intent,
            packs=(*expected.packs, expected.packs[0]),
            variables=expected.variables,
            assignments=expected.assignments,
            applicability=expected.applicability,
            overlays=expected.overlays,
            waivers=expected.waivers,
            created_by=expected.created_by,
            created_at=expected.created_at,
        )


def test_waiver_requires_bounded_timezone_aware_use() -> None:
    """Exceptions cannot be permanent, backwards, or evaluated at naive local time."""
    waiver = profile().waivers[0]
    assert not waiver.active_at(datetime(2026, 8, 1, tzinfo=UTC))
    with pytest.raises(ValueError, match="timezone-aware"):
        waiver.active_at(datetime(2026, 7, 15))
    with pytest.raises(ValueError, match="later than"):
        ExceptionWaiver.build(
            waiver_id="bad-window",
            control_id="core/no-godfiles",
            field="mode",
            from_value="deny",
            to_value="require",
            owner="owner",
            authorized_by="risk-owner",
            rationale="invalid window",
            evidence_digest=DIGEST,
            created_at="2026-07-15T00:00:00Z",
            expires_at="2026-07-15T00:00:00Z",
        )


def test_nested_profile_integrity_failures_are_rejected() -> None:
    """Every nested schema and digest is independently checked during profile parsing."""
    expected = profile()
    cases: list[tuple[dict[str, object], str]] = []
    wrong_schema = deepcopy(expected.to_dict())
    wrong_schema["schema_version"] = "9.0"
    cases.append((wrong_schema, "schema"))
    wrong_array = deepcopy(expected.to_dict())
    wrong_array["variables"] = "none"
    cases.append((wrong_array, "array"))
    wrong_intent_schema = deepcopy(expected.to_dict())
    cast(dict[str, object], wrong_intent_schema["intent"])["schema_version"] = "9.0"
    cases.append((wrong_intent_schema, "schema"))
    wrong_intent_digest = deepcopy(expected.to_dict())
    cast(dict[str, object], wrong_intent_digest["intent"])["intent_digest"] = "0" * 64
    cases.append((wrong_intent_digest, "intent digest"))
    wrong_pack = deepcopy(expected.to_dict())
    cast(list[dict[str, object]], wrong_pack["packs"])[0]["selection_digest"] = "0" * 64
    cases.append((wrong_pack, "selection digest"))
    wrong_applicability = deepcopy(expected.to_dict())
    cast(list[dict[str, object]], wrong_applicability["applicability"])[0]["decision_digest"] = (
        "0" * 64
    )
    cases.append((wrong_applicability, "applicability digest"))
    wrong_overlay = deepcopy(expected.to_dict())
    cast(list[dict[str, object]], wrong_overlay["overlays"])[0]["overlay_digest"] = "0" * 64
    cases.append((wrong_overlay, "overlay digest"))
    wrong_waiver = deepcopy(expected.to_dict())
    cast(list[dict[str, object]], wrong_waiver["waivers"])[0]["waiver_digest"] = "0" * 64
    cases.append((wrong_waiver, "waiver digest"))
    for encoded, message in cases:
        with pytest.raises(ValueError, match=message):
            ProjectProfile.from_dict(encoded)

    unknown_assignment = deepcopy(expected.to_dict())
    cast(list[dict[str, object]], unknown_assignment["assignments"])[0]["variable_id"] = (
        "unknown.variable"
    )
    with pytest.raises(ValueError, match="unknown variable"):
        ProjectProfile.from_dict(unknown_assignment)


def test_invalid_requirement_overlay_and_empty_pack_set_fail_closed() -> None:
    """Unsupported categories/modes and profiles without packs are never accepted."""
    expected = profile()
    with pytest.raises(ValueError, match="unsupported"):
        RequirementBinding.build(cast(RequirementCategory, "unknown"), ("value",))
    with pytest.raises(ValueError, match="unsupported"):
        ControlOverlay.build(
            control_id="core/no-godfiles",
            target_level="production",
            mode=cast(object, "allow"),
            source="invalid",
        )
    with pytest.raises(ValueError, match="at least one"):
        ProjectProfile.build(
            profile_id=expected.profile_id,
            intent=expected.intent,
            packs=(),
            variables=(),
            assignments=(),
            applicability=(),
            overlays=(),
            waivers=(),
            created_by=expected.created_by,
            created_at=expected.created_at,
        )
