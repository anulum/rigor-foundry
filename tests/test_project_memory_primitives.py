# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory protocol primitive tests
"""Exercise the exact no-float serialisation and provenance value contracts."""

from __future__ import annotations

import pytest

from rigor_foundry.project_memory_primitives import (
    PROJECT_MEMORY_MAX_CONTENT_BYTES,
    PROJECT_MEMORY_MAX_INDEX_BYTES,
    PROJECT_MEMORY_MAX_MANIFEST_BYTES,
    PROJECT_MEMORY_MAX_RECORDS,
    PROJECT_MEMORY_MAX_SOURCES,
    PROJECT_MEMORY_MAX_SUPERSEDES,
    PROJECT_MEMORY_SOFT_CONTENT_BYTES,
    ProjectMemoryActor,
    ProjectMemoryFreshness,
    ProjectMemoryInvalid,
    ProjectMemoryParent,
    ProjectMemorySource,
    canonical_json_bytes,
    generation_id_for,
    require_digest,
    require_mapping,
    require_timestamp,
    strict_json,
)


def test_ratified_bounds_and_canonical_json_are_exact() -> None:
    """The ratified profile and deterministic key ordering remain fixed."""
    assert (
        PROJECT_MEMORY_SOFT_CONTENT_BYTES,
        PROJECT_MEMORY_MAX_CONTENT_BYTES,
        PROJECT_MEMORY_MAX_RECORDS,
        PROJECT_MEMORY_MAX_MANIFEST_BYTES,
        PROJECT_MEMORY_MAX_INDEX_BYTES,
        PROJECT_MEMORY_MAX_SOURCES,
        PROJECT_MEMORY_MAX_SUPERSEDES,
    ) == (24576, 32768, 50, 65536, 16384, 32, 16)
    assert canonical_json_bytes({"z": 2, "a": [True, None, 1]}) == b'{"a":[true,null,1],"z":2}'
    assert generation_id_for("2026-09-04T12:30:45.123456Z") == "20260904T123045123456Z"


@pytest.mark.parametrize(
    "value, message",
    [
        ({"value": 1.5}, "outside the no-float"),
        ({"value": 2**53}, "interoperability bound"),
        ({"value": "ž"}, "printable ASCII"),
        ({"value": object()}, "outside the no-float"),
    ],
)
def test_canonical_json_rejects_values_outside_the_ratified_subset(
    value: object,
    message: str,
) -> None:
    """Float, oversized integer, Unicode metadata and opaque objects fail closed."""
    with pytest.raises(ProjectMemoryInvalid, match=message):
        canonical_json_bytes(value)


@pytest.mark.parametrize(
    "payload, message",
    [
        (b'{"a":1,"a":2}', "duplicate keys"),
        (b'{"a":1.5}', "forbidden number"),
        (b'{"a":NaN}', "forbidden number"),
        (b"\xff", "not strict UTF-8"),
        (b"{", "not strict UTF-8"),
    ],
)
def test_strict_json_rejects_ambiguous_or_noncanonical_domains(
    payload: bytes,
    message: str,
) -> None:
    """Duplicate, floating, non-finite, binary and malformed inputs are rejected."""
    with pytest.raises(ProjectMemoryInvalid, match=message):
        strict_json(payload)


def test_provenance_primitives_round_trip_exact_fields() -> None:
    """Source, actor, freshness and parent values preserve only declared fields."""
    source = ProjectMemorySource.from_dict(
        {"source_id": "session", "locator": "coordination/session.md", "sha256": "a" * 64},
        "source",
    )
    actor = ProjectMemoryActor.from_dict(
        {"identity": "RIGOR-FOUNDRY/validator-1", "claim_id": "memory-write-1"},
        "actor",
    )
    freshness = ProjectMemoryFreshness.from_dict(
        {"policy": "expires", "valid_until": "2026-09-04T13:00:00.000000Z"},
        "freshness",
    )
    parent = ProjectMemoryParent.from_dict(
        {"kind": "ecosystem-boot", "locator": "../../../AGENTS.md"},
        "parent",
    )

    assert source.to_dict()["sha256"] == "a" * 64
    assert actor.to_dict()["identity"] == "RIGOR-FOUNDRY/validator-1"
    assert freshness.to_dict()["valid_until"] == "2026-09-04T13:00:00.000000Z"
    assert parent.to_dict() == {"kind": "ecosystem-boot", "locator": "../../../AGENTS.md"}


@pytest.mark.parametrize(
    "factory, value, message",
    [
        (
            ProjectMemorySource.from_dict,
            {"source_id": "bad/id", "locator": "source", "sha256": "a" * 64},
            "portable identifier",
        ),
        (
            ProjectMemoryActor.from_dict,
            {"identity": "bad identity", "claim_id": "claim"},
            "not portable",
        ),
        (
            ProjectMemoryFreshness.from_dict,
            {"policy": "immutable", "valid_until": "2026-09-04T13:00:00.000000Z"},
            "must be null",
        ),
        (
            ProjectMemoryParent.from_dict,
            {"kind": "ecosystem-boot", "locator": "/absolute/AGENTS.md"},
            "normalised relative path",
        ),
    ],
)
def test_provenance_primitives_reject_unsafe_values(
    factory: object,
    value: dict[str, object],
    message: str,
) -> None:
    """Identifiers, actors, freshness and upward paths retain narrow grammars."""
    assert callable(factory)
    with pytest.raises(ProjectMemoryInvalid, match=message):
        factory(value, "value")


def test_exact_timestamp_and_field_sets_fail_closed() -> None:
    """Coarse timestamps and versionless extensions cannot enter a primitive."""
    with pytest.raises(ProjectMemoryInvalid, match="microsecond UTC"):
        generation_id_for("2026-09-04T12:30:45Z")
    with pytest.raises(ProjectMemoryInvalid, match="fields do not match"):
        ProjectMemorySource.from_dict(
            {
                "source_id": "source",
                "locator": "evidence/file",
                "sha256": "a" * 64,
                "trust": "assumed",
            },
            "source",
        )


def test_low_level_value_boundaries_reject_invalid_types_and_calendars() -> None:
    """Non-mappings, malformed digests and impossible calendar dates are rejected."""
    with pytest.raises(ProjectMemoryInvalid, match="must be an object"):
        require_mapping([], "value")
    with pytest.raises(ProjectMemoryInvalid, match="lowercase SHA-256"):
        require_digest("A" * 64, "digest")
    with pytest.raises(ProjectMemoryInvalid, match="calendar timestamp"):
        require_timestamp("2026-02-31T12:00:00.000000Z", "timestamp")
    with pytest.raises(ProjectMemoryInvalid, match="policy is unsupported"):
        ProjectMemoryFreshness.from_dict(
            {"policy": "whenever", "valid_until": None},
            "freshness",
        )
    with pytest.raises(ProjectMemoryInvalid, match="kind is unsupported"):
        ProjectMemoryParent.from_dict(
            {"kind": "sibling-memory", "locator": "../../../sibling/"},
            "parent",
        )
