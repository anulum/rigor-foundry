# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protocol primitive tests
"""Verify strict values, secret references, constraints, and evidence records."""

from __future__ import annotations

from copy import deepcopy

import pytest

from rigor_foundry.model_primitives import (
    VARIABLE_ASSIGNMENT_SCHEMA_VERSION,
    VARIABLE_DEFINITION_SCHEMA_VERSION,
    SecretReference,
    VariableAssignment,
    VariableConstraints,
    VariableDefinition,
    WorkEvidence,
    require_boolean,
    require_digest,
    require_git_object,
    require_identifier,
    require_json_scalar,
    require_nonempty_strings,
    require_number,
    require_semantic_version,
    require_unique_strings,
    require_utc_timestamp,
    require_variable_type,
    require_variable_value,
)

DIGEST = "a" * 64


@pytest.mark.parametrize(
    ("validator", "value"),
    [
        (require_identifier, "bad value"),
        (require_semantic_version, "latest"),
        (require_digest, "A" * 64),
        (require_git_object, "1" * 39),
        (require_utc_timestamp, "2026-07-15T12:00:00+02:00"),
        (require_boolean, 1),
        (require_number, True),
        (require_number, float("inf")),
    ],
)
def test_strict_primitive_validators_reject_ambiguous_values(
    validator: object,
    value: object,
) -> None:
    """Protocol validators reject coercion, local time, and malformed identities."""
    with pytest.raises(ValueError):
        validator(value, "field")


@pytest.mark.parametrize(
    "value",
    (
        "1.0.0-alpha..1",
        "1.0.0-alpha.",
        "1.0.0-01",
        "1.0.0-alpha_1",
        "1.0.0+build..1",
        "1.0.0+build.",
    ),
)
def test_semantic_version_rejects_invalid_identifier_shapes(value: str) -> None:
    """Prerelease and build identifiers obey exact SemVer 2.0 shapes."""
    with pytest.raises(ValueError, match="semantic version"):
        require_semantic_version(value, "version")
    assert require_semantic_version("1.0.0-alpha.1+build.01", "version") == (
        "1.0.0-alpha.1+build.01"
    )


def test_git_object_accepts_only_full_sha1_or_sha256_lengths() -> None:
    """Git object identifiers are exactly 40 or 64 lowercase hexadecimal characters."""
    assert require_git_object("a" * 40, "object") == "a" * 40
    assert require_git_object("b" * 64, "object") == "b" * 64
    for length in (41, 63):
        with pytest.raises(ValueError, match="full lowercase Git object"):
            require_git_object("c" * length, "object")


def test_secret_reference_is_opaque_digest_bound_and_round_trips() -> None:
    """Only an opaque provider coordinate enters the durable secret record."""
    reference = SecretReference.build(
        provider="vault",
        reference="secret/data/rigor#token",
        version="42",
    )
    assert SecretReference.from_dict(reference.to_dict()) == reference
    assert "token-value" not in str(reference.to_dict())
    tampered = {**reference.to_dict(), "version": "43"}
    with pytest.raises(ValueError, match="digest"):
        SecretReference.from_dict(tampered)
    with pytest.raises(ValueError, match="whitespace"):
        SecretReference.build(provider="vault", reference="secret path", version="1")


def definition(*, secret: bool = False) -> VariableDefinition:
    """Return one constrained public or secret variable definition."""
    constraints = VariableConstraints.build(pattern=r"linux|freebsd")
    reference = (
        SecretReference.build(provider="vault", reference="kv/rigor", version="7")
        if secret
        else None
    )
    return VariableDefinition.build(
        variable_id="deployment.os" if not secret else "deployment.token",
        value_type="string",
        scope="project",
        sensitivity="secret" if secret else "public",
        required=True,
        constraints=VariableConstraints.build() if secret else constraints,
        default_value=None if secret else "linux",
        default_secret_ref=reference,
        source="project-profile",
    )


def test_variable_definition_and_assignment_bind_exact_digests() -> None:
    """Definitions and typed assignments round-trip only with exact digest binding."""
    public = definition()
    assert public.to_dict()["schema_version"] == VARIABLE_DEFINITION_SCHEMA_VERSION == "1.0"
    assert VariableDefinition.from_dict(public.to_dict()) == public
    assignment = VariableAssignment.build(
        public,
        value="freebsd",
        secret_ref=None,
        source="project-overlay",
    )
    encoded = assignment.to_dict(public.definition_digest)
    assert encoded["schema_version"] == VARIABLE_ASSIGNMENT_SCHEMA_VERSION == "1.0"
    assert VariableAssignment.from_dict(encoded, public) == assignment
    altered = deepcopy(encoded)
    altered["value"] = "linux"
    with pytest.raises(ValueError, match="digest"):
        VariableAssignment.from_dict(altered, public)

    protected_definition = definition(secret=True)
    opaque_assignment = VariableAssignment.build(
        protected_definition,
        value=None,
        secret_ref=protected_definition.default_secret_ref,
        source="environment",
    )
    assert opaque_assignment.to_dict(protected_definition.definition_digest)["value"] is None
    with pytest.raises(ValueError, match="opaque secret reference"):
        VariableAssignment.build(
            protected_definition,
            value="inline-sensitive-material",
            secret_ref=None,
            source="bad",
        )
    with pytest.raises(ValueError, match="typed value"):
        VariableAssignment.build(public, value=None, secret_ref=None, source="bad")


def test_constraints_enforce_type_specific_bounds() -> None:
    """Numeric, textual, membership, and list bounds are enforced without coercion."""
    VariableConstraints.build(minimum=1, maximum=3).validate(2, "integer")
    VariableConstraints.build(minimum_items=1, maximum_items=2).validate(
        ("one", "two"),
        "string-list",
    )
    VariableConstraints.build(allowed_values=("a", "b")).validate("a", "string")
    with pytest.raises(ValueError, match="exceeds"):
        VariableConstraints.build(maximum=3).validate(4, "integer")
    with pytest.raises(ValueError, match="too few"):
        VariableConstraints.build(minimum_items=1).validate((), "string-list")
    with pytest.raises(ValueError, match="regular expression"):
        VariableConstraints.build(pattern="[")
    with pytest.raises(ValueError, match="must not exceed"):
        VariableConstraints.build(minimum=2, maximum=1)
    with pytest.raises(ValueError, match="must be an integer"):
        require_variable_value(True, "integer", "variable")


def test_work_evidence_preserves_argv_and_signal_exit_code() -> None:
    """Reproducible evidence stores exact argv, digests, and negative signal codes."""
    evidence = WorkEvidence(
        description="focused verifier completed",
        command=("python", "tools/verify.py", "--exact"),
        exit_code=-9,
        output_digest=DIGEST,
    )
    assert WorkEvidence.from_dict(evidence.to_dict()) == evidence
    with pytest.raises(ValueError, match="NUL"):
        WorkEvidence("bad argv", ("python\x00unsafe",), 0, DIGEST)
    with pytest.raises(ValueError, match="integer"):
        WorkEvidence("bad exit", ("python",), True, DIGEST)


def test_collection_scalar_and_variable_type_edges_are_strict() -> None:
    """Malformed timestamps, scalars, arrays, and all typed values reject coercion."""
    with pytest.raises(ValueError, match="ISO-8601"):
        require_utc_timestamp("not-a-time", "time")
    with pytest.raises(ValueError, match="JSON scalar"):
        require_json_scalar({"nested": True}, "scalar")
    with pytest.raises(ValueError, match="string array"):
        require_nonempty_strings("one", "items")
    with pytest.raises(ValueError, match="non-empty"):
        require_nonempty_strings([""], "items")
    with pytest.raises(ValueError, match="unique"):
        require_unique_strings(["same", "same"], "items")
    with pytest.raises(ValueError, match="unsupported"):
        require_variable_type("object", "type")
    assert require_variable_value(1.5, "number", "value") == 1.5
    assert require_variable_value(False, "boolean", "value") is False
    assert require_variable_value(("a", "b"), "string-list", "value") == ("a", "b")


def test_all_constraint_failure_modes_are_explicit() -> None:
    """Constraint construction/parsing and every value-bound failure remain distinct."""
    with pytest.raises(ValueError, match="allowed_values must be unique"):
        VariableConstraints.build(allowed_values=("a", "a"))
    with pytest.raises(ValueError, match="integer >= 0"):
        VariableConstraints.build(minimum_items=-1)
    with pytest.raises(ValueError, match="must not exceed"):
        VariableConstraints.build(minimum_items=2, maximum_items=1)
    with pytest.raises(ValueError, match="must be an array"):
        VariableConstraints.from_dict({"allowed_values": "all"})
    with pytest.raises(ValueError, match="not in"):
        VariableConstraints.build(allowed_values=("a",)).validate("b", "string")
    with pytest.raises(ValueError, match="does not match"):
        VariableConstraints.build(pattern="a+").validate("b", "string")
    with pytest.raises(ValueError, match="below"):
        VariableConstraints.build(minimum=2).validate(1, "integer")
    with pytest.raises(ValueError, match="require string-list"):
        VariableConstraints.build(minimum_items=1).validate("value", "string")
    with pytest.raises(ValueError, match="too many"):
        VariableConstraints.build(maximum_items=1).validate(("a", "b"), "string-list")


def test_definition_and_assignment_schema_edges_are_digest_bound() -> None:
    """Invalid scope/sensitivity/secret use and serialized bindings fail closed."""
    reference = SecretReference.build(provider="vault", reference="kv/token", version="1")
    kwargs = {
        "variable_id": "deployment.os",
        "value_type": "string",
        "scope": "project",
        "sensitivity": "public",
        "required": True,
        "constraints": VariableConstraints.build(),
        "default_value": "linux",
        "default_secret_ref": None,
        "source": "profile",
    }
    with pytest.raises(ValueError, match="scope"):
        VariableDefinition.build(**{**kwargs, "scope": "global"})
    with pytest.raises(ValueError, match="sensitivity"):
        VariableDefinition.build(**{**kwargs, "sensitivity": "classified"})
    with pytest.raises(ValueError, match="raw default"):
        VariableDefinition.build(
            **{
                **kwargs,
                "sensitivity": "secret",
                "default_secret_ref": reference,
            }
        )
    with pytest.raises(ValueError, match="cannot carry secret"):
        VariableDefinition.build(**{**kwargs, "default_secret_ref": reference})

    expected = definition()
    encoded = expected.to_dict()
    encoded["schema_version"] = "9.0"
    with pytest.raises(ValueError, match="schema"):
        VariableDefinition.from_dict(encoded)
    encoded = expected.to_dict()
    encoded["definition_digest"] = "0" * 64
    with pytest.raises(ValueError, match="digest"):
        VariableDefinition.from_dict(encoded)
    assignment = VariableAssignment.build(
        expected,
        value="linux",
        secret_ref=None,
        source="profile",
    )
    for field, value, message in (
        ("schema_version", "9.0", "schema"),
        ("variable_id", "other.variable", "wrong variable"),
        ("definition_digest", "0" * 64, "definition digest"),
    ):
        serialized = assignment.to_dict(expected.definition_digest)
        serialized[field] = value
        with pytest.raises(ValueError, match=message):
            VariableAssignment.from_dict(serialized, expected)


def test_string_list_and_artefact_records_round_trip() -> None:
    """List variables and optional artefact digests preserve canonical JSON shapes."""
    list_definition = VariableDefinition.build(
        variable_id="deployment.targets",
        value_type="string-list",
        scope="environment",
        sensitivity="internal",
        required=True,
        constraints=VariableConstraints.build(minimum_items=1),
        default_value=("linux",),
        default_secret_ref=None,
        source="profile",
    )
    assert VariableDefinition.from_dict(list_definition.to_dict()) == list_definition
    assignment = VariableAssignment.build(
        list_definition,
        value=("linux", "freebsd"),
        secret_ref=None,
        source="overlay",
    )
    assert (
        VariableAssignment.from_dict(
            assignment.to_dict(list_definition.definition_digest),
            list_definition,
        )
        == assignment
    )
    evidence = WorkEvidence("artefact", ("verify",), 0, DIGEST, "b" * 64)
    assert WorkEvidence.from_dict(evidence.to_dict()).artefact_digest == "b" * 64
    malformed = evidence.to_dict()
    malformed["exit_code"] = False
    with pytest.raises(ValueError, match="integer"):
        WorkEvidence.from_dict(malformed)
