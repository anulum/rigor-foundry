# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — campaign inference identity tests
"""Verify strict identity records and correlation-collapsed model witnesses."""

from __future__ import annotations

import pytest

import rigor_foundry
from rigor_foundry.campaign_identity import (
    INFERENCE_IDENTITY_SCHEMA_VERSION,
    MODEL_WITNESS_SCHEMA_VERSION,
    InferenceIdentity,
    ModelWitness,
    collapse_model_witnesses,
    promotion_identity_gaps,
)


def _identity(
    family: str,
    *,
    provider: str = "provider.example",
    model: str | None = None,
    operator: str = "operator-one",
) -> InferenceIdentity:
    """Build one content-addressed identity through the public constructor."""
    return InferenceIdentity.build(
        provider=provider,
        model=model or f"{family}-v1",
        model_family=family,
        operator=operator,
    )


def test_inference_identity_round_trip_binds_every_correlation_field() -> None:
    """Provider, exact model, family, and operator all affect identity."""
    identity = _identity("family-one")

    assert InferenceIdentity.from_dict(identity.to_dict()) == identity
    assert rigor_foundry.InferenceIdentity is InferenceIdentity
    assert rigor_foundry.INFERENCE_IDENTITY_SCHEMA_VERSION == "1.0"
    assert len(identity.identity_digest) == 64

    for field, value in (
        ("provider", "provider.other"),
        ("model", "family-one-v2"),
        ("model_family", "family-two"),
        ("operator", "operator-two"),
    ):
        changed = identity.to_dict()
        changed[field] = value
        with pytest.raises(ValueError, match="digest does not match"):
            InferenceIdentity.from_dict(changed)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "2.0", "schema version"),
        ("provider", "provider with spaces", "portable identity"),
        ("model", "", "non-empty string"),
        ("model_family", "../family", "portable identity"),
        ("operator", "operator?", "portable identity"),
    ],
)
def test_inference_identity_rejects_ambiguous_or_unsafe_components(
    field: str,
    value: object,
    message: str,
) -> None:
    """Identity fields reject schema drift and non-portable correlation keys."""
    document = _identity("family-one").to_dict()
    document[field] = value
    with pytest.raises(ValueError, match=message):
        InferenceIdentity.from_dict(document)

    unrecognised = _identity("family-one").to_dict()
    unrecognised["extra"] = "discarded"
    with pytest.raises(ValueError, match="fields do not match schema"):
        InferenceIdentity.from_dict(unrecognised)


def test_model_witness_collapse_counts_one_family_once_across_run_labels() -> None:
    """Same-family agent, session, provider, and version variation remains one witness."""
    first = _identity("shared-family", model="shared-v1", operator="operator-one")
    second = _identity(
        "shared-family",
        provider="provider.other",
        model="shared-v2",
        operator="operator-two",
    )
    third = _identity("independent-family", operator="operator-three")

    witnesses = collapse_model_witnesses(
        (
            ("run-two", second),
            ("run-three", third),
            ("run-one", first),
        )
    )

    assert tuple(witness.model_families for witness in witnesses) == (
        ("independent-family",),
        ("shared-family",),
    )
    shared = witnesses[1]
    assert shared.providers == ("provider.example", "provider.other")
    assert shared.models == ("shared-v1", "shared-v2")
    assert shared.operators == ("operator-one", "operator-two")
    assert shared.run_ids == ("run-one", "run-two")
    assert ModelWitness.from_dict(shared.to_dict()) == shared
    assert rigor_foundry.ModelWitness is ModelWitness
    assert shared.exact_models == (
        ("provider.example", "shared-v1"),
        ("provider.other", "shared-v2"),
    )
    assert rigor_foundry.MODEL_WITNESS_SCHEMA_VERSION == "1.2"


def test_exact_model_and_family_edges_form_one_transitive_witness() -> None:
    """Exact-model aliases and shared families cannot multiply witnesses."""
    first = _identity(
        "family-one",
        provider="provider.example",
        model="exact-model",
        operator="operator-one",
    )
    alias = _identity(
        "family-two",
        provider="provider.example",
        model="exact-model",
        operator="operator-two",
    )
    transitive = _identity(
        "family-two",
        provider="provider.other",
        model="other-model",
        operator="operator-three",
    )

    witnesses = collapse_model_witnesses(
        (
            ("run-one", first),
            ("run-two", alias),
            ("run-three", transitive),
        )
    )

    assert len(witnesses) == 1
    assert witnesses[0].model_families == ("family-one", "family-two")
    assert witnesses[0].run_ids == ("run-one", "run-three", "run-two")
    assert promotion_identity_gaps(witnesses, 2)[0] == (
        "expected 2 model-family witnesses, found 1"
    )


def test_model_witness_parser_and_input_reject_duplicates_and_tampering() -> None:
    """Witness construction rejects duplicate runs and non-canonical durable arrays."""
    identity = _identity("family-one")
    with pytest.raises(ValueError, match="duplicate run identifiers"):
        collapse_model_witnesses((("run-one", identity), ("run-one", identity)))

    witness = collapse_model_witnesses((("run-one", identity),))[0]
    changed = witness.to_dict()
    changed["models"] = ["z-model", "a-model"]
    with pytest.raises(ValueError, match="sorted and contain unique"):
        ModelWitness.from_dict(changed)

    changed = witness.to_dict()
    changed["models"] = ["other-model"]
    with pytest.raises(ValueError, match="projections do not match exact models"):
        ModelWitness.from_dict(changed)

    changed = witness.to_dict()
    changed["exact_models"] = [{"provider": "provider.example"}]
    with pytest.raises(ValueError, match="exact model fields do not match"):
        ModelWitness.from_dict(changed)

    changed = witness.to_dict()
    changed["exact_models"] = {}
    with pytest.raises(ValueError, match="exact_models must be an array"):
        ModelWitness.from_dict(changed)

    changed = witness.to_dict()
    changed["exact_models"] = []
    with pytest.raises(ValueError, match="exact_models must not be empty"):
        ModelWitness.from_dict(changed)

    changed = witness.to_dict()
    changed["exact_models"] = [
        *changed["exact_models"],
        *changed["exact_models"],
    ]
    with pytest.raises(ValueError, match="sorted and contain unique"):
        ModelWitness.from_dict(changed)

    changed = witness.to_dict()
    changed["run_ids"] = []
    with pytest.raises(ValueError, match="must not be empty"):
        ModelWitness.from_dict(changed)

    changed = witness.to_dict()
    changed["witness_digest"] = "0" * 64
    with pytest.raises(ValueError, match="digest does not match"):
        ModelWitness.from_dict(changed)

    changed = witness.to_dict()
    changed["schema_version"] = "2.0"
    with pytest.raises(ValueError, match="schema version"):
        ModelWitness.from_dict(changed)

    changed = witness.to_dict()
    changed["extra"] = []
    with pytest.raises(ValueError, match="fields do not match schema"):
        ModelWitness.from_dict(changed)


def test_promotion_identity_gaps_require_cross_model_and_operator_independence() -> None:
    """Promotion gaps distinguish model-family count from operator independence."""
    shared_operator = collapse_model_witnesses(
        (
            ("run-one", _identity("family-one")),
            ("run-two", _identity("family-two")),
        )
    )
    assert promotion_identity_gaps(shared_operator, 2) == (
        "promotion requires at least 2 independent operators, found 1",
    )

    one_family = collapse_model_witnesses(
        (("run-one", _identity("family-one", operator="operator-one")),)
    )
    assert promotion_identity_gaps(one_family, 2) == (
        "expected 2 model-family witnesses, found 1",
        "promotion requires at least 2 independent operators, found 1",
    )

    independent = collapse_model_witnesses(
        (
            ("run-one", _identity("family-one", operator="operator-one")),
            ("run-two", _identity("family-two", operator="operator-two")),
        )
    )
    assert promotion_identity_gaps(independent, 2) == ()
    assert INFERENCE_IDENTITY_SCHEMA_VERSION == "1.0"
    assert MODEL_WITNESS_SCHEMA_VERSION == "1.2"
