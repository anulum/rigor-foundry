# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — campaign inference identity and witness correlation
"""Bind audit inference identity and collapse correlated model-family runs."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from .models import canonical_digest, require_mapping, require_string, require_string_tuple

INFERENCE_IDENTITY_SCHEMA_VERSION = "1.0"
MODEL_WITNESS_SCHEMA_VERSION = "1.0"
_IDENTITY_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}\Z")
_INFERENCE_IDENTITY_FIELDS = frozenset(
    {
        "schema_version",
        "provider",
        "model",
        "model_family",
        "operator",
        "identity_digest",
    }
)
_MODEL_WITNESS_FIELDS = frozenset(
    {
        "schema_version",
        "model_family",
        "providers",
        "models",
        "operators",
        "run_ids",
        "witness_digest",
    }
)


def _identity_component(value: object, field: str) -> str:
    """Return one bounded portable identity component."""
    result = require_string(value, field)
    if _IDENTITY_COMPONENT.fullmatch(result) is None:
        raise ValueError(f"{field} must be a portable identity")
    return result


def _sorted_unique_components(value: object, field: str) -> tuple[str, ...]:
    """Return a non-empty, sorted, duplicate-free identity tuple."""
    values = require_string_tuple(value, field)
    parsed = tuple(
        _identity_component(item, f"{field}[{index}]") for index, item in enumerate(values)
    )
    if not parsed:
        raise ValueError(f"{field} must not be empty")
    if parsed != tuple(sorted(set(parsed))):
        raise ValueError(f"{field} must be sorted and contain unique values")
    return parsed


@dataclass(frozen=True)
class InferenceIdentity:
    """Provider, model, correlation-family, and operator identity for one run.

    ``model_family`` is the explicit correlation key. Runs with the same family
    contribute one evidentiary witness even when their agent, session, provider,
    exact model version, or operator labels differ.
    """

    provider: str
    model: str
    model_family: str
    operator: str
    identity_digest: str

    @classmethod
    def build(
        cls,
        *,
        provider: str,
        model: str,
        model_family: str,
        operator: str,
    ) -> InferenceIdentity:
        """Build one content-addressed inference identity."""
        body = {
            "schema_version": INFERENCE_IDENTITY_SCHEMA_VERSION,
            "provider": _identity_component(provider, "provider"),
            "model": _identity_component(model, "model"),
            "model_family": _identity_component(model_family, "model_family"),
            "operator": _identity_component(operator, "operator"),
        }
        return cls(
            provider=body["provider"],
            model=body["model"],
            model_family=body["model_family"],
            operator=body["operator"],
            identity_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise one inference identity."""
        return {
            "schema_version": INFERENCE_IDENTITY_SCHEMA_VERSION,
            "provider": self.provider,
            "model": self.model,
            "model_family": self.model_family,
            "operator": self.operator,
            "identity_digest": self.identity_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> InferenceIdentity:
        """Parse and integrity-check one inference identity."""
        data = require_mapping(value, "inference_identity")
        if frozenset(data) != _INFERENCE_IDENTITY_FIELDS:
            raise ValueError("inference identity fields do not match schema")
        if data.get("schema_version") != INFERENCE_IDENTITY_SCHEMA_VERSION:
            raise ValueError("unsupported inference identity schema version")
        identity = cls.build(
            provider=_identity_component(data.get("provider"), "provider"),
            model=_identity_component(data.get("model"), "model"),
            model_family=_identity_component(data.get("model_family"), "model_family"),
            operator=_identity_component(data.get("operator"), "operator"),
        )
        if data.get("identity_digest") != identity.identity_digest:
            raise ValueError("inference identity digest does not match its content")
        return identity


@dataclass(frozen=True)
class ModelWitness:
    """One correlation-collapsed evidentiary witness for a model family."""

    model_family: str
    providers: tuple[str, ...]
    models: tuple[str, ...]
    operators: tuple[str, ...]
    run_ids: tuple[str, ...]
    witness_digest: str

    @classmethod
    def build(
        cls,
        *,
        model_family: str,
        providers: Iterable[str],
        models: Iterable[str],
        operators: Iterable[str],
        run_ids: Iterable[str],
    ) -> ModelWitness:
        """Build one deterministic model-family witness."""
        body: dict[str, object] = {
            "schema_version": MODEL_WITNESS_SCHEMA_VERSION,
            "model_family": _identity_component(model_family, "model_family"),
            "providers": sorted(set(providers)),
            "models": sorted(set(models)),
            "operators": sorted(set(operators)),
            "run_ids": sorted(set(run_ids)),
        }
        providers_tuple = _sorted_unique_components(body["providers"], "providers")
        models_tuple = _sorted_unique_components(body["models"], "models")
        operators_tuple = _sorted_unique_components(body["operators"], "operators")
        run_ids_tuple = _sorted_unique_components(body["run_ids"], "run_ids")
        return cls(
            model_family=str(body["model_family"]),
            providers=providers_tuple,
            models=models_tuple,
            operators=operators_tuple,
            run_ids=run_ids_tuple,
            witness_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one model-family witness."""
        return {
            "schema_version": MODEL_WITNESS_SCHEMA_VERSION,
            "model_family": self.model_family,
            "providers": list(self.providers),
            "models": list(self.models),
            "operators": list(self.operators),
            "run_ids": list(self.run_ids),
            "witness_digest": self.witness_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ModelWitness:
        """Parse and integrity-check one model-family witness."""
        data = require_mapping(value, "model_witness")
        if frozenset(data) != _MODEL_WITNESS_FIELDS:
            raise ValueError("model witness fields do not match schema")
        if data.get("schema_version") != MODEL_WITNESS_SCHEMA_VERSION:
            raise ValueError("unsupported model witness schema version")
        witness = cls.build(
            model_family=_identity_component(data.get("model_family"), "model_family"),
            providers=_sorted_unique_components(data.get("providers"), "providers"),
            models=_sorted_unique_components(data.get("models"), "models"),
            operators=_sorted_unique_components(data.get("operators"), "operators"),
            run_ids=_sorted_unique_components(data.get("run_ids"), "run_ids"),
        )
        if data.get("witness_digest") != witness.witness_digest:
            raise ValueError("model witness digest does not match its content")
        return witness


def collapse_model_witnesses(
    runs: Iterable[tuple[str, InferenceIdentity]],
) -> tuple[ModelWitness, ...]:
    """Collapse run identities into one deterministic witness per model family."""
    grouped: dict[str, list[tuple[str, InferenceIdentity]]] = {}
    seen_run_ids: set[str] = set()
    for run_id, identity in runs:
        parsed_run_id = _identity_component(run_id, "run_id")
        if parsed_run_id in seen_run_ids:
            raise ValueError("model witness input contains duplicate run identifiers")
        seen_run_ids.add(parsed_run_id)
        grouped.setdefault(identity.model_family, []).append((parsed_run_id, identity))
    return tuple(
        ModelWitness.build(
            model_family=model_family,
            providers=(identity.provider for _run_id, identity in records),
            models=(identity.model for _run_id, identity in records),
            operators=(identity.operator for _run_id, identity in records),
            run_ids=(run_id for run_id, _identity in records),
        )
        for model_family, records in sorted(grouped.items())
    )


def promotion_identity_gaps(
    witnesses: tuple[ModelWitness, ...],
    required_model_witnesses: int,
) -> tuple[str, ...]:
    """Return cross-model and independent-operator promotion gaps."""
    gaps: list[str] = []
    if len(witnesses) < required_model_witnesses:
        gaps.append(
            f"expected {required_model_witnesses} model-family witnesses, found {len(witnesses)}"
        )
    operators = {operator for witness in witnesses for operator in witness.operators}
    if len(operators) < 2:
        gaps.append(f"promotion requires at least 2 independent operators, found {len(operators)}")
    return tuple(gaps)
