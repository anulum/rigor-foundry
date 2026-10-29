# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed candidate extractor registry
"""Retain the exact two extractor contracts without importing or installing code."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import canonical_digest
from .effect_operation_contracts_v3 import _extractor_descriptors
from .model_primitives import require_digest
from .policy_model_inputs import checked_policy_budget, policy_record_mapping, policy_wire_size
from .policy_read_budget import PolicyReadBudget1

EXTRACTOR_REGISTRY_V3_SCHEMA_VERSION = "3.0"
_FIELDS = frozenset({"schema_version", "object_kind", "extractors", "registry_digest"})


@dataclass(frozen=True)
class ExtractorRegistryV3:
    """Closed candidate metadata with both common headers inside its owning digest.

    Inline input/output contract mappings declare the required owning types and
    checks. They carry no independent identity, executable locator or authority.
    In particular, parsing does not implement native binding or part extraction.
    Every serializer returns fresh mappings and revalidates direct instances.
    """

    registry_digest: str

    schema_version: ClassVar[str] = EXTRACTOR_REGISTRY_V3_SCHEMA_VERSION
    object_kind: ClassVar[str] = "extractor-registry"

    @staticmethod
    def _body(*, budget: PolicyReadBudget1) -> dict[str, object]:
        """Bound the full fixed descriptor body before emitting an enclosing record."""
        limits = checked_policy_budget(budget)
        extractors = _extractor_descriptors()
        if len(extractors) > limits.max_references:
            raise ValueError("extractor registry exceeds its descriptor reference budget")
        body: dict[str, object] = {
            "schema_version": EXTRACTOR_REGISTRY_V3_SCHEMA_VERSION,
            "object_kind": "extractor-registry",
            "extractors": extractors,
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(cls, *, budget: PolicyReadBudget1) -> ExtractorRegistryV3:
        """Build the complete fixed atomic/native declaration under explicit parse limits.

        Parameters
        ----------
        budget : PolicyReadBudget1
            Whole-document bytes/depth and two-descriptor allocation limits.

        Returns
        -------
        ExtractorRegistryV3
            Candidate metadata without installed-code or selection proof.

        Raises
        ------
        ValueError
            The explicit budget cannot contain the complete record.
        """
        result = cls(canonical_digest(cls._body(budget=budget)))
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Emit all four fields after checking the direct instance and final encoded size."""
        body = self._body(budget=budget)
        digest = require_digest(self.registry_digest, "extractor registry3 digest")
        if digest != canonical_digest(body):
            raise ValueError("extractor registry3 digest differs")
        wire = {**body, "registry_digest": digest}
        policy_wire_size(wire, budget=budget)
        return wire

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> ExtractorRegistryV3:
        """Parse exactly the closed nonempty registry and both digest-bound common headers.

        Parameters
        ----------
        value : object
            Strict decoded JSON. Use the bounded policy reader for file/bytes input.
        budget : PolicyReadBudget1
            Explicit document, depth and descriptor allocation limits.

        Returns
        -------
        ExtractorRegistryV3
            Verified structural identity, without importing any extractor.

        Raises
        ------
        ValueError
            Any header, descriptor, type, order, field, digest or bound differs.
        """
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            schema_version=EXTRACTOR_REGISTRY_V3_SCHEMA_VERSION,
            object_kind="extractor-registry",
            budget=budget,
        )
        expected = cls.build(budget=budget)
        if canonical_digest(data["extractors"]) != canonical_digest(_extractor_descriptors()):
            raise ValueError("extractor registry3 contains an unreviewed descriptor")
        if require_digest(data["registry_digest"], "extractor registry3 digest") != (
            expected.registry_digest
        ):
            raise ValueError("extractor registry3 digest differs")
        return expected
