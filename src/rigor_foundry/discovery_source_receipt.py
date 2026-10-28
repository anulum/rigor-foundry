# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original discovery receipt parser
"""Retain the original discovery validator's integrity-only receipt unchanged."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import ClassVar

from .audit_primitives import canonical_digest
from .discovery_source_schema import (
    SCHEMA,
    DiscoveryLimits,
    digest,
    exact_object,
    identifier,
    integer,
    nonempty_list,
)
from .policy_read_budget import PolicyReadBudget1

_FIELDS = (
    "schema_version status assertion_class promotable manifest_sha256 sources shards "
    "candidate_count span_count unused_source_ids limits receipt_digest"
)
_LIMIT_FIELDS = "total_bytes file_bytes sources shards candidates spans"
_HARD_REFERENCES = 65536


def _rows(
    values: tuple[tuple[str, str], ...], identity: str, maximum: int
) -> list[dict[str, object]]:
    """Validate immutable original identity/digest pairs before serialization."""
    if not 0 < len(values) <= maximum:
        raise ValueError("invalid discovery receipt rows")
    result: list[dict[str, object]] = []
    ids: list[str] = []
    for row in values:
        if type(row) is not tuple or len(row) != 2:
            raise ValueError("invalid discovery receipt row")
        name, sha = identifier(row[0]), digest(row[1])
        ids.append(name)
        result.append({identity: name, "sha256": sha})
    if ids != sorted(set(ids)):
        raise ValueError("discovery receipt rows must be sorted and unique")
    return result


def _parse_rows(value: object, identity: str, maximum: int) -> tuple[tuple[str, str], ...]:
    """Parse bounded original row objects without normalizing their order."""
    result = []
    for item in nonempty_list(value, maximum):
        row = exact_object(item, identity + " sha256")
        result.append((identifier(row[identity]), digest(row["sha256"])))
    return tuple(result)


@dataclass(frozen=True)
class DiscoverySourceReceipt1:
    """An immutable parser model for the existing discovery receipt wire format.

    Parameters
    ----------
    manifest_sha256 : str
        Original exact manifest-byte digest.
    sources, shards : tuple of tuple of str
        Original sorted unique identity/digest pairs, including unused sources.
    candidate_count, span_count : int
        Original validated graph counts.
    unused_source_ids : tuple of str
        Original sorted unused subset of source identities.
    limits : DiscoveryLimits
        Original discovery limits, independent of this parser's read budget.
    receipt_digest : str
        Original complete receipt digest, never a replacement wrapper digest.

    Raises
    ------
    ValueError
        If fields, ordering, count bounds or the original digest are invalid.

    Notes
    -----
    Parsing grants no source access or semantic acceptance. A host must rerun
    the original validator against its actual selected files to observe them.
    """

    manifest_sha256: str
    sources: tuple[tuple[str, str], ...]
    shards: tuple[tuple[str, str], ...]
    candidate_count: int
    span_count: int
    unused_source_ids: tuple[str, ...]
    limits: DiscoveryLimits
    receipt_digest: str

    schema_version: ClassVar[str] = SCHEMA

    def __post_init__(self) -> None:
        """Validate direct instances with the same original-wire invariants."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        """Validate immutable children and retain every original receipt field."""
        if type(self.limits) is not DiscoveryLimits:
            raise ValueError("actual discovery limits are required")
        limits = DiscoveryLimits(**asdict(self.limits))
        if any(
            type(values) is not tuple
            for values in (self.sources, self.shards, self.unused_source_ids)
        ):
            raise ValueError("immutable discovery receipt collections are required")
        if (
            18 + 3 * (len(self.sources) + len(self.shards)) + len(self.unused_source_ids)
            > _HARD_REFERENCES
        ):
            raise ValueError("discovery receipt exceeds the reference ceiling")
        sources = _rows(self.sources, "source_id", limits.sources)
        shards = _rows(self.shards, "shard_id", limits.shards)
        unused = [identifier(value) for value in self.unused_source_ids]
        source_ids = {row["source_id"] for row in sources}
        if unused != sorted(set(unused)) or not set(unused) < source_ids:
            raise ValueError("invalid unused discovery source subset")
        candidates = integer(self.candidate_count, minimum=1)
        spans = integer(self.span_count, minimum=1)
        if (
            not len(shards) <= candidates <= limits.candidates
            or not candidates <= spans <= limits.spans
        ):
            raise ValueError("discovery receipt counts exceed their original graph limits")
        return {
            "schema_version": SCHEMA,
            "status": "discovery-integrity-verified",
            "assertion_class": "declared-snapshot-integrity-only",
            "promotable": False,
            "manifest_sha256": digest(self.manifest_sha256),
            "sources": sources,
            "shards": shards,
            "candidate_count": candidates,
            "span_count": spans,
            "unused_source_ids": unused,
            "limits": asdict(limits),
        }

    def to_dict(self) -> dict[str, object]:
        """Return the complete unchanged original discovery receipt.

        Returns
        -------
        dict of str to object
            Original fields and independently rechecked receipt_digest.

        Raises
        ------
        ValueError
            If any original invariant or digest fails revalidation.
        """
        body = self._body()
        if digest(self.receipt_digest) != canonical_digest(body):
            raise ValueError("original discovery receipt digest differs")
        return {**body, "receipt_digest": self.receipt_digest}

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> DiscoverySourceReceipt1:
        """Parse the original closed receipt with explicit allocation limits.

        Parameters
        ----------
        value : object
            Complete decoded output from validate_discovery_sources.
        budget : PolicyReadBudget1
            Parser allocation limits; original embedded limits remain unchanged.

        Returns
        -------
        DiscoverySourceReceipt1
            Original immutable receipt, without a new schema or digest.

        Raises
        ------
        ValueError
            If limits, fixed lifecycle fields, children or original digest fail.
        """
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        bound = PolicyReadBudget1.from_dict(budget.to_dict())
        data = exact_object(value, _FIELDS)
        if (
            data["schema_version"] != SCHEMA
            or data["status"] != "discovery-integrity-verified"
            or data["assertion_class"] != "declared-snapshot-integrity-only"
            or data["promotable"] is not False
        ):
            raise ValueError("unsupported original discovery receipt")
        sources = nonempty_list(data["sources"], bound.max_sources)
        shards = nonempty_list(data["shards"], bound.max_references)
        unused = data["unused_source_ids"]
        if not isinstance(unused, list):
            raise ValueError("unused discovery source identities must be an array")
        if (
            bound.max_depth < 3
            or 18 + 3 * (len(sources) + len(shards)) + len(unused) > bound.max_references
        ):
            raise ValueError("discovery receipt exceeds its parser budget")
        limits = exact_object(data["limits"], _LIMIT_FIELDS)
        original_limits = DiscoveryLimits(
            **{key: integer(item, minimum=1) for key, item in limits.items()}
        )
        return cls(
            digest(data["manifest_sha256"]),
            _parse_rows(sources, "source_id", original_limits.sources),
            _parse_rows(shards, "shard_id", original_limits.shards),
            integer(data["candidate_count"], minimum=1),
            integer(data["span_count"], minimum=1),
            tuple(identifier(item) for item in unused),
            original_limits,
            digest(data["receipt_digest"]),
        )
