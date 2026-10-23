# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete policy source byte partitions
"""Verify exact source-region partitions without inferring semantic acceptance."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal, cast

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_integer,
    require_mapping,
    require_string,
)
from .model_primitives import require_digest, require_identifier, require_nonempty_strings
from .policy_read_budget import PolicyReadBudget1
from .policy_source_reads import read_policy_source_payloads

SOURCE_REGION_SCHEMA_VERSION = "1.0"

RegionDisposition = Literal["normative", "context", "nonnormative", "protected", "unresolved"]
_DISPOSITIONS = frozenset({"normative", "context", "nonnormative", "protected", "unresolved"})
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "source_id",
        "start_byte",
        "end_byte",
        "byte_digest",
        "disposition",
        "rule_ids",
        "decision_ids",
        "reason_code",
        "region_digest",
    }
)


def _identities(value: object, field: str) -> tuple[str, ...]:
    """Validate sorted unique source relations without rewriting their order."""
    items = require_nonempty_strings(value, field)
    for item in items:
        require_identifier(item, field)
    if items != tuple(sorted(set(items))):
        raise ValueError("source region identities must be sorted and unique")
    return items


@dataclass(frozen=True)
class SourceRegion1:
    """One classified byte interval within a complete retained source partition."""

    source_id: str
    start_byte: int
    end_byte: int
    byte_digest: str
    disposition: RegionDisposition
    rule_ids: tuple[str, ...]
    decision_ids: tuple[str, ...]
    reason_code: str
    region_digest: str

    schema_version: ClassVar[str] = SOURCE_REGION_SCHEMA_VERSION
    object_kind: ClassVar[str] = "source-region"

    def __post_init__(self) -> None:
        """Validate direct values and their complete version-bound identity."""
        body = self._body()
        if require_digest(self.region_digest, "source region digest") != canonical_digest(body):
            raise ValueError("source region digest differs")

    def _body(self) -> dict[str, object]:
        """Validate all non-digest fields, including immutable relation arrays."""
        start = require_integer(self.start_byte, "source region start")
        end = require_integer(self.end_byte, "source region end", minimum=1)
        if start >= end:
            raise ValueError("source region must be nonempty and forward")
        disposition = require_string(self.disposition, "source region disposition")
        if disposition not in _DISPOSITIONS:
            raise ValueError("source region disposition is unsupported")
        if not isinstance(self.rule_ids, tuple) or not isinstance(self.decision_ids, tuple):
            raise ValueError("source region relations must be immutable tuples")
        rules = _identities(list(self.rule_ids), "source region rule identity")
        decisions = _identities(list(self.decision_ids), "source region decision identity")
        if disposition == "normative" and not rules:
            raise ValueError("normative source region requires rule identities")
        return {
            "schema_version": SOURCE_REGION_SCHEMA_VERSION,
            "object_kind": "source-region",
            "source_id": require_identifier(self.source_id, "source region source identity"),
            "start_byte": start,
            "end_byte": end,
            "byte_digest": require_digest(self.byte_digest, "source region byte digest"),
            "disposition": disposition,
            "rule_ids": list(rules),
            "decision_ids": list(decisions),
            "reason_code": require_identifier(self.reason_code, "source region reason"),
        }

    @classmethod
    def build(
        cls,
        *,
        source_id: str,
        start_byte: int,
        end_byte: int,
        payload: bytes,
        disposition: RegionDisposition,
        rule_ids: tuple[str, ...],
        decision_ids: tuple[str, ...],
        reason_code: str,
    ) -> SourceRegion1:
        """Bind declared region meaning to original bytes without admitting that meaning."""
        start = require_integer(start_byte, "source region start")
        end = require_integer(end_byte, "source region end", minimum=1)
        if not isinstance(payload, bytes) or not start < end <= len(payload):
            raise ValueError("source region is outside the retained bytes")
        byte_digest = hashlib.sha256(payload[start:end]).hexdigest()
        body: dict[str, object] = {
            "schema_version": SOURCE_REGION_SCHEMA_VERSION,
            "object_kind": "source-region",
            "source_id": source_id,
            "start_byte": start,
            "end_byte": end,
            "byte_digest": byte_digest,
            "disposition": disposition,
            "rule_ids": list(rule_ids),
            "decision_ids": list(decision_ids),
            "reason_code": reason_code,
        }
        return cls(
            source_id,
            start,
            end,
            byte_digest,
            disposition,
            rule_ids,
            decision_ids,
            reason_code,
            canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the exact closed record after checking its integrity."""
        body = self._body()
        digest = require_digest(self.region_digest, "source region digest")
        if digest != canonical_digest(body):
            raise ValueError("source region digest differs")
        return {**body, "region_digest": digest}

    @classmethod
    def from_dict(cls, value: object) -> SourceRegion1:
        """Parse exact region fields without sorting or semantic promotion."""
        data = require_mapping(value, "source region")
        require_exact_fields(data, _FIELDS, "source region")
        if (
            data["schema_version"] != SOURCE_REGION_SCHEMA_VERSION
            or data["object_kind"] != "source-region"
        ):
            raise ValueError("unsupported source region")
        disposition = require_string(data["disposition"], "source region disposition")
        if disposition not in _DISPOSITIONS:
            raise ValueError("source region disposition is unsupported")
        return cls(
            require_identifier(data["source_id"], "source region source identity"),
            require_integer(data["start_byte"], "source region start"),
            require_integer(data["end_byte"], "source region end", minimum=1),
            require_digest(data["byte_digest"], "source region byte digest"),
            cast(RegionDisposition, disposition),
            _identities(data["rule_ids"], "source region rule identity"),
            _identities(data["decision_ids"], "source region decision identity"),
            require_identifier(data["reason_code"], "source region reason"),
            require_digest(data["region_digest"], "source region digest"),
        )


def verify_policy_source_regions(
    paths: Mapping[str, Path],
    regions: tuple[SourceRegion1, ...],
    *,
    budget: PolicyReadBudget1,
) -> tuple[SourceRegion1, ...]:
    """Check a complete declared partition against actual bounded source-file reads.

    Parameters
    ----------
    paths : Mapping[str, Path]
        Complete supplied source-ID/path cohort, including empty sources.
    regions : tuple[SourceRegion1, ...]
        Regions sorted by source identity and start byte, without gaps or overlap.
    budget : PolicyReadBudget1
        Explicit byte, count, rule-identity and relation-reference ceilings.

    Returns
    -------
    tuple[SourceRegion1, ...]
        Exact checked records in their original declared order.

    Raises
    ------
    ValueError
        Identity, byte binding, partition completeness or a budget check fails.
    OSError
        A retained source cannot be opened.
    StableReadError
        A retained source is aliased, nonregular or unstable.

    Notes
    -----
    Each region consumes one source reference plus its rule and decision links.
    Complete byte accounting does not prove extraction semantics. Protected or
    unresolved regions remain explicit; this function grants no ready-boot,
    corpus-acceptance, read-domain or effect authority.
    """
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    limits = PolicyReadBudget1.from_dict(budget.to_dict())
    if not isinstance(regions, tuple) or len(regions) > limits.max_references:
        raise ValueError("policy regions exceed the reference budget")
    checked: list[SourceRegion1] = []
    references = 0
    rules: set[str] = set()
    previous: tuple[str, int] | None = None
    for region in regions:
        if type(region) is not SourceRegion1:
            raise ValueError("policy source region record is required")
        item = SourceRegion1.from_dict(region.to_dict())
        order = (item.source_id, item.start_byte)
        if previous is not None and order <= previous:
            raise ValueError("policy source regions must retain source and byte order")
        if item.source_id not in paths:
            raise ValueError("policy source region has an unresolved source")
        references += 1 + len(item.rule_ids) + len(item.decision_ids)
        rules.update(item.rule_ids)
        if references > limits.max_references or len(rules) > limits.max_rules:
            raise ValueError("policy source region relations exceed the budget")
        checked.append(item)
        previous = order
    payloads = read_policy_source_payloads(paths, budget=limits)
    positions = dict.fromkeys(payloads, 0)
    for item in checked:
        payload = payloads[item.source_id]
        if item.start_byte != positions[item.source_id] or item.end_byte > len(payload):
            raise ValueError("policy source partition has a gap, overlap or invalid bound")
        if (
            hashlib.sha256(payload[item.start_byte : item.end_byte]).hexdigest()
            != item.byte_digest
        ):
            raise ValueError("policy source region byte digest differs")
        positions[item.source_id] = item.end_byte
    if any(positions[source_id] != len(payload) for source_id, payload in payloads.items()):
        raise ValueError("policy source partition omits retained source bytes")
    return tuple(checked)
