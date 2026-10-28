# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original policy source metadata adapters
"""Resolve original capture and native-pin records without changing their wire identities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeAlias

from .audit_primitives import require_mapping
from .discovery_source_receipt import DiscoverySourceReceipt1
from .native_source_pin import NATIVE_SOURCE_PIN_SCHEMA, NativeSourcePin
from .policy_read_budget import PolicyReadBudget1
from .source_capture import SOURCE_PROVENANCE_SCHEMA_VERSION, SourceCapture
from .typed_object_reference import TypedObjectRef1

PolicySourceRecord: TypeAlias = SourceCapture | NativeSourcePin | DiscoverySourceReceipt1


def _bounded(value: object, budget: PolicyReadBudget1, remaining: list[int], depth: int) -> None:
    """Bound every decoded collection before an original child parser allocates it."""
    if not isinstance(value, (dict, list, tuple)):
        return
    remaining[0] -= len(value)
    if remaining[0] < 0 or depth >= budget.max_depth:
        raise ValueError("policy source record exceeds its reference or depth budget")
    children = value.values() if isinstance(value, dict) else value
    for child in children:
        _bounded(child, budget, remaining, depth + 1)


def _parse(kind: str, value: object, budget: PolicyReadBudget1) -> PolicySourceRecord:
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    limits = PolicyReadBudget1.from_dict(budget.to_dict())
    if kind not in {"source-capture", "native-source-pin", "discovery-source-receipt"}:
        raise ValueError("unsupported original policy source record")
    _bounded(value, limits, [limits.max_references], 0)
    data = require_mapping(value, "original policy source record")
    if kind == "source-capture":
        return SourceCapture.from_dict(data)
    if kind == "native-source-pin":
        return NativeSourcePin.from_dict(data)
    return DiscoverySourceReceipt1.from_dict(data, budget=limits)


@dataclass(frozen=True)
class PolicySourceRecord1:
    """Retained-reader adapter for one original source metadata record.

    Parameters
    ----------
    record : SourceCapture, NativeSourcePin or DiscoverySourceReceipt1
        Actual original owning model, preserving its complete serialized bytes.
    budget : PolicyReadBudget1
        Explicit collection/depth limits, separate from record identity.

    Raises
    ------
    ValueError
        If the model, original digest or bounded child parsing fails.

    Notes
    -----
    The adapter verifies metadata integrity. It grants no access, native issuer
    trust, semantic acceptance or authority to retrieve the referenced payload.
    """

    record: PolicySourceRecord
    budget: PolicyReadBudget1 = field(compare=False, repr=False)

    def __post_init__(self) -> None:
        """Require an actual original record under its explicit parse limits."""
        self.to_dict()

    def to_dict(self) -> dict[str, object]:
        """Revalidate and serialize the unchanged original metadata record.

        Returns
        -------
        dict of str to object
            Every original field, including its independently checked digest.

        Raises
        ------
        ValueError
            If the actual model, limits or original identity is inconsistent.
        """
        if type(self.record) not in {SourceCapture, NativeSourcePin, DiscoverySourceReceipt1}:
            raise ValueError("actual original policy source record is required")
        if isinstance(self.record, SourceCapture):
            kind = "source-capture"
        elif isinstance(self.record, NativeSourcePin):
            kind = "native-source-pin"
        else:
            kind = "discovery-source-receipt"
        data = self.record.to_dict()
        if _parse(kind, data, self.budget) != self.record:
            raise ValueError("policy source record differs from its original owning parser")
        return data

    def reference(self) -> dict[str, object]:
        """Bind the original complete record identity without interpreting its locator.

        Returns
        -------
        dict of str to object
            Exact supported kind/version and original identity/digest.

        Raises
        ------
        ValueError
            If original record integrity, explicit budgets or format validation fails.
        """
        self.to_dict()
        if isinstance(self.record, SourceCapture):
            kind, version = "source-capture", SOURCE_PROVENANCE_SCHEMA_VERSION
            identity = digest = self.record.capture_digest
        elif isinstance(self.record, NativeSourcePin):
            kind, version = "native-source-pin", NATIVE_SOURCE_PIN_SCHEMA
            identity, digest = self.record.source_id, self.record.pin_digest
        else:
            kind, version = "discovery-source-receipt", self.record.schema_version
            identity = digest = self.record.receipt_digest
        return TypedObjectRef1.build(
            kind=kind, format_version=version, object_id=identity, object_digest=digest
        ).to_dict()


def parse_policy_source_record(
    kind: str, value: object, *, budget: PolicyReadBudget1
) -> PolicySourceRecord1:
    """Parse original source metadata through its fixed, bounded owning parser.

    Parameters
    ----------
    kind : str
        Exact source-capture, native-source-pin or discovery-source-receipt role.
    value : object
        Complete original decoded source metadata.
    budget : PolicyReadBudget1
        Explicit allocation and nesting limits before child parsing.

    Returns
    -------
    PolicySourceRecord1
        Validated original record with the retained-reader interface.

    Raises
    ------
    ValueError
        If the kind, bounds, fields, original version or digest fails.
    """
    return PolicySourceRecord1(_parse(kind, value, budget), budget)
