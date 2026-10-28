# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original policy source record tests
"""Preserve actual capture/native parser identities through retained source APIs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_discovery_source_receipt import receipt
from test_native_source_pin import _pin
from test_source_provenance import capture

from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.context_source_resolution import parse_context_source_target
from rigor_foundry.discovery_source_receipt import DiscoverySourceReceipt1
from rigor_foundry.native_source_pin import NativeSourcePin
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_records import (
    PolicySourceRecord,
    PolicySourceRecord1,
    parse_policy_source_record,
)
from rigor_foundry.source_capture import SourceCapture
from rigor_foundry.typed_object_reference import TypedObjectRef1


def records(tmp_path: Path) -> tuple[PolicySourceRecord1, ...]:
    """Reuse original public capture and real native-file fixtures without new source meanings."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    pin, _, _ = _pin(tmp_path)
    discovery_root = tmp_path / "discovery"
    discovery_root.mkdir()
    discovery = DiscoverySourceReceipt1.from_dict(
        receipt(discovery_root), budget=implementation_budget()
    )
    return tuple(
        PolicySourceRecord1(item, implementation_budget()) for item in (capture(), pin, discovery)
    )


@pytest.mark.parametrize("position", (0, 1, 2))
def test_original_records_keep_exact_identity_through_retained_json(
    tmp_path: Path, position: int
) -> None:
    """Actual owning parsers and retained file readers preserve every old field and digest."""
    item = records(tmp_path / "native")[position]
    payload = json.dumps(item.record.to_dict()).encode()
    ref = TypedObjectRef1.from_dict(item.reference())
    path = tmp_path / "metadata.json"
    path.write_bytes(payload)
    with RetainedContextSource(
        path,
        reference=ref,
        raw_digest=hashlib.sha256(payload).hexdigest(),
        budget=implementation_budget(),
    ) as source:
        assert source.read() == item
        assert source.read().to_dict() == item.record.to_dict()
        assert (
            parse_context_source_target(ref, item.record.to_dict(), budget=implementation_budget())
            == item
        )
    assert (
        parse_policy_source_record(
            ref.kind, item.record.to_dict(), budget=implementation_budget(max_references=2048)
        )
        == item
    )
    if isinstance(item.record, SourceCapture):
        assert ref.object_id == ref.object_digest == item.record.capture_digest
        assert ref.object_digest != item.record.payload_digest
    elif isinstance(item.record, NativeSourcePin):
        assert ref.object_id == item.record.source_id
        assert ref.object_digest == item.record.pin_digest
    else:
        assert ref.object_id == ref.object_digest == item.record.receipt_digest


def test_closed_original_record_fields_and_fixed_versions_refuse(tmp_path: Path) -> None:
    """Neither new fields nor an unrelated owning version appoint a source parser."""
    for item in records(tmp_path):
        ref = TypedObjectRef1.from_dict(item.reference())
        data = item.to_dict()
        for changed in [
            {**data, "loader": "caller"},
            {**data, "schema_version": "unsupported"},
            {
                **data,
                {
                    "source-capture": "capture_digest",
                    "native-source-pin": "pin_digest",
                    "discovery-source-receipt": "receipt_digest",
                }[ref.kind]: "f" * 64,
            },
        ]:
            with pytest.raises(ValueError):
                parse_policy_source_record(ref.kind, changed, budget=implementation_budget())
        foreign = TypedObjectRef1.build(
            kind=ref.kind,
            format_version=ref.format_version,
            object_id=ref.object_id,
            object_digest="f" * 64,
        )
        with pytest.raises(ValueError):
            parse_context_source_target(foreign, data, budget=implementation_budget())


def test_original_record_budgets_types_and_noncanonical_instances_refuse(tmp_path: Path) -> None:
    """Whole decoded limits and original revalidation precede retained record use."""
    limits = implementation_budget()
    with pytest.raises(ValueError, match="unsupported"):
        parse_policy_source_record("caller", {}, budget=limits)
    with pytest.raises(ValueError, match="budget is required"):
        parse_policy_source_record("source-capture", {}, budget=cast(PolicyReadBudget1, {}))
    for payload in [{"large": [0] * 8}, {"nested": {"deeper": []}}, {"tuple": (0,) * 8}]:
        with pytest.raises(ValueError, match="budget"):
            parse_policy_source_record(
                "source-capture",
                payload,
                budget=implementation_budget(max_references=4, max_depth=2),
            )
    with pytest.raises(ValueError, match="actual original"):
        PolicySourceRecord1(cast(PolicySourceRecord, {}), limits)
    original, _, _ = _pin(tmp_path)
    altered = replace(original, root=cast(Path, str(original.root)))
    with pytest.raises(ValueError, match="differs from its original"):
        PolicySourceRecord1(altered, limits)
