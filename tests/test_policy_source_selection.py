# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual original source selection tests
"""Exercise retained capture, native and discovery owners on complete real files."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest
from discovery_source_support import limits, snapshot
from test_context_owner_implementation import implementation_budget
from test_native_source_pin import _pin
from test_source_provenance import capture, policy
from test_task_definition import definition

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.discovery_source_receipt import DiscoverySourceReceipt1
from rigor_foundry.discovery_source_schema import DiscoveryLimits
from rigor_foundry.discovery_source_validation import validate_discovery_sources
from rigor_foundry.git_inventory import StableReadError
from rigor_foundry.native_source_host import HostNativeSourceState, HostNativeSourceVerifier
from rigor_foundry.native_source_pin import NativeSourcePin
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_records import PolicySourceRecord1
from rigor_foundry.policy_source_selection import DiscoverySourceSelection, PolicySourceSelection
from rigor_foundry.retained_policy_source import RetainedPolicySource
from rigor_foundry.source_universe import SourceReadState
from rigor_foundry.typed_object_reference import TypedObjectRef1


@dataclass(frozen=True)
class SelectedPolicy:
    """Real host selections and externally mutable host pin/revocation state for tests."""

    source: PolicySourceSelection
    host: list[HostNativeSourceState]
    root: Path
    path: Path


@contextmanager
def selection(
    root: Path,
    kind: str = "capture",
    *,
    state: SourceReadState = "verified",
    fault: str = "",
    capture_payload: bytes = b"original\r\npolicy\x00\xff",
) -> Iterator[SelectedPolicy]:
    """Select real original files before retaining any source/parent descriptors."""
    root.mkdir()
    raw_root, meta_root = root / "raw", root / "metadata"
    raw_root.mkdir()
    meta_root.mkdir()
    budget = implementation_budget()
    host: list[HostNativeSourceState] = []
    native = None
    question = reply = None
    discovery = None
    source_id = "policy"
    record: PolicySourceRecord1
    if kind == "native":
        pin, arguments, path = _pin(raw_root)
        source_id = pin.source_id
        record = PolicySourceRecord1(pin, budget)
        host_pin = pin
        if fault == "foreign-host":
            data = pin.to_dict()
            data.pop("pin_digest")
            data["source_id"] = "other-host-source"
            host_pin = NativeSourcePin.from_dict({**data, "pin_digest": canonical_digest(data)})
        host.append(HostNativeSourceState(host_pin, host_pin.pin_digest, frozenset()))
        native = HostNativeSourceVerifier(lambda: nullcontext(host[0]))
        question, reply = arguments["question_capture"], arguments["reply_capture"]
    elif kind == "discovery":
        snapshot(raw_root)
        original_limits = limits(raw_root)
        data = validate_discovery_sources(raw_root, "manifest.json", limits=original_limits)
        if fault == "foreign-limits":
            changed_limits = cast(dict[str, object], data["limits"])
            changed_limits["total_bytes"] = cast(int, changed_limits["total_bytes"]) + 1
            data.pop("receipt_digest")
            data["receipt_digest"] = canonical_digest(data)
        record = PolicySourceRecord1(
            DiscoverySourceReceipt1.from_dict(data, budget=budget), budget
        )
        discovery = DiscoverySourceSelection(raw_root, "manifest.json", original_limits)
        source_id = "source0"
        path = raw_root / "source0.txt"
        if fault == "manifest":
            manifest = raw_root / "manifest.json"
            manifest.write_bytes(manifest.read_bytes() + b" ")
    else:
        path = raw_root / "captured.bin"
        path.write_bytes(capture_payload)
        record = PolicySourceRecord1(
            capture(
                path.read_bytes(),
                retrieval_policy=policy(maximum_bytes=max(4096, len(capture_payload))),
            ),
            budget,
        )
    if fault == "payload":
        path.write_bytes(b"different source bytes")
    elif fault == "path":
        alias = raw_root / "other-file"
        alias.write_bytes(path.read_bytes())
        path = alias
    if fault == "wrong-kind":
        wire = definition().to_dict()
        reference = TypedObjectRef1.from_dict(definition().reference())
    else:
        wire = record.to_dict()
        reference = TypedObjectRef1.from_dict(record.reference())
    metadata_path = meta_root / "record.json"
    metadata_bytes = json.dumps(wire).encode()
    metadata_path.write_bytes(metadata_bytes)
    with ExitStack() as stack:
        metadata = stack.enter_context(
            RetainedContextSource(
                metadata_path,
                reference=reference,
                raw_digest=hashlib.sha256(metadata_bytes).hexdigest(),
                budget=budget,
            )
        )
        payload = None
        if state == "verified":
            raw = path.read_bytes()
            payload = stack.enter_context(
                RetainedPolicySource(
                    path,
                    byte_digest=hashlib.sha256(raw).hexdigest(),
                    byte_count=len(raw),
                    budget=budget,
                )
            )
        else:
            native = question = reply = discovery = None
        selected = PolicySourceSelection(
            source_id,
            metadata,
            "internal",
            "opaque:source",
            state,
            "included",
            None,
            payload,
            native,
            question,
            reply,
            discovery,
        )
        yield SelectedPolicy(selected, host, raw_root, path)


@pytest.mark.parametrize("kind", ["capture", "native", "discovery"])
def test_actual_original_source_owners_retain_exact_byte_and_record_meanings(
    tmp_path: Path, kind: str
) -> None:
    """Owning source reads agree with unchanged original capture/native/discovery models."""
    with selection(tmp_path / "selected", kind) as actual:
        first = actual.source.read(budget=implementation_budget())
        assert first.payload == actual.path.read_bytes()
        assert actual.source.read(budget=implementation_budget()) == first
        assert first.record == actual.source.metadata.read()
        assert len(first.snapshot_id) == len(first.verification_digest) == 64
        assert first.record.reference()["object_digest"] != first.snapshot_id


@pytest.mark.parametrize("state", ["unread", "unavailable", "protected"])
@pytest.mark.parametrize("kind", ["capture", "native", "discovery"])
def test_explicit_held_sources_do_not_open_original_payloads(
    tmp_path: Path, state: SourceReadState, kind: str
) -> None:
    """No installed raw/native/discovery reader is needed to retain a held metadata row."""
    with selection(tmp_path / "selected", kind, state=state) as actual:
        actual.path.unlink()
        read = actual.source.read(budget=implementation_budget())
        assert read.payload is None
        assert read.verification_digest == read.record.reference()["object_digest"]


@pytest.mark.parametrize(
    ("kind", "fault"),
    [
        ("capture", "payload"),
        ("capture", "wrong-kind"),
        ("native", "foreign-host"),
        ("native", "path"),
        ("discovery", "path"),
        ("discovery", "payload"),
        ("discovery", "manifest"),
        ("discovery", "foreign-limits"),
    ],
)
def test_actual_original_owner_mismatch_cannot_borrow_a_valid_label(
    tmp_path: Path, kind: str, fault: str
) -> None:
    """Real mismatched files, manifest bytes and valid foreign host pins refuse selection."""
    with selection(tmp_path / "selected", kind, fault=fault) as actual, pytest.raises(ValueError):
        actual.source.read(budget=implementation_budget())


def test_current_host_revocation_is_rechecked_and_not_replaced_by_metadata(tmp_path: Path) -> None:
    """Actual host state changes between public reads invalidate the original native source."""
    with selection(tmp_path / "selected", "native") as actual:
        assert actual.source.read(budget=implementation_budget()).payload is not None
        current = actual.host[0]
        actual.host[0] = replace(
            current, revoked_pin_digests=frozenset({current.expected_pin_digest})
        )
        with pytest.raises(PermissionError, match="revoked"):
            actual.source.read(budget=implementation_budget())


def test_selection_types_read_states_and_original_source_ids_refuse(tmp_path: Path) -> None:
    """Host composition requires actual concrete readers and exact original source roles."""
    with selection(tmp_path / "selected", "native") as actual:
        mutations: tuple[dict[str, object], ...] = (
            {"metadata": {}},
            {"read_state": "accepted"},
            {"payload": None},
            {"read_state": "protected"},
        )
        for changed in mutations:
            with pytest.raises(ValueError):
                PolicySourceSelection(**{**actual.source.__dict__, **changed})
        with pytest.raises(ValueError, match="native source identity"):
            replace(actual.source, source_id="foreign").read(budget=implementation_budget())
        native_changes: tuple[dict[str, object], ...] = (
            {"native_verifier": None},
            {"question_capture": None},
            {"reply_capture": None},
            {"discovery": {}},
        )
        for changed in native_changes:
            with pytest.raises(ValueError, match="host verifier"):
                PolicySourceSelection(**{**actual.source.__dict__, **changed}).read(
                    budget=implementation_budget()
                )
    with selection(tmp_path / "capture") as actual:
        with pytest.raises(ValueError, match="borrow"):
            replace(actual.source, question_capture=b"caller").read(budget=implementation_budget())
        with pytest.raises(ValueError, match="processing byte budget"):
            actual.source.read(budget=implementation_budget(max_source_bytes=1))
        with pytest.raises(ValueError, match="budget is required"):
            actual.source.read(budget=cast(PolicyReadBudget1, {}))
    with selection(tmp_path / "discovery", "discovery") as actual:
        with pytest.raises(ValueError, match="source identity is absent"):
            replace(actual.source, source_id="foreign").read(budget=implementation_budget())
        discovery_changes: tuple[dict[str, object], ...] = (
            {"discovery": None},
            {"question_capture": b"caller"},
        )
        for changed in discovery_changes:
            with pytest.raises(ValueError, match="snapshot owner"):
                PolicySourceSelection(**{**actual.source.__dict__, **changed}).read(
                    budget=implementation_budget()
                )


def test_original_discovery_processing_is_bounded_without_normalizing_receipt(
    tmp_path: Path,
) -> None:
    """Whole original validator limits must fit explicit current processing ceilings."""
    with selection(tmp_path / "selected", "discovery") as actual:
        source = actual.source
        selected = source.discovery
        assert selected is not None and source.payload is not None
        record = source.metadata.read()
        assert isinstance(record, PolicySourceRecord1) and isinstance(
            record.record, DiscoverySourceReceipt1
        )
        for changes in (
            {"max_total_source_bytes": 1},
            {"max_source_bytes": 1},
            {"max_sources": 1},
            {"max_references": 1},
        ):
            with pytest.raises(ValueError, match="processing limits"):
                selected.verify(
                    source_id=source.source_id,
                    source=source.payload,
                    receipt=record.record,
                    budget=implementation_budget(**changes),
                )
        with pytest.raises(StableReadError):
            selected.verify(
                source_id=source.source_id,
                source=source.payload,
                receipt=record.record,
                budget=implementation_budget(max_document_bytes=1),
            )
        with pytest.raises(ValueError, match="absent from the original discovery manifest"):
            selected.verify(
                source_id="absent",
                source=source.payload,
                receipt=record.record,
                budget=implementation_budget(),
            )
        with pytest.raises(ValueError, match="budget is required"):
            selected.verify(
                source_id=source.source_id,
                source=source.payload,
                receipt=record.record,
                budget=cast(PolicyReadBudget1, {}),
            )
        with pytest.raises(ValueError, match="actual original discovery"):
            selected.verify(
                source_id=source.source_id,
                source=cast(RetainedPolicySource, {}),
                receipt=record.record,
                budget=implementation_budget(),
            )


def test_discovery_host_selection_is_not_a_wire_root_or_unbounded_limit(tmp_path: Path) -> None:
    """Actual untraversed root/manifest/limit selections must be supplied by the host."""
    budget = DiscoveryLimits(10, 10, 1, 1, 1, 1)
    for root in (Path("relative"), tmp_path / ".." / "other", cast(Path, "caller")):
        with pytest.raises(ValueError, match="absolute untraversed"):
            DiscoverySourceSelection(root, "manifest.json", budget)
    with pytest.raises(ValueError):
        DiscoverySourceSelection(tmp_path, "../manifest.json", budget)
    with pytest.raises(ValueError, match="actual discovery limits"):
        DiscoverySourceSelection(tmp_path, "manifest.json", cast(DiscoveryLimits, {}))
