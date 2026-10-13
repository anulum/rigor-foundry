# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual journal export and receipt consistency tests
"""Exercise receipts from actual fsynced journal records and hostile altered wire bytes."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from rigor_foundry.effect_intent_token_v2 import EffectIntentBindingV2, EffectIntentTokenV2
from rigor_foundry.effect_journal_records_v2 import (
    EffectJournalRecordV2,
)
from rigor_foundry.effect_journal_v2 import EffectJournalStoreV2
from rigor_foundry.handler_effect_intent_receipt_v1 import HandlerEffectIntentReceiptV1

_TIME = "2026-10-01T18:28:00Z"
_HEADER = "a" * 64
_CONTEXT = "b" * 64
_NONCE = bytes(range(32))
_PRESTATE = "c" * 64


def receipt_fixture(
    tmp_path: Path, *, handler_operation_digest: str = _HEADER
) -> HandlerEffectIntentReceiptV1:
    """Export an actual issued intent from a real cooperative journal lease."""
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    store = EffectJournalStoreV2(custody / "effect.journal")
    head = store.initialize()
    permit = str(uuid4())
    with store.locked(selected_head_digest=head, max_bytes=100000) as lease:
        token = lease.append_effect_intent_from_host(
            body={"permit_id": permit, "part_index": 0, "pre_state_digest": _PRESTATE},
            host_time=_TIME,
        )
        current = EffectIntentBindingV2(permit, 0, lease.snapshot.records[-1].record_digest)
        return lease.export_effect_intent_receipt_for_handler(
            token,
            current=current,
            handler_operation_digest=handler_operation_digest,
            effect_context_digest=_CONTEXT,
            ready_nonce=_NONCE,
        )


def test_real_export_retains_actual_frame_and_independent_bindings(tmp_path: Path) -> None:
    """Returned bytes match the durable frame and are not a mutation token."""
    receipt = receipt_fixture(tmp_path)
    record = receipt.to_record()
    assert record.kind == "effect-intent"
    assert record.body["pre_state_digest"] == _PRESTATE
    assert (tmp_path / "custody/effect.journal").read_bytes().endswith(record.frame)
    receipt.require_binding(
        handler_operation_digest=_HEADER, effect_context_digest=_CONTEXT, ready_nonce=_NONCE
    )
    receipt.require_effect_intent(
        permit_id=cast(str, record.body["permit_id"]), part_index=0, pre_state_digest=_PRESTATE
    )
    assert receipt.receipt_digest == sha256(receipt.canonical_bytes).hexdigest()
    assert not isinstance(receipt, EffectIntentTokenV2)
    with pytest.raises(PermissionError, match="issued by the journal"):
        EffectIntentTokenV2.require_current(
            cast(EffectIntentTokenV2, receipt),
            EffectIntentBindingV2(cast(str, record.body["permit_id"]), 0, record.record_digest),
        )
    assert HandlerEffectIntentReceiptV1.from_bytes(receipt.canonical_bytes) == receipt


@pytest.mark.parametrize("identity", [(0, 1), (2**64 - 1, 2**64 - 1)])
def test_full_uint64_structural_identity_roundtrip(
    tmp_path: Path, identity: tuple[int, int]
) -> None:
    """The carrier supports full native integer identities without selecting them."""
    original = receipt_fixture(tmp_path)
    receipt = HandlerEffectIntentReceiptV1.from_record(
        original.to_record(),
        journal_identity=identity,
        handler_operation_digest=_HEADER,
        effect_context_digest=_CONTEXT,
        ready_nonce=_NONCE,
    )
    body = json.loads(receipt.canonical_bytes)
    assert body["journal_identity"] == {"device": str(identity[0]), "inode": str(identity[1])}


@pytest.mark.parametrize(
    "case",
    [
        "extra",
        "missing",
        "schema",
        "noncanonical",
        "bad-digest",
        "identity-type",
        "identity-extra",
        "identity-numeric",
        "identity-unicode",
        "identity-leading-zero",
        "identity-length",
        "identity-range",
        "identity-zero-inode",
        "sequence-zero",
        "sequence-bool",
        "sequence-range",
        "frame-type",
        "frame-unicode",
        "frame-base64",
        "frame-pad-bits",
        "frame-incomplete",
        "frame-corrupt",
        "record-digest",
        "previous-head",
    ],
)
def test_altered_actual_receipt_wire_refuses(tmp_path: Path, case: str) -> None:
    """An altered exact receipt cannot hide wrong identity, frame, schema or encoding."""
    receipt = receipt_fixture(tmp_path)
    body = cast(dict[str, object], json.loads(receipt.canonical_bytes))
    identity = cast(dict[str, object], body["journal_identity"])
    match case:
        case "extra":
            body["unknown"] = 0
        case "missing":
            del body["effect_context_digest"]
        case "schema":
            body["schema"] = "old"
        case "noncanonical":
            pass
        case "bad-digest":
            body["ready_nonce"] = "no"
        case "identity-type":
            body["journal_identity"] = []
        case "identity-extra":
            identity["unknown"] = "0"
        case "identity-numeric":
            identity["device"] = 1
        case "identity-unicode":
            identity["device"] = "１"
        case "identity-leading-zero":
            identity["device"] = "00"
        case "identity-length":
            identity["device"] = "1" * 21
        case "identity-range":
            identity["device"] = str(2**64)
        case "identity-zero-inode":
            identity["inode"] = "0"
        case "sequence-zero":
            body["effect_intent_seq"] = 0
        case "sequence-bool":
            body["effect_intent_seq"] = True
        case "sequence-range":
            body["effect_intent_seq"] = 2**53
        case "frame-type":
            body["effect_intent_frame"] = 1
        case "frame-unicode":
            body["effect_intent_frame"] = "é"
        case "frame-base64":
            body["effect_intent_frame"] = "!"
        case "frame-pad-bits":
            body["effect_intent_frame"] = "AB=="
        case "frame-incomplete":
            body["effect_intent_frame"] = "AA=="
        case "frame-corrupt":
            frame = receipt.to_record().frame
            body["effect_intent_frame"] = base64.b64encode(
                frame[:-1] + bytes([frame[-1] ^ 1])
            ).decode()
        case "record-digest":
            body["effect_intent_record_digest"] = "d" * 64
        case "previous-head":
            body["effect_intent_previous_head"] = "e" * 64
        case _:
            raise AssertionError("unknown altered receipt case")
    payload = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if case == "noncanonical":
        payload += b"\n"
    with pytest.raises((ValueError, PermissionError)):
        HandlerEffectIntentReceiptV1.from_bytes(payload)


@pytest.mark.parametrize("payload", [b"", b"x" * 65537, cast(bytes, "text")])
def test_wrong_receipt_type_and_budget_refuse(payload: bytes) -> None:
    """No direct input bypasses the exact bytes and complete body ceiling."""
    with pytest.raises(ValueError, match="bounded exact bytes"):
        HandlerEffectIntentReceiptV1.from_bytes(payload)


@pytest.mark.parametrize("identity", [cast(tuple[int, int], [0, 1]), (True, 1), (0, 1, 2)])
def test_builder_rejects_invalid_identity_shape(tmp_path: Path, identity: tuple[int, int]) -> None:
    """Malformed builder identity fails without an assumed selected source."""
    with pytest.raises(ValueError, match="journal identity"):
        HandlerEffectIntentReceiptV1.from_record(
            receipt_fixture(tmp_path).to_record(),
            journal_identity=identity,
            handler_operation_digest=_HEADER,
            effect_context_digest=_CONTEXT,
            ready_nonce=_NONCE,
        )


def test_builder_rejects_wrong_record_and_non_intent_frame(tmp_path: Path) -> None:
    """Even a structurally valid journal outcome cannot supply intent receipt data."""
    with pytest.raises(ValueError, match="exact journal record"):
        HandlerEffectIntentReceiptV1.from_record(
            cast(EffectJournalRecordV2, None),
            journal_identity=(0, 1),
            handler_operation_digest=_HEADER,
            effect_context_digest=_CONTEXT,
            ready_nonce=_NONCE,
        )
    receipt = receipt_fixture(tmp_path)
    store = EffectJournalStoreV2(tmp_path / "custody/effect.journal")
    with store.locked(
        selected_head_digest=receipt.to_record().record_head, max_bytes=100000
    ) as lease:
        record = lease.append_from_host(
            kind="effect-complete",
            body={
                "permit_id": receipt.to_record().body["permit_id"],
                "part_index": 0,
                "post_state_digest": _PRESTATE,
            },
            host_time=_TIME,
        )
        with pytest.raises(ValueError, match="record kind or digest"):
            HandlerEffectIntentReceiptV1.from_record(
                record,
                journal_identity=(0, 1),
                handler_operation_digest=_HEADER,
                effect_context_digest=_CONTEXT,
                ready_nonce=_NONCE,
            )


@pytest.mark.parametrize("nonce", [b"", cast(bytes, "n" * 32)])
def test_wrong_nonce_types_refuse_at_builder_and_binding(tmp_path: Path, nonce: bytes) -> None:
    """A nonce must be the original32 exact bytes, never caller text or an empty default."""
    receipt = receipt_fixture(tmp_path)
    with pytest.raises(ValueError, match="nonce"):
        HandlerEffectIntentReceiptV1.from_record(
            receipt.to_record(),
            journal_identity=(0, 1),
            handler_operation_digest=_HEADER,
            effect_context_digest=_CONTEXT,
            ready_nonce=nonce,
        )
    with pytest.raises(ValueError, match="nonce"):
        receipt.require_binding(
            handler_operation_digest=_HEADER, effect_context_digest=_CONTEXT, ready_nonce=nonce
        )


@pytest.mark.parametrize("field", ["header", "context", "nonce", "permit", "part", "prestate"])
def test_current_owner_binding_mismatch_refuses(tmp_path: Path, field: str) -> None:
    """A valid receipt for a different current operation never satisfies the binding."""
    receipt = receipt_fixture(tmp_path)
    record = receipt.to_record()
    with pytest.raises(PermissionError):
        if field in {"header", "context", "nonce"}:
            receipt.require_binding(
                handler_operation_digest="d" * 64 if field == "header" else _HEADER,
                effect_context_digest="e" * 64 if field == "context" else _CONTEXT,
                ready_nonce=b"x" * 32 if field == "nonce" else _NONCE,
            )
        else:
            receipt.require_effect_intent(
                permit_id=str(uuid4())
                if field == "permit"
                else cast(str, record.body["permit_id"]),
                part_index=1 if field == "part" else 0,
                pre_state_digest="e" * 64 if field == "prestate" else _PRESTATE,
            )


@pytest.mark.parametrize("part", [True, -1, 2**53])
def test_current_part_validation_and_direct_instance_refusal(tmp_path: Path, part: int) -> None:
    """Malformed current parts and altered direct instances cannot bypass reparsing."""
    receipt = receipt_fixture(tmp_path)
    with pytest.raises(ValueError, match="current part"):
        receipt.require_effect_intent(
            permit_id=cast(str, receipt.to_record().body["permit_id"]),
            part_index=part,
            pre_state_digest=_PRESTATE,
        )
    altered = replace(receipt, canonical_bytes=b"bad")
    with pytest.raises(ValueError):
        _ = altered.receipt_digest
    with pytest.raises(ValueError):
        altered.to_record()


def test_export_refuses_foreign_closed_or_changed_journal_and_retains_issued_bytes(
    tmp_path: Path,
) -> None:
    """Only the issuing journal's active actual token can export immutable frame bytes."""
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    store = EffectJournalStoreV2(custody / "journal")
    head = store.initialize()
    other = EffectJournalStoreV2(custody / "other")
    other_head = other.initialize()
    permit = str(uuid4())
    with store.locked(selected_head_digest=head, max_bytes=100000) as lease:
        token = lease.append_effect_intent_from_host(
            body={"permit_id": permit, "part_index": 0, "pre_state_digest": _PRESTATE},
            host_time=_TIME,
        )
        record = lease.snapshot.records[-1]
        current = EffectIntentBindingV2(permit, 0, record.record_digest)
        record.body["permit_id"] = str(uuid4())
        receipt = lease.export_effect_intent_receipt_for_handler(
            token,
            current=current,
            handler_operation_digest=_HEADER,
            effect_context_digest=_CONTEXT,
            ready_nonce=_NONCE,
        )
        assert receipt.to_record().body["permit_id"] == permit
        with (
            other.locked(selected_head_digest=other_head, max_bytes=100000) as foreign,
            pytest.raises(PermissionError, match="another journal"),
        ):
            foreign.export_effect_intent_receipt_for_handler(
                token,
                current=current,
                handler_operation_digest=_HEADER,
                effect_context_digest=_CONTEXT,
                ready_nonce=_NONCE,
            )
        original_fd = lease.descriptor
        foreign_fd = os.open(other.path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            lease.descriptor = foreign_fd
            with pytest.raises(PermissionError, match="descriptor changed"):
                lease.export_effect_intent_receipt_for_handler(
                    token,
                    current=current,
                    handler_operation_digest=_HEADER,
                    effect_context_digest=_CONTEXT,
                    ready_nonce=_NONCE,
                )
        finally:
            lease.descriptor = original_fd
            os.close(foreign_fd)
        lease.append_from_host(
            kind="effect-complete",
            body={"permit_id": permit, "part_index": 0, "post_state_digest": _PRESTATE},
            host_time=_TIME,
        )
        with pytest.raises(PermissionError, match="invalidated"):
            lease.export_effect_intent_receipt_for_handler(
                token,
                current=current,
                handler_operation_digest=_HEADER,
                effect_context_digest=_CONTEXT,
                ready_nonce=_NONCE,
            )
