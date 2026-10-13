# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact handler effect intent receipt bytes
"""Carry a bound journal frame without manufacturing cross-process token authority."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from .audit_primitives import require_exact_fields, require_mapping
from .effect_journal_records_v2 import (
    EffectJournalRecordV2,
    _uuid,
    canonical_journal_json_v2,
    parse_effect_journal_frame_v2,
)
from .model_primitives import require_digest
from .project_registry_primitives import project_registry_strict_json

HANDLER_EFFECT_INTENT_RECEIPT_MAX_BYTES_V1: Final = 65536
_SCHEMA: Final = "rigor.handler-effect-intent-receipt.v1"
_FIELDS: Final = frozenset(
    {
        "schema",
        "handler_operation_digest",
        "effect_context_digest",
        "ready_nonce",
        "journal_identity",
        "effect_intent_frame",
        "effect_intent_previous_head",
        "effect_intent_seq",
        "effect_intent_record_digest",
    }
)


def _identity(value: object) -> tuple[int, int]:
    """Decode full unsigned kernel identities from canonical decimal strings."""
    body = require_mapping(value, "effect intent journal identity")
    require_exact_fields(body, frozenset({"device", "inode"}), "effect intent journal identity")
    values: list[int] = []
    for name, minimum in (("device", 0), ("inode", 1)):
        text = body[name]
        if (
            type(text) is not str
            or not text.isascii()
            or not text.isdecimal()
            or len(text) > 20
            or (len(text) > 1 and text[0] == "0")
        ):
            raise ValueError("effect intent journal identity decimal differs")
        number = int(text)
        if not minimum <= number < 1 << 64:
            raise ValueError("effect intent journal identity range differs")
        values.append(number)
    return values[0], values[1]


def _parse(payload: bytes) -> tuple[dict[str, object], EffectJournalRecordV2]:
    """Recheck the complete bounded receipt and its exact framed intent."""
    if (
        type(payload) is not bytes
        or not 0 < len(payload) <= HANDLER_EFFECT_INTENT_RECEIPT_MAX_BYTES_V1
    ):
        raise ValueError("effect intent receipt needs bounded exact bytes")
    body = require_mapping(project_registry_strict_json(payload), "effect intent receipt")
    require_exact_fields(body, _FIELDS, "effect intent receipt")
    if body["schema"] != _SCHEMA or canonical_journal_json_v2(body) != payload:
        raise ValueError("effect intent receipt schema or canonical bytes differ")
    for name in (
        "handler_operation_digest",
        "effect_context_digest",
        "ready_nonce",
        "effect_intent_previous_head",
        "effect_intent_record_digest",
    ):
        require_digest(body[name], "effect intent receipt " + name)
    _identity(body["journal_identity"])
    seq = body["effect_intent_seq"]
    if type(seq) is not int or not 1 <= seq <= 2**53 - 1:
        raise ValueError("effect intent receipt sequence differs")
    encoded = body["effect_intent_frame"]
    if type(encoded) is not str or not encoded.isascii():
        raise ValueError("effect intent receipt frame must be ASCII base64")
    try:
        frame = base64.b64decode(encoded, validate=True)
    except binascii.Error as exc:
        raise ValueError("effect intent receipt frame base64 differs") from exc
    if base64.b64encode(frame).decode("ascii") != encoded:
        raise ValueError("effect intent receipt frame base64 is not canonical")
    previous = require_digest(body["effect_intent_previous_head"], "effect intent previous head")
    record = parse_effect_journal_frame_v2(
        frame, previous_head=bytes.fromhex(previous), expected_seq=seq
    )
    if (
        record.kind != "effect-intent"
        or record.record_digest != body["effect_intent_record_digest"]
    ):
        raise ValueError("effect intent receipt record kind or digest differs")
    return dict(body), record


@dataclass(frozen=True)
class HandlerEffectIntentReceiptV1:
    """Canonical receipt consistency data without mutation or selected authority.

    Attributes
    ----------
    canonical_bytes : bytes
        Complete bounded receipt containing its exact frame and handler bindings.

    Notes
    -----
    Use a checked builder to validate structure. Even a valid receipt cannot
    establish actual writer identity, successful fsync or process-local token issuance.
    """

    canonical_bytes: bytes

    @classmethod
    def from_bytes(cls, payload: bytes) -> HandlerEffectIntentReceiptV1:
        """Check one exact receipt and its contained intent frame.

        Parameters
        ----------
        payload
            Exact canonical UTF-8 JSON receipt, bounded to 65,536 bytes.

        Returns
        -------
        HandlerEffectIntentReceiptV1
            Structurally validated retained bytes, without journal custody proof.

        Raises
        ------
        ValueError, PermissionError
            Closed fields, canonical encoding, bindings or framed intent refuse.
        """
        _parse(payload)
        return cls(payload)

    @classmethod
    def from_record(
        cls,
        record: EffectJournalRecordV2,
        *,
        journal_identity: tuple[int, int],
        handler_operation_digest: str,
        effect_context_digest: str,
        ready_nonce: bytes,
    ) -> HandlerEffectIntentReceiptV1:
        """Encode a frame and bindings without claiming its writer or durability.

        Parameters
        ----------
        record
            Exact effect-intent record with its original frame, head and sequence.
        journal_identity
            Full kernel device/inode pair encoded as canonical unsigned decimals.
        handler_operation_digest, effect_context_digest
            Exact header and effect-context digests supplied by the operation owner.
        ready_nonce
            Original 32-byte nonce for the handler exchange.

        Returns
        -------
        HandlerEffectIntentReceiptV1
            Canonical receipt after complete structural and frame revalidation.

        Raises
        ------
        ValueError, PermissionError
            Record, identity, nonce, digests or bounded canonical bytes refuse.

        Notes
        -----
        The actual journal owner separately exports its registered post-fsync
        record. This builder establishes neither that provenance nor token issuance.
        """
        if type(record) is not EffectJournalRecordV2:
            raise ValueError("effect intent receipt needs an exact journal record")
        if (
            type(journal_identity) is not tuple
            or len(journal_identity) != 2
            or any(type(value) is not int for value in journal_identity)
        ):
            raise ValueError("effect intent receipt journal identity differs")
        if type(ready_nonce) is not bytes or len(ready_nonce) != 32:
            raise ValueError("effect intent receipt nonce must be exactly32bytes")
        body = {
            "schema": _SCHEMA,
            "handler_operation_digest": handler_operation_digest,
            "effect_context_digest": effect_context_digest,
            "ready_nonce": ready_nonce.hex(),
            "journal_identity": {
                "device": str(journal_identity[0]),
                "inode": str(journal_identity[1]),
            },
            "effect_intent_frame": base64.b64encode(record.frame).decode("ascii"),
            "effect_intent_previous_head": record.previous_head,
            "effect_intent_seq": record.seq,
            "effect_intent_record_digest": record.record_digest,
        }
        return cls.from_bytes(canonical_journal_json_v2(body))

    def to_record(self) -> EffectJournalRecordV2:
        """Reparse retained bytes and return their validated journal frame.

        Returns
        -------
        EffectJournalRecordV2
            Exact decoded effect-intent record after all receipt checks.

        Raises
        ------
        ValueError, PermissionError
            Receipt or retained frame fails structural revalidation.
        """
        return _parse(self.canonical_bytes)[1]

    def require_binding(
        self, *, handler_operation_digest: str, effect_context_digest: str, ready_nonce: bytes
    ) -> None:
        """Require the operation owner's exact header, context and original nonce.

        Parameters
        ----------
        handler_operation_digest, effect_context_digest
            Operation owner's independently retained current header/context identities.
        ready_nonce
            Exact original 32-byte nonce for this handler exchange.

        Returns
        -------
        None
            All three current bindings match the revalidated receipt.

        Raises
        ------
        ValueError
            Nonce, digest or receipt fields are malformed.
        PermissionError
            Current bindings differ or the contained frame fails verification.

        Notes
        -----
        Matching data establishes neither private endpoint custody nor actual fsync.
        """
        if type(ready_nonce) is not bytes or len(ready_nonce) != 32:
            raise ValueError("effect intent receipt nonce must be exactly32bytes")
        operation = require_digest(handler_operation_digest, "effect intent header binding")
        context = require_digest(effect_context_digest, "effect intent context binding")
        body, _ = _parse(self.canonical_bytes)
        if (
            body["handler_operation_digest"],
            body["effect_context_digest"],
            body["ready_nonce"],
        ) != (operation, context, ready_nonce.hex()):
            raise PermissionError("effect intent receipt differs from current handler operation")

    def require_effect_intent(
        self, *, permit_id: str, part_index: int, pre_state_digest: str
    ) -> None:
        """Match the exact pre-B effect operands retained by the operation owner.

        Parameters
        ----------
        permit_id, part_index
            Current canonical permit UUID and nonnegative bounded part index.
        pre_state_digest
            Independently retained current pre-state SHA-256.

        Returns
        -------
        None
            Receipt intent matches all current operands.

        Raises
        ------
        ValueError, PermissionError
            Operands, receipt/frame structure or exact current binding refuses.
        """
        _uuid(permit_id, "effect intent receipt current permit")
        if type(part_index) is not int or not 0 <= part_index <= 2**53 - 1:
            raise ValueError("effect intent receipt current part differs")
        expected = require_digest(pre_state_digest, "effect intent receipt current prestate")
        body = self.to_record().body
        if (body["permit_id"], body["part_index"], body["pre_state_digest"]) != (
            permit_id,
            part_index,
            expected,
        ):
            raise PermissionError("effect intent receipt differs from current part or prestate")

    @property
    def receipt_digest(self) -> str:
        """Hash revalidated receipt bytes without asserting host custody or token authority.

        Returns
        -------
        str
            Lowercase SHA-256 of the complete checked canonical receipt bytes.

        Raises
        ------
        ValueError, PermissionError
            Receipt or contained frame fails structural revalidation.
        """
        _parse(self.canonical_bytes)
        return sha256(self.canonical_bytes).hexdigest()
