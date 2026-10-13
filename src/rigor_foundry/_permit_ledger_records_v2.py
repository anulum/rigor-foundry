# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — permit ledger binary records
"""Validate the fixed permit ledger wire and derive immutable replay records."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Final
from uuid import UUID

from ._permit_ledger_storage_io_v2 import _read_exact, _write_all
from .model_primitives import parse_utc_timestamp, require_identifier

_MAGIC: Final = b"RIGOR-PERMIT-LEDGER-V2.2\n"

_RECORD: Final = struct.Struct(">B3x16s16s32sQI32s")

_RECORD_BYTES: Final = _RECORD.size

_CONSUMED: Final = 0

_RECOVERY: Final = 1

_EMPTY_ID: Final = b"\x00" * 16

_MAX_ID: Final = b"\xff" * 16

_EMPTY_DIGEST: Final = b"\x00" * 32

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)

_INITIAL_HEAD: Final = sha256(_MAGIC).digest()


@dataclass(frozen=True)
class LedgerRecordV2:
    """One validated consumption or recovery record in the fixed binary chain.

    Attributes
    ----------
    kind : int
        Zero for consumption and one for explicit torn-tail recovery.
    permit_id, single_use_id : str or None
        Canonical consumed UUIDs; recovery records carry neither ID.
    permit_digest : str or None
        Nonzero signed-permit digest for consumption, absent for recovery.
    head_digest, record_digest : str
        SHA-256 of the resulting chain and exact complete record bytes.
    """

    kind: int
    permit_id: str | None
    single_use_id: str | None
    permit_digest: str | None
    head_digest: str
    record_digest: str


def _nonce(value: object) -> bytes:
    """Require the canonical UUID carried by a signed v2 permit."""
    name = require_identifier(value, "permit_ledger.permit_id")
    try:
        parsed = UUID(name)
    except ValueError as exc:
        raise ValueError("permit ledger ID must be a canonical UUID") from exc
    if str(parsed) != name or parsed.int in (0, (1 << 128) - 1):
        raise ValueError("permit ledger ID must be a non-reserved canonical UUID")
    return parsed.bytes


def _micros(value: str, label: str) -> int:
    """Convert an exact UTC timestamp to integral microseconds since epoch."""
    instant = parse_utc_timestamp(value, label)
    delta = instant - _EPOCH
    micros = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    if not 0 < micros < 2**64:
        raise ValueError(f"{label} is outside the ledger time range")
    return micros


def _scan(
    descriptor: int,
    complete_records: int,
    *,
    nonce: bytes | None,
    anchor_count: int | None = None,
    single_use_nonce: bytes | None = None,
) -> tuple[bytes, bool, bytes | None, tuple[LedgerRecordV2, ...]]:
    """Verify the chain, UUID uniqueness, selected prefix and requested IDs."""
    os.lseek(descriptor, 0, os.SEEK_SET)
    if _read_exact(descriptor, len(_MAGIC)) != _MAGIC:
        raise PermissionError("permit ledger header differs")
    head = _INITIAL_HEAD
    found = False
    used_ids: set[bytes] = set()
    records: list[LedgerRecordV2] = []
    anchor_head = head if anchor_count == 0 else None
    for index in range(complete_records):
        raw = _read_exact(descriptor, _RECORD_BYTES)
        kind, record_id, single_use_id, digest, stamp, metadata, previous = _RECORD.unpack(raw)
        if raw[1:4] != b"\x00" * 3:
            raise PermissionError("permit ledger reserved bytes differ")
        if previous != head:
            raise PermissionError("permit ledger hash chain differs")
        if kind == _CONSUMED:
            if (
                record_id in (_EMPTY_ID, _MAX_ID)
                or single_use_id == _MAX_ID
                or (single_use_id != _EMPTY_ID and single_use_id == record_id)
                or digest == _EMPTY_DIGEST
                or stamp == 0
                or metadata != 0
            ):
                raise PermissionError("permit ledger consumption record differs")
            for used_id in (record_id, single_use_id):
                if used_id == _EMPTY_ID:
                    continue
                if used_id in used_ids:
                    raise PermissionError("permit ledger UUID appears more than once")
                used_ids.add(used_id)
                found |= used_id in (nonce, single_use_nonce)
        elif kind == _RECOVERY:
            if (
                record_id != _EMPTY_ID
                or single_use_id != _EMPTY_ID
                or digest == _EMPTY_DIGEST
                or stamp == 0
                or not 0 < metadata < _RECORD_BYTES
            ):
                raise PermissionError("permit ledger recovery record differs")
        else:
            raise PermissionError("permit ledger record kind differs")
        head = sha256(head + raw[:-32]).digest()
        records.append(
            LedgerRecordV2(
                kind=kind,
                permit_id=str(UUID(bytes=record_id)) if kind == _CONSUMED else None,
                single_use_id=(
                    str(UUID(bytes=single_use_id))
                    if kind == _CONSUMED and single_use_id != _EMPTY_ID
                    else None
                ),
                permit_digest=digest.hex() if kind == _CONSUMED else None,
                head_digest=head.hex(),
                record_digest=sha256(raw).hexdigest(),
            )
        )
        if anchor_count == index + 1:
            anchor_head = head
    return head, found, anchor_head, tuple(records)


def _append(
    descriptor: int,
    *,
    head: bytes,
    kind: int,
    nonce: bytes,
    single_use_nonce: bytes,
    digest: bytes,
    stamp: int,
    metadata: int,
) -> bytes:
    """Append and fsync one complete linked record, returning its new head."""
    raw = _RECORD.pack(kind, nonce, single_use_nonce, digest, stamp, metadata, head)
    _write_all(descriptor, raw)
    os.fsync(descriptor)
    return sha256(head + raw[:-32]).digest()


@dataclass(frozen=True)
class LedgerFileIdentityV2:
    """File identity observed while holding the actual ledger lock.

    Attributes
    ----------
    path_digest : str
        Canonical digest of the selected absolute path.
    device, inode : int
        Kernel identity of the retained descriptor, not custody authentication.
    """

    path_digest: str
    device: int
    inode: int


@dataclass(frozen=True)
class LedgerSnapshotV2:
    """Complete chain-verified history observed under one selected ledger prefix.

    Attributes
    ----------
    record_count : int
        Number of complete records in the current retained file.
    head_digest : str
        SHA-256 chain head after every returned record.
    identity : LedgerFileIdentityV2
        Path and descriptor identity observed under the ledger lock.
    records : tuple[LedgerRecordV2, ...]
        Ordered validated consumption and recovery records.

    Notes
    -----
    Constructing a snapshot does not authenticate an external protected anchor.
    """

    record_count: int
    head_digest: str
    identity: LedgerFileIdentityV2
    records: tuple[LedgerRecordV2, ...]
