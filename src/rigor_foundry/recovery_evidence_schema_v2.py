# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed recovery evidence objects
"""Validate the provisional V2.4/V2.1 recovery object schemas."""

from __future__ import annotations

from hashlib import sha256
from typing import Final

from ._permit_ledger_records_v2 import _micros
from .effect_journal_records_v2 import JOURNAL_MAGIC_V2
from .permit_anchor_records_v2 import ANCHOR_MAGIC_V24, ANCHOR_RECORD_V24
from .recovery_evidence_fields_v2 import (
    bounded_int,
    canonical_object_bytes,
    canonical_time,
    closed_object,
    digest,
    identity,
    parse_canonical_object_bytes,
    principal,
    removed_bytes,
)

ANCHOR_FINAL_RECOVERY_SCHEMA_VERSION: Final = "rigor.permit-anchor-final-recovery.v2.4"
ANCHOR_ADOPTION_RECOVERY_SCHEMA_VERSION: Final = "rigor.permit-anchor-recovery.v2.4"
JOURNAL_TAIL_RECOVERY_SCHEMA_VERSION: Final = "rigor.effect-journal-tail-recovery.v2.1"
_IDENTITIES: Final = frozenset({"anchor_file", "ledger_file", "journal_file"})
_OPERATOR: Final = frozenset(
    {"operator_identity", "credential_proof_ref", "recovery_code_digest", "host_time"}
)
_KIND1_FIELDS: Final = (
    _IDENTITIES
    | _OPERATOR
    | frozenset(
        {
            "domain",
            "prior_anchor_head",
            "prior_anchor_record_count",
            "prior_ledger_record_count",
            "prior_ledger_head",
            "prior_journal_head",
            "tail_offset",
            "tail_length",
            "captured_file_size",
            "removed_bytes_b64",
            "removed_digest",
            "failure_class",
            "parent_intent_digest",
        }
    )
)
_KIND2_FIELDS: Final = _IDENTITIES | frozenset(
    {
        "domain",
        "old_anchor_head",
        "old_ledger_record_count",
        "new_ledger_record_count",
        "old_ledger_head",
        "new_ledger_head",
        "old_journal_head",
        "new_journal_head",
        "adopted_ledger_record_digests",
        "included_journal_record_digests",
        "consumed_uuids_digest",
        "recovery_code_digest",
        "host_time",
    }
)
_JOURNAL_FIELDS: Final = (
    _IDENTITIES
    | _OPERATOR
    | frozenset(
        {
            "domain",
            "selected_anchor_head",
            "selected_journal_head",
            "last_complete_journal_head",
            "old_size",
            "frame_offset",
            "declared_payload_length",
            "removed_length",
            "removed_bytes_b64",
            "removed_digest",
            "failure_class",
            "parent_intent_digest",
        }
    )
)


def _identities(value: dict[str, object]) -> None:
    """Validate all three closed selected file-identity objects."""
    for field in _IDENTITIES:
        identity(value[field])


def _time(value: dict[str, object]) -> str:
    """Require a byte-canonical host time from the shared field grammar."""
    return canonical_time(value["host_time"])


def _operator(value: dict[str, object]) -> str:
    """Validate digest-only ingress attribution and canonical host time."""
    principal(value["operator_identity"])
    digest(value["credential_proof_ref"], "recovery.credential_proof_ref")
    digest(value["recovery_code_digest"], "recovery.recovery_code_digest")
    return _time(value)


def _parent(value: dict[str, object]) -> None:
    """Require either a root null or one exact child parent digest."""
    parent = value["parent_intent_digest"]
    if parent is not None:
        digest(parent, "recovery.parent_intent_digest")


def _digests(value: dict[str, object], names: frozenset[str]) -> None:
    """Validate every named exact lowercase digest field."""
    for name in names:
        digest(value[name], f"recovery.{name}")


def _removed(value: dict[str, object], *, maximum: int, length_name: str) -> bytes:
    """Check strict base64, its exact length and its SHA-256 commitment."""
    raw = removed_bytes(value["removed_bytes_b64"], maximum=maximum)
    length = bounded_int(value[length_name], minimum=1, maximum=maximum)
    if len(raw) != length or sha256(raw).hexdigest() != value["removed_digest"]:
        raise ValueError("recovery removed bytes differ from their commitment")
    return raw


def _digest_array(value: object, label: str) -> tuple[str, ...]:
    """Require an ordered array of exact lowercase digests."""
    if not isinstance(value, list):
        raise ValueError(f"{label} is not an array")
    return tuple(digest(item, label) for item in value)


def validate_anchor_final_intent_v2(value: object) -> bytes:
    """Validate one closed kind-1 intent and return its exact canonical bytes.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.

    Returns
    -------
    bytes
        Canonical kind-1 root or child intent with exact captured-byte commitments.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    item = closed_object(value, _KIND1_FIELDS, "anchor final intent")
    if item["domain"] != ANCHOR_FINAL_RECOVERY_SCHEMA_VERSION:
        raise ValueError("anchor final intent domain differs")
    _identities(item)
    _operator(item)
    _parent(item)
    _digests(
        item,
        frozenset(
            {"prior_anchor_head", "prior_ledger_head", "prior_journal_head", "removed_digest"}
        ),
    )
    prior_count = bounded_int(item["prior_anchor_record_count"], minimum=1)
    bounded_int(item["prior_ledger_record_count"], minimum=0)
    offset = bounded_int(item["tail_offset"], minimum=len(ANCHOR_MAGIC_V24) + 200)
    if offset != len(ANCHOR_MAGIC_V24) + ANCHOR_RECORD_V24.size * prior_count:
        raise ValueError("anchor final intent tail offset differs")
    raw = _removed(item, maximum=200, length_name="tail_length")
    if bounded_int(item["captured_file_size"], minimum=offset + 1) != offset + len(raw):
        raise ValueError("anchor final intent captured size differs")
    failure_class = item["failure_class"]
    if failure_class == "partial-tail":
        if len(raw) == 200:
            raise ValueError("anchor partial tail is complete")
    elif failure_class == "complete-invalid-final":
        if len(raw) != 200:
            raise ValueError("anchor final record is incomplete")
    else:
        raise ValueError("anchor final intent failure class differs")
    return canonical_object_bytes(item)


def validate_anchor_adoption_evidence_v2(value: object) -> bytes:
    """Validate one closed kind-2 evidence object and exact suffix arrays.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.

    Returns
    -------
    bytes
        Canonical kind-2 evidence with exact ordered suffix digest arrays.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    item = closed_object(value, _KIND2_FIELDS, "anchor adoption evidence")
    if item["domain"] != ANCHOR_ADOPTION_RECOVERY_SCHEMA_VERSION:
        raise ValueError("anchor adoption evidence domain differs")
    _identities(item)
    _time(item)
    _digests(
        item,
        frozenset(
            {
                "old_anchor_head",
                "old_ledger_head",
                "new_ledger_head",
                "old_journal_head",
                "new_journal_head",
                "consumed_uuids_digest",
                "recovery_code_digest",
            }
        ),
    )
    old_count = bounded_int(item["old_ledger_record_count"], minimum=0)
    new_count = bounded_int(item["new_ledger_record_count"], minimum=old_count + 1)
    adopted = _digest_array(item["adopted_ledger_record_digests"], "adopted ledger digest")
    _digest_array(item["included_journal_record_digests"], "included journal digest")
    if len(adopted) != new_count - old_count:
        raise ValueError("anchor adoption evidence suffix length differs")
    return canonical_object_bytes(item)


def validate_journal_tail_intent_v2(value: object) -> bytes:
    """Validate one closed journal terminal-fragment recovery intent.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.

    Returns
    -------
    bytes
        Canonical journal fragment intent with exact frame-length boundaries.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    item = closed_object(value, _JOURNAL_FIELDS, "journal tail intent")
    if item["domain"] != JOURNAL_TAIL_RECOVERY_SCHEMA_VERSION:
        raise ValueError("journal tail intent domain differs")
    _identities(item)
    _operator(item)
    _parent(item)
    _digests(
        item,
        frozenset(
            {
                "selected_anchor_head",
                "selected_journal_head",
                "last_complete_journal_head",
                "removed_digest",
            }
        ),
    )
    offset = bounded_int(item["frame_offset"], minimum=len(JOURNAL_MAGIC_V2))
    raw = _removed(item, maximum=65572, length_name="removed_length")
    if bounded_int(item["old_size"], minimum=offset + 1) != offset + len(raw):
        raise ValueError("journal tail captured size differs")
    declared = item["declared_payload_length"]
    if len(raw) < 4:
        if declared is not None or item["failure_class"] != "partial":
            raise ValueError("journal short length field differs")
    else:
        length = bounded_int(declared, minimum=1, maximum=65536)
        if length != int.from_bytes(raw[:4], "big"):
            raise ValueError("journal declared payload length differs")
        frame_size = 4 + length + 32
        if item["failure_class"] == "partial":
            if len(raw) >= frame_size:
                raise ValueError("journal partial frame is complete")
        elif item["failure_class"] in ("bad-head", "noncanonical"):
            if len(raw) != frame_size:
                raise ValueError("journal invalid final frame length differs")
        else:
            raise ValueError("journal tail failure class differs")
    return canonical_object_bytes(item)


def validate_recovery_evidence_bytes_v2(data: bytes) -> str:
    """Parse exact bytes and return only their closed, verified domain.

    Parameters
    ----------
    data : bytes
        Exact canonical UTF-8 evidence bytes; whitespace and duplicate-key aliases refuse.

    Returns
    -------
    str
        One of the three accepted provisional domain identifiers.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    item = parse_canonical_object_bytes(data)
    domain = item.get("domain")
    if domain == ANCHOR_FINAL_RECOVERY_SCHEMA_VERSION:
        validate_anchor_final_intent_v2(item)
    elif domain == ANCHOR_ADOPTION_RECOVERY_SCHEMA_VERSION:
        validate_anchor_adoption_evidence_v2(item)
    elif domain == JOURNAL_TAIL_RECOVERY_SCHEMA_VERSION:
        validate_journal_tail_intent_v2(item)
    else:
        raise ValueError("recovery evidence domain is unknown")
    return domain


def exact_recovery_stamp_us_v2(value: object) -> int:
    """Return the binary anchor stamp for one byte-canonical host time.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.

    Returns
    -------
    int
        Positive integral microseconds since the Unix epoch, suitable for the wire.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    return _micros(canonical_time(value), "recovery.host_time")
