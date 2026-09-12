# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — immutable discovery progress replay
"""Replay receipt-binding changes without editing candidate content or authority."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .audit_primitives import canonical_digest, require_mapping
from .discovery_source_schema import (
    DiscoveryValidationError,
    capture_name,
    digest,
    exact_object,
    identifier,
    nonempty_list,
    parse_json,
)
from .git_inventory import open_directory_no_follow, read_stable_regular_file_at

_PROGRESS_SCHEMA_VERSION = "discovery-progress-change.v1"


@dataclass(frozen=True)
class ProgressLimits:
    """Bound all input bytes, records, transactions and changes per transaction."""

    total_bytes: int
    file_bytes: int
    records: int
    transactions: int
    changes: int

    def __post_init__(self) -> None:
        """Reject unbounded, boolean and nonpositive resource limits."""
        for value in (
            self.total_bytes,
            self.file_bytes,
            self.records,
            self.transactions,
            self.changes,
        ):
            if type(value) is not int or not 0 < value <= 2**31 - 1:
                raise DiscoveryValidationError("invalid-progress-limit")


@dataclass
class _Reader:
    """Read explicit flat captures under one opened directory and aggregate budget."""

    descriptor: int
    limits: ProgressLimits
    remaining: int

    def read(self, name: str) -> object:
        """Parse one stable, single-link regular file without following links."""
        name = capture_name(name)
        maximum = min(self.remaining, self.limits.file_bytes)
        result = read_stable_regular_file_at(
            self.descriptor,
            name,
            name,
            buffer_limit=maximum,
            maximum_bytes=maximum,
            require_single_link=True,
        )
        self.remaining -= result.byte_size
        if (
            result.payload is None
        ):  # pragma: no cover -- equal read/buffer bounds guarantee payload
            raise DiscoveryValidationError("progress-buffer-unavailable")
        return parse_json(result.payload)


def _state(value: object, limit: int) -> dict[str, object]:
    """Validate immutable candidate identities and all existing receipt references."""
    state = exact_object(value, "records receipts")
    receipts = require_mapping(state["receipts"], "receipts")
    for key, descriptor in receipts.items():
        identifier(key)
        digest(require_mapping(descriptor, "receipt").get("receipt_digest"))
    seen: set[str] = set()
    for raw in nonempty_list(state["records"], limit):
        record = require_mapping(raw, "record")
        key = identifier(record.get("candidate_id"))
        if key in seen:
            raise DiscoveryValidationError("duplicate-progress-candidate")
        seen.add(key)
        binding = record.get("source_receipt")
        if "source_receipt" not in record or (
            binding is not None and identifier(binding) not in receipts
        ):
            raise DiscoveryValidationError("unknown-progress-receipt")
    return state


def _apply(state: dict[str, object], value: object, reader: _Reader) -> None:
    """Apply one preconditioned binding transaction after verifying its receipts."""
    transaction = exact_object(
        value, "schema_version parent_sha256 result_sha256 additions changes"
    )
    if transaction["schema_version"] != _PROGRESS_SCHEMA_VERSION:
        raise DiscoveryValidationError("invalid-progress-format")
    if digest(transaction["parent_sha256"]) != canonical_digest(state):
        raise DiscoveryValidationError("progress-parent-mismatch")
    expected = digest(transaction["result_sha256"])
    receipts = require_mapping(state["receipts"], "receipts")
    additions = transaction["additions"]
    if not isinstance(additions, list) or len(additions) > reader.limits.changes:
        raise DiscoveryValidationError("invalid-progress-additions")
    added: set[str] = set()
    for raw in additions:
        addition = exact_object(raw, "key descriptor capture")
        key = identifier(addition["key"])
        if key in receipts:
            raise DiscoveryValidationError("duplicate-progress-receipt")
        descriptor = require_mapping(addition["descriptor"], "receipt")
        receipt = require_mapping(reader.read(capture_name(addition["capture"])), "receipt")
        body = {name: item for name, item in receipt.items() if name != "receipt_digest"}
        if (
            digest(receipt.get("receipt_digest")) != canonical_digest(body)
            or descriptor.get("receipt_digest") != receipt["receipt_digest"]
            or receipt.get("promotable") is not False
            or receipt.get("assertion_class") != "declared-snapshot-integrity-only"
        ):
            raise DiscoveryValidationError("progress-receipt-mismatch")
        receipts[key] = descriptor
        added.add(key)
    records = {
        str(record["candidate_id"]): record
        for raw in nonempty_list(state["records"], reader.limits.records)
        for record in [require_mapping(raw, "record")]
    }
    changed: set[str] = set()
    used: set[str] = set()
    for raw in nonempty_list(transaction["changes"], reader.limits.changes):
        change = exact_object(raw, "candidate_id before after")
        key = identifier(change["candidate_id"])
        after = identifier(change["after"])
        if key in changed or key not in records:
            raise DiscoveryValidationError("invalid-progress-candidate-change")
        if (
            records[key]["source_receipt"] != change["before"]
            or change["before"] == after
            or after not in receipts
        ):
            raise DiscoveryValidationError("progress-binding-mismatch")
        records[key]["source_receipt"] = after
        changed.add(key)
        used.add(after)
    if added - used:
        raise DiscoveryValidationError("unused-progress-receipt")
    if canonical_digest(state) != expected:
        raise DiscoveryValidationError("progress-result-mismatch")


def replay_discovery_progress(
    root: Path,
    base_name: str,
    transaction_names: tuple[str, ...],
    *,
    base_sha256: str,
    limits: ProgressLimits,
    base_metadata_fields: tuple[str, ...] = (),
) -> dict[str, object]:
    """Return verified current bindings and derived counts from explicit files.

    Parameters
    ----------
    root:
        Absolute no-symlink directory containing flat input captures.
    base_name:
        Base JSON containing records and receipt descriptors. Other record
        metadata is opaque and immutable; private adapters own its interpretation.
    transaction_names:
        Ordered transaction filenames, never directory discovery or latest lookup.
    base_sha256:
        Trusted canonical digest of the complete base envelope, including declared
        metadata fields; not permission to promote it.
    limits:
        Explicit byte and object ceilings for this read-only replay.
    base_metadata_fields:
        Exact additional envelope fields in an existing base snapshot. Their
        bytes remain bound by the base pin, but they are not mutable progress.
        This permits reuse of a retained snapshot without copying its records.

    Returns
    -------
    dict[str, object]
        State, canonical state digest, derived total/bound/pending counts and
        promotable=false. No caller-supplied progress counts are accepted.

    Notes
    -----
    Historical base receipt descriptors are trusted only through the supplied
    base pin. Newly added receipt bytes are checked for integrity, not semantic
    correctness or current upstream truth. No writes, network or policy actions.
    An invalid chain raises ValueError or an underlying filesystem read error;
    it never returns a partially applied state. JSON nesting is bounded at16.
    """
    digest(base_sha256)
    if not root.is_absolute() or ".." in root.parts:
        raise DiscoveryValidationError("invalid-progress-root")
    if len(transaction_names) > limits.transactions or len(set(transaction_names)) != len(
        transaction_names
    ):
        raise DiscoveryValidationError("invalid-progress-chain")
    descriptor = open_directory_no_follow(root)
    try:
        reader = _Reader(descriptor, limits, limits.total_bytes)
        base = exact_object(
            reader.read(base_name), " ".join(("records", "receipts", *base_metadata_fields))
        )
        if canonical_digest(base) != base_sha256:
            raise DiscoveryValidationError("progress-base-mismatch")
        state = _state({"records": base["records"], "receipts": base["receipts"]}, limits.records)
        for name in transaction_names:
            _apply(state, reader.read(name), reader)
        records = nonempty_list(state["records"], limits.records)
        bound = sum(
            require_mapping(record, "record")["source_receipt"] is not None for record in records
        )
        return {
            "state": state,
            "state_sha256": canonical_digest(state),
            "total": len(records),
            "bound": bound,
            "pending": len(records) - bound,
            "promotable": False,
        }
    finally:
        os.close(descriptor)
