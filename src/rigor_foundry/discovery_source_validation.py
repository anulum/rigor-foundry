# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — discovery source validation
"""Verify declared discovery snapshot integrity, never authority or completeness."""

from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .audit_primitives import canonical_digest
from .discovery_source_schema import (
    SCHEMA,
    DiscoveryLimits,
    DiscoveryReadError,
    DiscoveryValidationError,
    capture_name,
    digest,
    discovery_object,
    exact_object,
    identifier,
    integer,
    nonempty_list,
    parse_json,
    text_bytes,
)
from .git_inventory import StableReadError, open_directory_no_follow, read_stable_regular_file_at


@dataclass
class _CaptureReader:
    """Own the remaining aggregate byte budget and unique capture allocation."""

    descriptor: int
    limits: DiscoveryLimits
    remaining: int
    names: set[str] = field(default_factory=set)

    def read(self, value: object) -> bytes:
        """Read one unique single-link regular capture without following links."""
        name = capture_name(value)
        if name in self.names:
            raise DiscoveryValidationError("duplicate-capture")
        self.names.add(name)
        maximum = min(self.remaining, self.limits.file_bytes)
        try:
            result = read_stable_regular_file_at(
                self.descriptor,
                name,
                name,
                buffer_limit=maximum,
                maximum_bytes=maximum,
                require_single_link=True,
            )
        except StableReadError as exc:
            if exc.reason == "limit-exceeded":
                raise DiscoveryValidationError("byte-budget-exceeded") from exc
            raise DiscoveryReadError("capture-read-failed") from exc
        self.remaining -= result.byte_size
        # The shared reader guarantees a payload when both bounds are equal.
        if result.payload is None:  # pragma: no cover
            raise DiscoveryReadError("capture-buffer-unavailable")
        return result.payload


def _bound_capture(reader: _CaptureReader, record: dict[str, object]) -> bytes:
    """Bind complete captured bytes and size to their declared digest."""
    expected = digest(record["sha256"])
    size = integer(record["bytes"])
    payload = reader.read(record["capture"])
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != expected:
        raise DiscoveryValidationError("capture-binding-mismatch")
    return payload


def _source_lines(payload: bytes) -> tuple[bytes, ...]:
    """Split only on LF and retain complete original line terminators."""
    text_bytes(payload)
    chunks = payload.split(b"\n")
    return tuple(chunk + b"\n" for chunk in chunks[:-1]) + ((chunks[-1],) if chunks[-1] else ())


def _load_sources(
    reader: _CaptureReader,
    records: object,
) -> tuple[dict[str, tuple[bytes, ...]], list[dict[str, str]]]:
    """Load every declared source once, including unreferenced inventory bytes."""
    sources: dict[str, tuple[bytes, ...]] = {}
    identities: list[dict[str, str]] = []
    for value in nonempty_list(records, reader.limits.sources):
        record = exact_object(value, "source_id capture sha256 bytes lines")
        source_id = identifier(record["source_id"])
        if source_id in sources:
            raise DiscoveryValidationError("duplicate-source")
        lines = _source_lines(_bound_capture(reader, record))
        if len(lines) != integer(record["lines"]):
            raise DiscoveryValidationError("source-line-count-mismatch")
        sources[source_id] = lines
        identities.append({"source_id": source_id, "sha256": digest(record["sha256"])})
    return sources, sorted(identities, key=lambda item: item["source_id"])


def _candidate(
    value: object,
    sources: dict[str, tuple[bytes, ...]],
    remaining_spans: int,
) -> tuple[str, list[str]]:
    """Validate a candidate's statement and exact supporting source-span edges."""
    record = exact_object(value, "candidate_id statement source_spans")
    candidate_id = identifier(record["candidate_id"])
    statement = record["statement"]
    if not isinstance(statement, str) or not statement.strip():
        raise DiscoveryValidationError("invalid-statement")
    try:
        statement.encode("utf-8")
    except UnicodeError as exc:
        raise DiscoveryValidationError("invalid-statement") from exc
    used: list[str] = []
    seen: set[tuple[str, int, int]] = set()
    for value in nonempty_list(record["source_spans"], remaining_spans):
        span = exact_object(value, "source_id start_line end_line sha256")
        source_id = identifier(span["source_id"])
        start, end = integer(span["start_line"], minimum=1), integer(span["end_line"], minimum=1)
        expected = digest(span["sha256"])
        if source_id not in sources or not start <= end <= len(sources[source_id]):
            raise DiscoveryValidationError("unresolved-span")
        edge = (source_id, start, end)
        if edge in seen:
            raise DiscoveryValidationError("duplicate-span")
        seen.add(edge)
        if hashlib.sha256(b"".join(sources[source_id][start - 1 : end])).hexdigest() != expected:
            raise DiscoveryValidationError("span-binding-mismatch")
        used.append(source_id)
    return candidate_id, used


def _verify(reader: _CaptureReader, manifest_name: str) -> dict[str, object]:
    """Verify the complete declared graph and build an integrity-only receipt."""
    payload = reader.read(manifest_name)
    manifest = discovery_object(
        parse_json(payload),
        "schema_version status sources shards candidate_count",
    )
    declared_count = integer(manifest["candidate_count"], minimum=1)
    if declared_count > reader.limits.candidates:
        raise DiscoveryValidationError("candidate-budget-exceeded")
    sources, source_ids = _load_sources(reader, manifest["sources"])
    shard_ids: dict[str, str] = {}
    candidates: set[str] = set()
    used_sources: set[str] = set()
    span_count = 0
    for value in nonempty_list(manifest["shards"], reader.limits.shards):
        record = exact_object(value, "shard_id capture sha256 bytes candidates")
        shard_id = identifier(record["shard_id"])
        if shard_id in shard_ids:
            raise DiscoveryValidationError("duplicate-shard")
        shard = discovery_object(
            parse_json(_bound_capture(reader, record)),
            "schema_version status shard_id candidates",
        )
        if identifier(shard["shard_id"]) != shard_id:
            raise DiscoveryValidationError("shard-binding-mismatch")
        shard_candidates = nonempty_list(
            shard["candidates"],
            reader.limits.candidates - len(candidates),
        )
        if len(shard_candidates) != integer(record["candidates"], minimum=1):
            raise DiscoveryValidationError("shard-count-mismatch")
        for value in shard_candidates:
            candidate_id, used = _candidate(value, sources, reader.limits.spans - span_count)
            if candidate_id in candidates:
                raise DiscoveryValidationError("duplicate-candidate")
            candidates.add(candidate_id)
            used_sources.update(used)
            span_count += len(used)
        shard_ids[shard_id] = digest(record["sha256"])
    if len(candidates) != declared_count:
        raise DiscoveryValidationError("candidate-count-mismatch")
    body: dict[str, object] = {
        "schema_version": SCHEMA,
        "status": "discovery-integrity-verified",
        "assertion_class": "declared-snapshot-integrity-only",
        "promotable": False,
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "sources": source_ids,
        "shards": [{"shard_id": key, "sha256": shard_ids[key]} for key in sorted(shard_ids)],
        "candidate_count": len(candidates),
        "span_count": span_count,
        "unused_source_ids": sorted(set(sources) - used_sources),
        "limits": asdict(reader.limits),
    }
    return {**body, "receipt_digest": canonical_digest(body)}


def validate_discovery_sources(
    root: Path,
    manifest_name: str,
    *,
    limits: DiscoveryLimits,
) -> dict[str, object]:
    """Read a flat explicit snapshot and return a deterministic integrity receipt.

    Require an absolute, non-traversing, no-symlink root and caller-set budgets.
    Read only the manifest and named captures, reject hardlinks and nonregular
    files, and never write, fetch or execute source data. Every descriptor is
    closed. Per-file stable reads are not a filesystem-wide atomic snapshot.

    Raise DiscoveryValidationError for invalid schema, bindings or budgets;
    raise DiscoveryReadError for inaccessible captures or unsupported platforms.
    Returned promotable=false is unconditional; this API verifies neither
    semantic support nor issuing authority, freshness or corpus completeness.
    """
    limits = DiscoveryLimits(**asdict(limits))
    if not root.is_absolute() or ".." in root.parts or "\0" in str(root):
        raise DiscoveryValidationError("invalid-root")
    capture_name(manifest_name)
    try:
        descriptor = open_directory_no_follow(root)
    except (OSError, RuntimeError) as exc:
        raise DiscoveryReadError("capture-root-unavailable") from exc
    try:
        return _verify(_CaptureReader(descriptor, limits, limits.total_bytes), manifest_name)
    finally:
        os.close(descriptor)
