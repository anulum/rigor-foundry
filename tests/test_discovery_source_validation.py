# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — discovery source validation
"""Exercise source closure through real captures and the public validator."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pytest
from discovery_source_support import (
    limits,
    load_shard,
    records,
    sha,
    snapshot,
    write_manifest,
    write_shard,
)

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.discovery_source_schema import DiscoveryLimits, DiscoveryValidationError
from rigor_foundry.discovery_source_validation import validate_discovery_sources


def test_complete_snapshot_replay_and_no_writes(tmp_path: Path) -> None:
    """Bind two shards, preserve all bytes and emit no source prose or authority."""
    snapshot(tmp_path)
    (tmp_path / "unrelated.txt").write_bytes(b"Never read or claim this file.")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    budget = limits(tmp_path)
    first = validate_discovery_sources(tmp_path, "manifest.json", limits=budget)
    assert first == validate_discovery_sources(tmp_path, "manifest.json", limits=budget)
    assert first["manifest_sha256"] == sha(before["manifest.json"])
    assert first["candidate_count"] == first["span_count"] == 2
    assert first["unused_source_ids"] == ["source2"]
    assert first["promotable"] is False
    assert first["assertion_class"] == "declared-snapshot-integrity-only"
    assert first["limits"] == asdict(budget)
    body = {key: value for key, value in first.items() if key != "receipt_digest"}
    assert first["receipt_digest"] == canonical_digest(body)
    assert "source evidence" not in str(first)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize(
    "name", ["total_bytes", "file_bytes", "sources", "shards", "candidates", "spans"]
)
def test_one_below_each_budget_refuses(tmp_path: Path, name: str) -> None:
    """Accept exact measured limits, then reject one less for each real resource."""
    snapshot(tmp_path)
    budget = limits(tmp_path)
    validate_discovery_sources(tmp_path, "manifest.json", limits=budget)
    values = asdict(budget)
    values[name] -= 1
    with pytest.raises(DiscoveryValidationError):
        validate_discovery_sources(tmp_path, "manifest.json", limits=DiscoveryLimits(**values))


@pytest.mark.parametrize("value", [0, -1, True, 2**31, 1.2, "10"])
def test_invalid_budget_types(value: object) -> None:
    """Refuse nonpositive, boolean, oversized and noninteger public budgets."""
    with pytest.raises(DiscoveryValidationError, match="invalid-limit"):
        DiscoveryLimits(value, 1, 1, 1, 1, 1)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "newer"),
        ("status", "active"),
        ("signature", "approved"),
        ("candidate_count", True),
        ("candidate_count", 0),
        ("candidate_count", 1),
        ("sources", []),
        ("sources", {}),
        ("shards", []),
    ],
)
def test_manifest_fields(tmp_path: Path, field: str, value: object) -> None:
    """Refuse schema drift, authority injection, false counts and empty collections."""
    manifest = snapshot(tmp_path)
    manifest[field] = value
    write_manifest(tmp_path, manifest)
    with pytest.raises(DiscoveryValidationError):
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_id", "bad identifier"),
        ("source_id", 1),
        ("sha256", "A" * 64),
        ("sha256", "0" * 64),
        ("bytes", 999),
        ("lines", 9),
        ("capture", "../escape"),
        ("capture", "CON.txt"),
        ("capture", "COM1"),
        ("capture", "LPT9.txt"),
        ("capture", "trailing."),
        ("capture", 1),
        ("capture", "https://host/file"),
        ("capture", "manifest.json"),
        ("lines", False),
    ],
)
def test_source_metadata(tmp_path: Path, field: str, value: object) -> None:
    """Verify digests, byte/line counts, identity and flat capture confinement."""
    manifest = snapshot(tmp_path)
    records(manifest, "sources")[0][field] = value
    write_manifest(tmp_path, manifest)
    with pytest.raises(DiscoveryValidationError):
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))


@pytest.mark.parametrize(
    ("collection", "key", "value"),
    [
        ("sources", "source_id", "source0"),
        ("sources", "capture", "source0.txt"),
        ("shards", "shard_id", "shard0"),
        ("shards", "capture", "shard0.json"),
    ],
)
def test_duplicate_inventory(tmp_path: Path, collection: str, key: str, value: str) -> None:
    """Reject duplicate IDs and capture reuse instead of collapsing inventory."""
    manifest = snapshot(tmp_path)
    records(manifest, collection)[1][key] = value
    write_manifest(tmp_path, manifest)
    with pytest.raises(DiscoveryValidationError):
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("shard_id", "different"),
        ("schema_version", "old"),
        ("status", "ratified"),
        ("candidates", []),
        ("extra", 0),
    ],
)
def test_shard_schema(tmp_path: Path, field: str, value: object) -> None:
    """Refuse a correctly hashed shard whose inner contract differs."""
    manifest = snapshot(tmp_path)
    shard = load_shard(tmp_path)
    shard[field] = value
    write_shard(tmp_path, manifest, shard)
    with pytest.raises(DiscoveryValidationError):
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("candidate_id", "rule1"),
        ("statement", ""),
        ("statement", 1),
        ("statement", "\ud800"),
        ("source_spans", []),
        ("approved", True),
    ],
)
def test_candidate_schema(tmp_path: Path, field: str, value: object) -> None:
    """Reject duplicate global IDs, empty/invalid statements and authority fields."""
    manifest = snapshot(tmp_path)
    shard = load_shard(tmp_path)
    records(shard, "candidates")[0][field] = value
    write_shard(tmp_path, manifest, shard)
    with pytest.raises(DiscoveryValidationError):
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_id", "absent"),
        ("source_id", "source2"),
        ("start_line", 0),
        ("start_line", 3),
        ("end_line", 1),
        ("end_line", 3),
        ("end_line", False),
        ("sha256", "0" * 64),
        ("sha256", "bad"),
    ],
)
def test_span_binding(tmp_path: Path, field: str, value: object) -> None:
    """Refuse unknown, empty, out-of-range, malformed or incorrectly hashed spans."""
    manifest = snapshot(tmp_path)
    shard = load_shard(tmp_path)
    span = records(records(shard, "candidates")[0], "source_spans")[0]
    if field == "end_line" and value == 1:
        span["start_line"] = 2
    span[field] = value
    write_shard(tmp_path, manifest, shard)
    with pytest.raises(DiscoveryValidationError):
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))


def test_duplicate_span(tmp_path: Path) -> None:
    """Reject the same edge twice even when the byte and count budgets permit it."""
    manifest = snapshot(tmp_path)
    shard = load_shard(tmp_path)
    spans = records(records(shard, "candidates")[0], "source_spans")
    spans.append(dict(spans[0]))
    write_shard(tmp_path, manifest, shard)
    with pytest.raises(DiscoveryValidationError, match="duplicate-span"):
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path, spans=3))


def test_shard_declared_count(tmp_path: Path) -> None:
    """Reject a shard manifest count independently of global candidate totals."""
    manifest = snapshot(tmp_path)
    records(manifest, "shards")[0]["candidates"] = 2
    write_manifest(tmp_path, manifest)
    with pytest.raises(DiscoveryValidationError, match="shard-count-mismatch"):
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))


@pytest.mark.parametrize("payload", [b"a\n", b"a\r\nb", b"\xef\xbb\xbfa", b"a\rb", b"a\vb", b"\n"])
def test_exact_line_semantics(tmp_path: Path, payload: bytes) -> None:
    """Treat LF alone as a separator while retaining CR, BOM and final bytes."""
    manifest = snapshot(tmp_path)
    line_count = payload.count(b"\n") + (not payload.endswith(b"\n"))
    (tmp_path / "source0.txt").write_bytes(payload)
    records(manifest, "sources")[0].update(
        sha256=sha(payload), bytes=len(payload), lines=line_count
    )
    shard = load_shard(tmp_path)
    records(records(shard, "candidates")[0], "source_spans")[0].update(
        end_line=line_count, sha256=sha(payload)
    )
    write_shard(tmp_path, manifest, shard)
    assert (
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))[
            "promotable"
        ]
        is False
    )


def test_shared_source_across_candidates(tmp_path: Path) -> None:
    """Allow shared supporting bytes without counting a source twice."""
    manifest = snapshot(tmp_path)
    shard = load_shard(tmp_path, 1)
    records(shard, "candidates")[0]["source_spans"] = records(load_shard(tmp_path), "candidates")[
        0
    ]["source_spans"]
    write_shard(tmp_path, manifest, shard, 1)
    receipt = validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))
    assert receipt["unused_source_ids"] == ["source1", "source2"]
