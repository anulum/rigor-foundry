# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete memory source binding tests
"""Exercise source closure through public memory and verification boundaries."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import cast

import pytest
from test_project_memory_activation_plan import proposal

from rigor_foundry.project_memory_models import ProjectMemoryManifest
from rigor_foundry.project_memory_primitives import (
    PROJECT_MEMORY_MAX_RECORDS,
    PROJECT_MEMORY_MAX_SOURCES,
    ProjectMemorySource,
)
from rigor_foundry.project_memory_sources import verify_project_memory_sources


def memory(
    payloads: tuple[bytes, ...],
) -> tuple[ProjectMemoryManifest, dict[tuple[str, str, str], bytes]]:
    """Build genuine source-bearing records, including shared reference identities."""
    p = proposal()
    sources = tuple(
        ProjectMemorySource("same-source", "README.md", hashlib.sha256(payload).hexdigest())
        for payload in payloads
    )
    records = tuple(
        replace(
            p.memory.records[0],
            record_id=f"record-{i:04d}",
            content_path=f"records/identity/record-{i:04d}.md",
            sources=(source,),
        )
        for i, source in enumerate(sources)
    )
    manifest = ProjectMemoryManifest.build(
        project_id=p.memory.project_id,
        generated_at=p.memory.generated_at,
        previous_manifest_sha256=None,
        parents=p.memory.parents,
        records=records,
    )
    return manifest, {
        (s.source_id, s.locator, s.sha256): payload
        for s, payload in zip(sources, payloads, strict=True)
    }


def test_shared_sources_and_different_snapshots_are_not_confused() -> None:
    """Deduplicate exact shared references while retaining distinct snapshots and immutable output."""
    manifest, contents = memory((b"version one", b"version two", b"version one", b""))
    result = verify_project_memory_sources(manifest, contents, max_source_bytes=22)
    assert len(result) == 3
    assert {
        (source.source_id, source.locator, source.sha256): payload for source, payload in result
    } == contents
    assert [source.sha256 for source, _ in result] == sorted(key[2] for key in contents)
    saved = dict(contents)
    contents.clear()
    assert {
        (source.source_id, source.locator, source.sha256): payload for source, payload in result
    } == saved


@pytest.mark.parametrize("budget", [False, 0, -1, 1.5, 2**53])
def test_invalid_budget_types(budget: object) -> None:
    """Reject capacities outside the positive exact-integer range."""
    manifest, contents = memory((b"source",))
    with pytest.raises(ValueError, match="positive exact"):
        verify_project_memory_sources(manifest, contents, max_source_bytes=cast(int, budget))


def test_empty_file_and_exact_byte_budget() -> None:
    """Accept empty sources and exact capacity while refusing one-byte overflow."""
    manifest, contents = memory((b"",))
    assert verify_project_memory_sources(manifest, contents, max_source_bytes=1)[0][1] == b""
    manifest, contents = memory((b"source",))
    assert verify_project_memory_sources(manifest, contents, max_source_bytes=6)
    with pytest.raises(ValueError, match="byte budget"):
        verify_project_memory_sources(manifest, contents, max_source_bytes=5)


def test_cardinality_is_bounded_even_for_empty_sources() -> None:
    """Reject excessive reference counts even when every payload is empty."""
    manifest, _ = memory((b"",))
    contents = {
        (str(i), "README.md", hashlib.sha256(b"").hexdigest()): b""
        for i in range(PROJECT_MEMORY_MAX_RECORDS * PROJECT_MEMORY_MAX_SOURCES + 1)
    }
    with pytest.raises(ValueError, match="count"):
        verify_project_memory_sources(manifest, contents, max_source_bytes=1)


@pytest.mark.parametrize("case", ["missing", "extra", "locator", "id", "hash"])
def test_exact_reference_set_is_required(case: str) -> None:
    """Require complete source ID, locator and digest triples without extra references."""
    manifest, contents = memory((b"source",))
    key = next(iter(contents))
    if case == "missing":
        contents.clear()
    elif case == "extra":
        contents[("foreign", key[1], key[2])] = b"source"
    else:
        replacement = list(key)
        replacement[{"id": 0, "locator": 1, "hash": 2}[case]] = "wrong"
        contents[(replacement[0], replacement[1], replacement[2])] = contents.pop(key)
    with pytest.raises(ValueError, match="every exact"):
        verify_project_memory_sources(manifest, contents, max_source_bytes=100)


@pytest.mark.parametrize("payload", [bytearray(b"source"), memoryview(b"source"), "source"])
def test_mutable_and_non_byte_payloads_are_refused(payload: object) -> None:
    """Reject mutable or non-byte source payloads before digest verification."""
    manifest, contents = memory((b"source",))
    contents[next(iter(contents))] = cast(bytes, payload)
    with pytest.raises(ValueError, match="immutable"):
        verify_project_memory_sources(manifest, contents, max_source_bytes=100)


def test_wrong_content_and_forged_manifest_are_refused_without_echoing_source() -> None:
    """Reject forged hashes/models without exposing captured source bytes in errors."""
    manifest, contents = memory((b"source",))
    contents[next(iter(contents))] = b"private marker"
    with pytest.raises(ValueError, match="digest mismatch") as error:
        verify_project_memory_sources(manifest, contents, max_source_bytes=100)
    assert "private marker" not in str(error.value) and "README.md" not in str(error.value)
    with pytest.raises(ValueError):
        verify_project_memory_sources(
            replace(manifest, manifest_sha256="0" * 64), {}, max_source_bytes=100
        )
