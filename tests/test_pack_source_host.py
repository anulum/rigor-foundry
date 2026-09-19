# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — retained pack-source host tests
"""Exercise host-selected source custody through real retained files."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.git_inventory import StableReadError
from rigor_foundry.pack_source_host import (
    HostPackSourceSelection,
    HostPackSourceState,
    HostPackSourceVerifier,
)

_URI = "https://standards.example/core/v2"
_PAYLOAD = b"retained source with exact identity\n"


def _verifier(state: HostPackSourceState) -> HostPackSourceVerifier:
    @contextmanager
    def lease() -> Iterator[HostPackSourceState]:
        yield state

    return HostPackSourceVerifier(lease)


def _selection(path: Path, *, payload: bytes = _PAYLOAD) -> HostPackSourceSelection:
    return HostPackSourceSelection.build(
        pack_id="core",
        source_uri=_URI,
        source_digest=hashlib.sha256(payload).hexdigest(),
        retained_path=path,
    )


def _state(selection: HostPackSourceSelection) -> HostPackSourceState:
    return HostPackSourceState(selection, selection.selection_digest, frozenset())


def test_host_selection_reads_exact_retained_bytes_without_remote_lookup(tmp_path: Path) -> None:
    path = tmp_path / "source"
    path.write_bytes(_PAYLOAD)
    selection = _selection(path)
    proof = _verifier(_state(selection)).verify(
        pack_id="core", source_uri=_URI, source_digest=selection.source_digest
    )
    assert proof["source_digest"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert proof["selection_digest"] == selection.selection_digest
    assert proof["assertion_class"] == "retained-object-integrity-only"
    assert proof["promotable"] is False
    assert "freshness_seconds" not in proof


def test_mutated_or_missing_retained_bytes_refuse(tmp_path: Path) -> None:
    path = tmp_path / "source"
    path.write_bytes(_PAYLOAD)
    selection = _selection(path)
    verifier = _verifier(_state(selection))
    path.write_bytes(b"changed after host selection\n")
    with pytest.raises(ValueError, match="digest differs"):
        verifier.verify(pack_id="core", source_uri=_URI, source_digest=selection.source_digest)
    path.unlink()
    with pytest.raises(StableReadError, match="cannot access regular path"):
        verifier.verify(pack_id="core", source_uri=_URI, source_digest=selection.source_digest)


@pytest.mark.parametrize("field", ["pack_id", "source_uri", "source_digest"])
def test_pack_cannot_choose_another_host_source(tmp_path: Path, field: str) -> None:
    path = tmp_path / "source"
    path.write_bytes(_PAYLOAD)
    selection = _selection(path)
    requested = {
        "pack_id": "core",
        "source_uri": _URI,
        "source_digest": selection.source_digest,
    }
    requested[field] = (
        "other"
        if field == "pack_id"
        else ("https://other.example/core/v2" if field == "source_uri" else "f" * 64)
    )
    with pytest.raises(PermissionError, match="differs"):
        _verifier(_state(selection)).verify(**requested)


def test_changed_selection_or_revocation_refuses(tmp_path: Path) -> None:
    path = tmp_path / "source"
    path.write_bytes(_PAYLOAD)
    selection = _selection(path)
    request = {"pack_id": "core", "source_uri": _URI, "source_digest": selection.source_digest}
    with pytest.raises(PermissionError, match="differs"):
        _verifier(replace(_state(selection), expected_selection_digest="0" * 64)).verify(**request)
    with pytest.raises(PermissionError, match="differs"):
        _verifier(
            replace(_state(selection), selected=replace(selection, source_uri="other"))
        ).verify(**request)
    with pytest.raises(PermissionError, match="differs"):
        _verifier(
            replace(
                _state(selection),
                revoked_selection_digests=frozenset({selection.selection_digest}),
            )
        ).verify(**request)
    with pytest.raises(ValueError, match="revoked_selection_digest"):
        _verifier(
            replace(_state(selection), revoked_selection_digests=frozenset({"not-a-digest"}))
        ).verify(**request)


def test_unavailable_host_state_refuses(tmp_path: Path) -> None:
    path = tmp_path / "source"
    path.write_bytes(_PAYLOAD)
    selection = _selection(path)

    @contextmanager
    def absent_state() -> Iterator[HostPackSourceState]:
        yield cast(HostPackSourceState, object())

    with pytest.raises(PermissionError, match="unavailable"):
        HostPackSourceVerifier(absent_state).verify(
            pack_id="core", source_uri=_URI, source_digest=selection.source_digest
        )


def test_host_cannot_suppress_pack_source_failure(tmp_path: Path) -> None:
    """A state lease swallowing a read failure must not yield an empty success."""
    path = tmp_path / "source"
    path.write_bytes(b"changed\n")
    selection = _selection(path)

    @contextmanager
    def suppressing_state() -> Iterator[HostPackSourceState]:
        with suppress(ValueError):
            yield _state(selection)

    with pytest.raises(PermissionError, match="suppressed verification failure"):
        HostPackSourceVerifier(suppressing_state).verify(
            pack_id="core", source_uri=_URI, source_digest=selection.source_digest
        )


def test_linked_retained_sources_refuse(tmp_path: Path) -> None:
    path = tmp_path / "source"
    path.write_bytes(_PAYLOAD)
    linked = tmp_path / "hardlink"
    os.link(path, linked)
    selection = _selection(path)
    request = {"pack_id": "core", "source_uri": _URI, "source_digest": selection.source_digest}
    with pytest.raises(StableReadError, match="multiple hard links"):
        _verifier(_state(selection)).verify(**request)
    linked.unlink()
    path.unlink()
    path.symlink_to(tmp_path / "other-source")
    with pytest.raises(StableReadError):
        _verifier(_state(selection)).verify(**request)


def test_selection_requires_absolute_untraversed_file_path() -> None:
    with pytest.raises(ValueError, match="absolute untraversed"):
        _selection(Path("relative/source"))
    with pytest.raises(ValueError, match="absolute untraversed"):
        _selection(Path("/tmp/../source"))
    with pytest.raises(ValueError, match="whitespace"):
        HostPackSourceSelection.build(
            pack_id="core",
            source_uri="https://standards.example/bad path",
            source_digest=hashlib.sha256(_PAYLOAD).hexdigest(),
            retained_path=Path("/tmp/source"),
        )
