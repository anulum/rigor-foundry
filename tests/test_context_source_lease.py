# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual source lifetime tests
"""Retain real source descriptors and refuse changed selections at use and close."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import cast

import pytest
from test_context_source_resolution import sources
from test_policy_source_records import records
from test_task_definition import budget, definition
from test_typed_object_reference import reference

from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.context_source_resolution import SUPPORTED_CONTEXT_TARGET_FORMATS
from rigor_foundry.git_inventory import StableReadError
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.project_registry_models import ProjectRegistry
from rigor_foundry.typed_object_reference import TypedObjectRef1


def source_file(directory: Path) -> tuple[Path, TypedObjectRef1, str]:
    """Write an actual task document before selecting its exact source identity."""
    directory.mkdir()
    task = definition()
    path = directory / "task.json"
    payload = json.dumps(task.to_dict()).encode()
    path.write_bytes(payload)
    return path, TypedObjectRef1.from_dict(task.reference()), hashlib.sha256(payload).hexdigest()


def source_handles(directory: Path) -> int:
    """Count actual process descriptors for owned source paths without private access."""
    count = 0
    for path in Path("/proc/self/fd").iterdir():
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            continue
        if target == str(directory) or target.startswith(str(directory) + "/"):
            count += 1
    return count


def test_actual_owning_source_parsers_with_held_lifetimes(tmp_path: Path) -> None:
    """Every implemented source format uses retained original bytes and a fixed parser."""
    selected = (
        *sources(),
        *((TypedObjectRef1.from_dict(item.reference()), item) for item in records(tmp_path)),
    )
    assert (
        frozenset((ref.kind, ref.format_version) for ref, _ in selected)
        == SUPPORTED_CONTEXT_TARGET_FORMATS
    )
    for index, (ref, target) in enumerate(selected):
        directory = tmp_path / str(index)
        directory.mkdir()
        payload = (
            target.to_bytes()
            if isinstance(target, ProjectRegistry)
            else json.dumps(target.to_dict()).encode()
        )
        path = directory / "source.json"
        path.write_bytes(payload)
        before = source_handles(directory)
        with RetainedContextSource(
            path,
            reference=ref,
            raw_digest=hashlib.sha256(payload).hexdigest(),
            budget=budget(max_references=2048, max_sources=3),
        ) as lease:
            assert source_handles(directory) == before + 2
            assert lease.reference == ref
            assert len(lease.snapshot_id) == 64
            assert lease.read() == target
        assert source_handles(directory) == before
        lease.close()
        for operation in (
            lease.read,
            lambda: lease.reference,
            lambda: lease.snapshot_id,
            lease.__enter__,
        ):
            with pytest.raises(ValueError, match="closed"):
                operation()


def test_complete_work_record_refuses_small_budget_and_releases(tmp_path: Path) -> None:
    """The same complete event chain succeeds within its budget and releases handles on refusal."""
    ref, target = next((ref, target) for ref, target in sources() if ref.kind == "work-record")
    path = tmp_path / "work.json"
    payload = json.dumps(target.to_dict()).encode()
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    with pytest.raises(ValueError, match="reference or depth budget"):
        RetainedContextSource(
            path, reference=ref, raw_digest=digest, budget=budget(max_references=64)
        )
    assert source_handles(tmp_path) == 0
    with RetainedContextSource(
        path, reference=ref, raw_digest=digest, budget=budget(max_references=2048)
    ) as lease:
        assert lease.read() == target
        assert source_handles(tmp_path) == 2
    assert source_handles(tmp_path) == 0


def test_same_source_cannot_reconstruct_another_retained_selection(tmp_path: Path) -> None:
    """Equal bytes and references do not let a new lease reuse the old selection ID."""
    path, ref, digest = source_file(tmp_path / "source")
    with (
        RetainedContextSource(path, reference=ref, raw_digest=digest, budget=budget()) as first,
        RetainedContextSource(path, reference=ref, raw_digest=digest, budget=budget()) as second,
    ):
        assert first.read() == second.read()
        assert first.snapshot_id != second.snapshot_id


@pytest.mark.parametrize(
    "mutation",
    ["edit", "replace-same-bytes", "delete", "alias", "parent-replaced", "directory-entry"],
)
def test_changed_source_or_parent_refuses_and_releases(tmp_path: Path, mutation: str) -> None:
    """Actual replacement/aliasing/edits cannot survive a matching-looking reference."""
    path, ref, digest = source_file(tmp_path / "source")
    lease = RetainedContextSource(path, reference=ref, raw_digest=digest, budget=budget())
    if mutation == "edit":
        path.write_bytes(path.read_bytes() + b" ")
    elif mutation == "replace-same-bytes":
        replacement = path.parent / "replacement.json"
        replacement.write_bytes(path.read_bytes())
        replacement.replace(path)
    elif mutation == "delete":
        path.unlink()
    elif mutation == "alias":
        payload = path.read_bytes()
        path.unlink()
        target = tmp_path / "elsewhere.json"
        target.write_bytes(payload)
        path.symlink_to(target)
    elif mutation == "parent-replaced":
        path.parent.rename(tmp_path / "moved")
        path.parent.mkdir()
        path.write_bytes((tmp_path / "moved" / "task.json").read_bytes())
    else:
        (path.parent / "new-entry").write_bytes(b"new")
    with pytest.raises(ValueError, match="identity changed"):
        lease.read()
    with pytest.raises(ValueError, match="identity changed"):
        lease.close()
    assert source_handles(path.parent) == 0
    assert source_handles(tmp_path / "moved") == 0
    with pytest.raises(ValueError, match="closed"):
        lease.read()


def test_closing_mutation_is_checked_even_without_a_second_explicit_read(tmp_path: Path) -> None:
    """The public context manager validates the same retained source at closure."""
    path, ref, digest = source_file(tmp_path / "source")
    with (
        pytest.raises(ValueError, match="identity changed"),
        RetainedContextSource(path, reference=ref, raw_digest=digest, budget=budget()) as lease,
    ):
        assert lease.read() == definition()
        path.write_bytes(path.read_bytes() + b" ")
    assert source_handles(path.parent) == 0


@pytest.mark.parametrize(
    "bad",
    [
        "missing",
        "directory",
        "symlink",
        "hardlink",
        "wrong-bytes",
        "wrong-target",
        "oversize",
        "malformed-json",
    ],
)
def test_failed_construction_releases_all_owned_descriptors(tmp_path: Path, bad: str) -> None:
    """Actual bad inputs refuse before usable lifetime and leave no source handles."""
    path, ref, digest = source_file(tmp_path / "source")
    if bad == "missing":
        path.unlink()
    elif bad == "directory":
        path.unlink()
        path.mkdir()
    elif bad == "symlink":
        path.unlink()
        path.symlink_to("missing")
    elif bad == "hardlink":
        os.link(path, path.parent / "alias")
    elif bad == "wrong-bytes":
        digest = "a" * 64
    elif bad == "wrong-target":
        ref = reference(identity="foreign")
    elif bad == "oversize":
        path.write_bytes(b"x" * 65537)
    else:
        path.write_bytes(b'{"a":1,"a":2}')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises((ValueError, OSError, StableReadError)):
        RetainedContextSource(path, reference=ref, raw_digest=digest, budget=budget())
    assert source_handles(path.parent) == 0


def test_registry_uses_its_original_canonical_bytes(tmp_path: Path) -> None:
    """Valid original registry identity does not allow rewritten retained source bytes."""
    ref, registered = sources()[-1]
    assert isinstance(registered, ProjectRegistry)
    directory = tmp_path / "source"
    directory.mkdir()
    path = directory / "registry.json"
    payload = json.dumps(registered.to_dict(), indent=2).encode()
    path.write_bytes(payload)
    with pytest.raises(ValueError, match="not canonical"):
        RetainedContextSource(
            path,
            reference=ref,
            raw_digest=hashlib.sha256(payload).hexdigest(),
            budget=budget(max_references=64),
        )
    assert source_handles(directory) == 0


def test_invalid_budget_and_reference_refuse_before_opening(tmp_path: Path) -> None:
    """Host source selection has no permissive budget or reference fallback."""
    path = tmp_path / "missing"
    with pytest.raises(ValueError, match="budget is required"):
        RetainedContextSource(
            path, reference=reference(), raw_digest="a" * 64, budget=cast(PolicyReadBudget1, {})
        )
    with pytest.raises(ValueError, match="reference is required"):
        RetainedContextSource(
            path, reference=cast(TypedObjectRef1, {}), raw_digest="a" * 64, budget=budget()
        )
