# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact historical Git checkout
"""Read pinned Git commits in isolated, byte-preserving checkouts."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .git_inventory import GitInventory, is_git_ignored, load_git_inventory
from .git_provenance import GitRunner
from .ignored_inventory import IgnoredInventoryDeclaration, IgnoredInventoryEvidence
from .model_primitives import require_git_object


def materialise_historical_commit(
    source: Path, destination: Path, commit: str, runner: GitRunner
) -> None:
    """Check out one exact commit from the local source object store."""
    object_format = "sha1" if len(commit) == 40 else "sha256"
    runner.run(destination, "init", "--quiet", "--template=", f"--object-format={object_format}")
    object_store = runner.run(
        source,
        "-c",
        f"safe.directory={source.as_posix()}",
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "objects",
    ).stdout.rstrip(b"\r\n")
    if (
        b"\n" in object_store
        or b"\r" in object_store
        or not Path(os.fsdecode(object_store)).is_absolute()
    ):
        raise ValueError("historical Git object store must have a single absolute path")
    (destination / ".git" / "objects" / "info" / "alternates").write_bytes(object_store + b"\n")
    resolved = runner.run(
        destination, "rev-parse", "--verify", "--end-of-options", f"{commit}^{{commit}}"
    ).stdout.strip()
    if resolved != commit.encode("ascii"):
        raise ValueError("historical revision must identify the exact commit object")
    attributes = destination / ".git" / "info"
    attributes.mkdir(exist_ok=True)
    # The isolated info/attributes takes precedence over attributes committed in the tree.
    (attributes / "attributes").write_bytes(
        b"* -text -crlf -eol -ident -filter -working-tree-encoding\n"
    )
    runner.run(destination, "checkout", "--quiet", "--detach", "--no-recurse-submodules", commit)


def load_verified_historical_inventory(
    checkout: Path, commit: str, runner: GitRunner
) -> GitInventory:
    """Verify detached Git identity and the raw bytes of an isolated checkout."""
    inventory = load_git_inventory(checkout, git_runner=runner)
    if inventory.head != commit or inventory.branch != "HEAD" or inventory.dirty_paths:
        raise RuntimeError("historical checkout is not clean, detached and at the selected commit")
    for item in inventory.files:
        if item.git_mode != "160000" and item.scanned_blob_id != item.object_id:
            raise RuntimeError(f"historical checkout bytes differ from Git for {item.path}")
    return inventory


@contextmanager
def historical_inventory(source: Path, revision: str, runner: GitRunner) -> Iterator[GitInventory]:
    """Yield the selected commit's byte-verified inventory until inspection ends."""
    commit = require_git_object(revision, "historical revision")
    parent = Path(tempfile.gettempdir()).resolve(strict=True)
    if parent.is_relative_to(source):
        raise ValueError(
            "historical scan temporary directory must be outside the source repository"
        )
    with tempfile.TemporaryDirectory(prefix="rigor-historical-scan-", dir=parent) as temporary:
        checkout = Path(temporary)
        materialise_historical_commit(source, checkout, commit, runner)
        yield load_verified_historical_inventory(checkout, commit, runner)


def describe_historical_ignored_paths(
    inventory: GitInventory,
    declarations: tuple[IgnoredInventoryDeclaration, ...],
    *,
    git_runner: GitRunner,
) -> tuple[IgnoredInventoryEvidence, ...]:
    """Validate snapshot declarations without claiming an off-tree observation."""
    tracked = {item.path for item in inventory.files}
    evidence = []
    for declaration in declarations:
        if declaration.path in tracked:
            raise ValueError(f"ignored inventory path is tracked: {declaration.path}")
        if not is_git_ignored(
            inventory.root,
            Path(declaration.path),
            git_runner=git_runner,
            expected_git_provenance=inventory.git_provenance,
        ):
            raise ValueError(f"ignored inventory path is not ignored: {declaration.path}")
        evidence.append(
            IgnoredInventoryEvidence(
                declaration.evidence_id,
                declaration.path,
                declaration.capture,
                "unavailable",
                None,
                None,
                None,
                "historical-state-unavailable",
            )
        )
    return tuple(evidence)
