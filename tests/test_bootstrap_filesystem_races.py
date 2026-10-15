# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real bootstrap filesystem race contracts
"""Schedule outside fixture writers at actual syscalls of the public bootstrap API."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace
from repository_audit_git_repository import GitRepository

_POLICY = Path("config/policy.json")
_TODO = Path("private-todo/TODO.md")
_LEDGER = Path("private-ledger/reviews.json")


@pytest.fixture
def adopter(tmp_path: Path) -> Path:
    """Create a real committed adopter with three distinct declared parents.

    Parameters
    ----------
    tmp_path : Path
        Owned pytest fixture allocation.

    Returns
    -------
    Path
        Exact Git root with absent policy, TODO and review-ledger leaves.
    """
    repository = GitRepository.create(tmp_path / "adopter")
    repository.write_text("src/item.py", "VALUE = 1\n")
    repository.write_text(
        "tests/test_item.py",
        "from item import VALUE\n\ndef test_item() -> None:\n    assert VALUE == 1\n",
    )
    repository.write_text(".gitignore", "private-todo/\nprivate-ledger/\n")
    repository.commit()
    for parent in ("config", "private-todo", "private-ledger"):
        (repository.root / parent).mkdir(mode=0o700)
    return repository.root


def _observe(root: Path, callback: Callable[[SyscallStop], bool]) -> dict[str, object]:
    """Run and reap one real worker, retaining the unmodified native trace."""
    result = run_traced(
        [
            sys.executable,
            "-B",
            str(Path(__file__).with_name("filesystem_refusal_worker.py")),
            "bootstrap",
            str(root),
        ],
        callback,
        timeout=90,
    )
    write_trace(root.parent / "bootstrap-trace.json", result)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def test_native_bootstrap_control_preserves_absent_ledger(adopter: Path) -> None:
    """Observation alone retains valid policy/TODO creation and ledger absence."""
    result = _observe(adopter, lambda _stop: False)
    assert result["accepted"] is True
    policy = json.loads((adopter / _POLICY).read_text())
    assert policy["canonical_todo"] == _TODO.as_posix()
    assert (adopter / _TODO).stat().st_mode & 0o777 == 0o600
    assert not (adopter / _LEDGER).exists()


@pytest.mark.parametrize("relative", [_POLICY, _TODO], ids=["policy", "todo"])
def test_concurrent_leaf_creation_refuses_without_overwrite(adopter: Path, relative: Path) -> None:
    """A real writer winning immediately before O_EXCL keeps its exact bytes."""
    target = adopter / relative
    marker = b"concurrent owner bytes\n"
    changed = False

    def mutate(stop: SyscallStop) -> bool:
        """Create the owned leaf immediately before its exclusive open."""
        nonlocal changed
        if not changed and stop.number == 257 and stop.entering and stop.path == str(target):
            target.write_bytes(marker)
            changed = True
        return False

    result = _observe(adopter, mutate)
    assert changed
    assert result["accepted"] is False
    assert "already exists; bootstrap never overwrites" in str(result["error"])
    assert target.read_bytes() == marker
    assert not (adopter / _LEDGER).exists()


@pytest.mark.parametrize("after_creation", [False, True], ids=["git-checks", "final-check"])
def test_root_replacement_refuses_at_both_identity_checks(
    adopter: Path, after_creation: bool
) -> None:
    """A new actual root inode cannot replace the retained root before success."""
    opened_root = False
    opened_todo = False
    completed_git_commands = 0
    changed = False
    retained = adopter.with_name("retained-adopter")

    def mutate(stop: SyscallStop) -> bool:
        """Replace the root at the selected actual identity sample."""
        nonlocal opened_root, opened_todo, changed, completed_git_commands
        if stop.number == 61 and not stop.entering and stop.result > 0:
            completed_git_commands += 1
        if stop.number == 257 and not stop.entering and stop.result >= 0:
            opened_root |= stop.path == str(adopter)
            opened_todo |= stop.path == str(adopter / _TODO)
        if (
            not changed
            and opened_root
            and opened_todo == after_creation
            # Version, worktree root, three ls-files and three two-call ignore checks.
            and (after_creation or completed_git_commands == 11)
            and stop.number == 262
            and stop.entering
            and stop.path == str(adopter)
        ):
            adopter.rename(retained)
            adopter.mkdir(mode=0o700)
            changed = True
        return False

    result = _observe(adopter, mutate)
    assert changed
    assert result["accepted"] is False
    expected = "during bootstrap" if after_creation else "during Git checks"
    assert expected in str(result["error"])
    assert not (adopter / _POLICY).exists()
    assert (retained / _POLICY).exists() is after_creation
    assert (retained / ".git/HEAD").is_file()


@pytest.mark.parametrize(
    ("parent", "message"),
    [
        ("config", "policy parent"),
        ("private-todo", "TODO parent"),
        ("private-ledger", "review-ledger parent"),
    ],
)
def test_final_parent_replacement_refuses(adopter: Path, parent: str, message: str) -> None:
    """Reopening each final parent detects an actual directory inode substitution."""
    target = adopter / parent
    retained = adopter / ("retained-" + parent)
    opened_todo = False
    changed = False

    def mutate(stop: SyscallStop) -> bool:
        """Replace the owned parent immediately before its final reopen."""
        nonlocal opened_todo, changed
        if stop.number == 257 and not stop.entering and stop.result >= 0:
            opened_todo |= stop.path == str(adopter / _TODO)
        if (
            not changed
            and opened_todo
            and stop.number == 257
            and stop.entering
            and stop.path == str(target)
        ):
            target.rename(retained)
            target.mkdir(mode=0o700)
            changed = True
        return False

    result = _observe(adopter, mutate)
    assert changed
    assert result["accepted"] is False
    assert message + " changed during bootstrap" in str(result["error"])
    assert retained.is_dir() and target.is_dir()


@pytest.mark.parametrize("relative", [_POLICY, _TODO], ids=["policy", "todo"])
@pytest.mark.parametrize("mutation", ["inode", "directory", "hardlink"])
def test_final_leaf_identity_and_link_checks_refuse(
    adopter: Path, relative: Path, mutation: str
) -> None:
    """Equal-byte new inodes, directories and extra hardlinks all prevent success."""
    target = adopter / relative
    retained = adopter / ("retained-" + target.name)
    opened_todo = False
    changed = False
    original = b""

    def mutate(stop: SyscallStop) -> bool:
        """Alter the leaf before the independent final parent sample."""
        nonlocal opened_todo, changed, original
        if stop.number == 257 and not stop.entering and stop.result >= 0:
            opened_todo |= stop.path == str(adopter / _TODO)
        if (
            not changed
            and opened_todo
            and stop.number == 257
            and not stop.entering
            and stop.result >= 0
            and stop.path == str(adopter / _LEDGER.parent)
        ):
            original = target.read_bytes()
            if mutation == "hardlink":
                os.link(target, retained)
            else:
                target.rename(retained)
                if mutation == "directory":
                    target.mkdir(mode=0o700)
                else:
                    target.write_bytes(original)
            changed = True
        return False

    result = _observe(adopter, mutate)
    assert changed
    assert result["accepted"] is False
    expected = (
        "path changed during bootstrap" if mutation == "inode" else "single-link regular file"
    )
    assert expected in str(result["error"])
    assert retained.read_bytes() == original


@pytest.mark.parametrize("after_sample", [False, True], ids=["before-sample", "after-sample"])
def test_final_ledger_absence_is_a_sample_not_a_reservation(
    adopter: Path, after_sample: bool
) -> None:
    """The final absence check refuses presence but cannot reserve an uncreated path."""
    target = adopter / _LEDGER
    marker = b"concurrent owner ledger\n"
    opened_todo = False
    changed = False

    def mutate(stop: SyscallStop) -> bool:
        """Write the ledger immediately before or after its final stat."""
        nonlocal opened_todo, changed
        if stop.number == 257 and not stop.entering and stop.result >= 0:
            opened_todo |= stop.path == str(adopter / _TODO)
        if (
            not changed
            and opened_todo
            and stop.number == 262
            and stop.path == str(target)
            and stop.entering != after_sample
        ):
            if after_sample:
                assert stop.result == -2
            target.write_bytes(marker)
            changed = True
        return False

    result = _observe(adopter, mutate)
    assert changed
    assert result["accepted"] is after_sample
    if not after_sample:
        assert "never overwrites or adopts an existing review-ledger path" in str(result["error"])
    assert target.read_bytes() == marker


@pytest.mark.parametrize("owner", ["policy", "TODO", "review-ledger"])
@pytest.mark.parametrize("mutation", ["ignored", "tracked"])
def test_final_git_ownership_changes_refuse(adopter: Path, owner: str, mutation: str) -> None:
    """Real ignore-file or index changes cannot alter the declared ownership."""
    opened_todo = False
    changed = False

    def mutate(stop: SyscallStop) -> bool:
        """Change actual tracking or ignore rules after the absence sample."""
        nonlocal opened_todo, changed
        if stop.number == 257 and not stop.entering and stop.result >= 0:
            opened_todo |= stop.path == str(adopter / _TODO)
        if (
            not changed
            and opened_todo
            and stop.number == 262
            and not stop.entering
            and stop.path == str(adopter / _LEDGER)
            and stop.result == -2
        ):
            if mutation == "tracked":
                relative = {"policy": _POLICY, "TODO": _TODO, "review-ledger": _LEDGER}[owner]
                if owner == "review-ledger":
                    (adopter / relative).write_bytes(b"concurrent tracked ledger\n")
                GitRepository(adopter, "/usr/bin/git").git_command(
                    "add", "--force", "--", relative.as_posix()
                )
            else:
                ignored = ["private-todo/", "private-ledger/"]
                if owner == "policy":
                    ignored.append("config/policy.json")
                elif owner == "TODO":
                    ignored.remove("private-todo/")
                else:
                    ignored.remove("private-ledger/")
                (adopter / ".gitignore").write_text("\n".join(ignored) + "\n")
            changed = True
        return False

    result = _observe(adopter, mutate)
    assert changed
    assert result["accepted"] is False
    label = "policy" if owner == "policy" else owner + " path"
    assert label + " Git ownership changed during bootstrap" in str(result["error"])
