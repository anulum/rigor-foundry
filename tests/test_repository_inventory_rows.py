# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository inventory preimage tests
"""Exercise complete index/file preimages with actual conflict and file bytes."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository
from test_task_definition import budget

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.repository_inventory_rows import (
    RepositoryFileRow,
    RepositoryIndexEntry,
    RepositoryIndexState,
    parse_git_index_state,
    parse_repository_file_rows,
    repository_file_rows_digest,
    require_inventory_path,
)


def row(path: str = "src/main.py") -> RepositoryFileRow:
    """Declare known regular bytes independently of their optional Git blob."""
    return RepositoryFileRow(
        path, "regular", "100644", None, hashlib.sha256(b"x").hexdigest(), 1, "python", "source"
    )


def entry(path: str = "src/main.py", stage: int = 0, width: int = 40) -> RepositoryIndexEntry:
    """Supply complete index identities for boundary corruption tests."""
    return RepositoryIndexEntry(path, stage, "100644", "a" * width)


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_actual_git_conflict_preserves_all_stages(tmp_path: Path, object_format: str) -> None:
    """A real merge retains stages one/two/three and a complete unmerged path union."""
    repository = GitRepository.create(tmp_path / "repository", object_format=object_format)
    repository.write_text("src/main.py", "base\n")
    repository.commit()
    clean = parse_git_index_state(
        repository.git_command("ls-files", "--stage", "-z").stdout.encode(), budget=budget()
    )
    assert clean.unmerged_paths == ()
    repository.git_command("checkout", "-b", "side")
    repository.write_text("src/main.py", "side\n")
    repository.commit()
    repository.git_command("checkout", "main")
    repository.write_text("src/main.py", "main\n")
    repository.commit()
    with pytest.raises(RuntimeError, match="CONFLICT"):
        repository.git_command("merge", "side")
    actual = parse_git_index_state(
        repository.git_command("ls-files", "--stage", "-z").stdout.encode(), budget=budget()
    )
    assert actual.unmerged_paths == ("src/main.py",)
    assert [item.stage for item in actual.entries if item.relative_path == "src/main.py"] == [
        1,
        2,
        3,
    ]
    assert actual.digest(budget=budget()) == canonical_digest(actual.to_dict())
    assert actual.digest(budget=budget()) != clean.digest(budget=budget())
    assert RepositoryIndexState.from_dict(actual.to_dict(), budget=budget()) == actual
    assert {len(item.object_id) for item in actual.entries} == (
        {40} if object_format == "sha1" else {64}
    )


def test_actual_file_bytes_and_nullable_classifications_are_retained(tmp_path: Path) -> None:
    """Unknown language and deleted/generated observations remain explicit digest inputs."""
    path = tmp_path / "main.py"
    payload = b"VALUE = 1\r\n"
    path.write_bytes(payload)
    observed = RepositoryFileRow(
        "src/main.py",
        "regular",
        "100644",
        None,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        path.stat().st_size,
        "python",
        "source",
    )
    deleted = RepositoryFileRow(
        "src/old.py", "deleted", "100644", "a" * 40, None, None, "python", "source"
    )
    unresolved = RepositoryFileRow(
        "src/unknown", "unsupported", None, None, None, None, None, None
    )
    rows = (observed, deleted, unresolved)
    assert parse_repository_file_rows([item.to_dict() for item in rows], budget=budget()) == rows
    assert repository_file_rows_digest(rows, budget=budget()) == canonical_digest(
        [item.to_dict() for item in rows]
    )
    assert repository_file_rows_digest((), budget=budget()) == canonical_digest([])
    link = RepositoryFileRow(
        "src/link",
        "symlink",
        "120000",
        "b" * 40,
        hashlib.sha256(b"main.py").hexdigest(),
        7,
        "python",
        "source",
    )
    submodule = RepositoryFileRow(
        "vendor", "gitlink", "160000", "c" * 40, None, None, None, "dependency"
    )
    for item in (link, submodule):
        assert RepositoryFileRow.from_dict(item.to_dict()) == item
    assert "schema_version" not in observed.to_dict()


@pytest.mark.parametrize(
    "path",
    [
        ".",
        "../x",
        "/x",
        "a/../x",
        "a/./x",
        "a//x",
        "a/",
        "a\\x",
        "a\0x",
        "C:/x",
        ".git/index",
        "x/.GIT/config",
        "",
    ],
)
def test_nonportable_or_escaping_paths_refuse(path: str) -> None:
    """No normalization can silently rewrite a signed path or expose Git metadata."""
    with pytest.raises(ValueError):
        require_inventory_path(path)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("kind", "directory"),
        ("mode", "100600"),
        ("mode", "120000"),
        ("object_id", "short"),
        ("byte_digest", "bad"),
        ("byte_count", True),
        ("byte_count", -1),
        ("byte_count", None),
        ("byte_digest", None),
        ("language", "bad language"),
        ("role", ""),
        ("relative_path", None),
    ],
)
def test_invalid_file_rows_refuse(field: str, invalid: object) -> None:
    """Malformed identities and contradictory observations cannot enter preimages."""
    data = row().to_dict()
    data[field] = invalid
    with pytest.raises(ValueError):
        RepositoryFileRow.from_dict(data)


def test_deleted_gitlink_and_missing_bytes_relations_refuse() -> None:
    """Present bytes, missing files and submodule commits have distinct meanings."""
    base = row().to_dict()
    changes: list[dict[str, object]] = [
        {"kind": "deleted"},
        {"kind": "gitlink", "mode": "160000"},
        {"kind": "gitlink", "mode": "160000", "byte_digest": None, "byte_count": None},
        {"byte_digest": None, "byte_count": None},
    ]
    for change in changes:
        with pytest.raises(ValueError):
            RepositoryFileRow.from_dict({**base, **change})
    for value in [None, {**base, "extra": True}, {k: v for k, v in base.items() if k != "role"}]:
        with pytest.raises(ValueError):
            RepositoryFileRow.from_dict(value)


def test_file_array_order_duplicates_types_and_budgets_refuse() -> None:
    """Array ceilings apply before conversion and public hashing rechecks direct rows."""
    first, second = row("a"), row("b")
    for value in [
        None,
        [first.to_dict(), first.to_dict()],
        [second.to_dict(), first.to_dict()],
        [first.to_dict()] * 2,
    ]:
        with pytest.raises(ValueError):
            parse_repository_file_rows(value, budget=budget(max_references=1))
    with pytest.raises(ValueError, match="sorted"):
        parse_repository_file_rows([second.to_dict(), first.to_dict()], budget=budget())
    with pytest.raises(ValueError, match="sorted"):
        repository_file_rows_digest((first, first), budget=budget())
    for invalid in [[], ({},), (first, second)]:
        with pytest.raises(ValueError):
            repository_file_rows_digest(
                cast(tuple[RepositoryFileRow, ...], invalid), budget=budget(max_references=1)
            )
    with pytest.raises(ValueError, match="budget is required"):
        parse_repository_file_rows([], budget=cast(PolicyReadBudget1, {}))
    object.__setattr__(first, "byte_count", True)
    with pytest.raises(ValueError):
        repository_file_rows_digest((first,), budget=budget())


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("stage", -1),
        ("stage", 4),
        ("stage", True),
        ("mode", "bad"),
        ("object_id", "short"),
        ("relative_path", "../x"),
    ],
)
def test_invalid_index_entry_refuses(field: str, invalid: object) -> None:
    """Exact stages and full Git metadata are validated even outside whole-state parsing."""
    data = entry().to_dict()
    data[field] = invalid
    with pytest.raises(ValueError):
        RepositoryIndexEntry.from_dict(data)
    with pytest.raises(ValueError):
        RepositoryIndexEntry.from_dict({**entry().to_dict(), "extra": True})


def test_index_relations_and_direct_corruption_refuse() -> None:
    """Duplicate, missing or mixed stage identities cannot produce a clean index digest."""
    for entries, paths in [
        ((entry(), entry()), ()),
        ((entry("b"), entry("a")), ()),
        ((entry(stage=1),), ()),
        ((entry(),), ("src/main.py",)),
        ((entry(), entry(stage=1)), ("src/main.py",)),
        ((entry("a"), entry("b", width=64)), ()),
    ]:
        with pytest.raises(ValueError):
            RepositoryIndexState(entries, paths)
    invalid_collections: list[tuple[object, object]] = [
        ([], ()),
        (({},), ()),
        ((), []),
        ((entry(),) * 65537, ()),
    ]
    for bad_entries, bad_paths in invalid_collections:
        with pytest.raises(ValueError):
            RepositoryIndexState(
                cast(tuple[RepositoryIndexEntry, ...], bad_entries),
                cast(tuple[str, ...], bad_paths),
            )
    actual = RepositoryIndexState((entry(),), ())
    with pytest.raises(ValueError, match="budget"):
        RepositoryIndexState((entry(stage=1),), ("src/main.py",)).digest(
            budget=budget(max_references=1)
        )
    object.__setattr__(actual.entries[0], "stage", 5)
    with pytest.raises(ValueError):
        actual.digest(budget=budget())
    invalid_states: list[object] = [
        None,
        {"entries": [], "unmerged_paths": [], "extra": True},
        {"entries": [], "unmerged_paths": None},
        {"entries": None, "unmerged_paths": []},
        {"entries": [entry().to_dict()] * 2, "unmerged_paths": []},
    ]
    for value in invalid_states:
        with pytest.raises(ValueError):
            RepositoryIndexState.from_dict(value, budget=budget(max_references=1))


@pytest.mark.parametrize(
    "payload",
    [
        b"missing-nul",
        b"bad\0",
        b"100644 a\tx\0",
        b"100644 " + b"a" * 40 + b" 01\tx\0",
        b"100644 " + b"a" * 40 + b" 0\t\xff\0",
        b"\xff " + b"a" * 40 + b" 0\tx\0",
    ],
)
def test_malformed_raw_git_output_refuses(payload: bytes) -> None:
    """Raw Git metadata requires exact separators, encodings and integer spellings."""
    with pytest.raises(ValueError):
        parse_git_index_state(payload, budget=budget())


def test_raw_git_empty_output_and_allocation_limits() -> None:
    """Empty indexes are observed values; type, byte and row limits still apply."""
    assert parse_git_index_state(b"", budget=budget()).to_dict() == {
        "entries": [],
        "unmerged_paths": [],
    }
    for payload in [cast(bytes, ""), b"x" * 65537, b"\0\0"]:
        with pytest.raises(ValueError):
            parse_git_index_state(payload, budget=budget(max_references=1))
