# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit adopter bootstrap tests
"""Exercise fail-closed bootstrap behavior through real Git and filesystems."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.bootstrap import bootstrap_repository
from rigor_foundry.models import AUDIT_DOMAINS, AuditPolicy

_POLICY = Path("rigor-foundry-policy.json")
_TODO = Path("docs/internal/TODO.md")
_LEDGER = Path("docs/internal/reviews.json")
Mutation = Literal[
    "create-ledger",
    "drop-todo-ignore",
    "hardlink-policy",
    "replace-policy",
    "replace-ledger-parent",
    "replace-root",
    "replace-todo",
    "replace-todo-parent",
    "track-policy",
]


def _apply_real_mutation(repository: GitRepository, mutation: Mutation) -> None:
    """Apply one real filesystem or Git mutation at the revalidation boundary."""
    root = repository.root
    if mutation == "replace-todo-parent":
        internal = root / "docs/internal"
        internal.rename(root / "docs/internal-original")
        internal.mkdir(mode=0o700)
    elif mutation == "replace-ledger-parent":
        reviews = root / "reviews"
        reviews.rename(root / "reviews-original")
        reviews.mkdir(mode=0o700)
    elif mutation == "track-policy":
        repository.git_command("add", "--", _POLICY.as_posix())
    elif mutation == "replace-policy":
        policy = root / _POLICY
        policy.rename(root / "rigor-foundry-policy-original.json")
        policy.write_text("concurrent policy\n", encoding="utf-8")
    elif mutation == "replace-todo":
        todo = root / _TODO
        todo.rename(todo.with_name("TODO-original.md"))
        todo.write_text("concurrent TODO\n", encoding="utf-8")
    elif mutation == "drop-todo-ignore":
        (root / ".gitignore").write_text("", encoding="utf-8")
    elif mutation == "create-ledger":
        (root / _LEDGER).write_text("concurrent ledger\n", encoding="utf-8")
    elif mutation == "hardlink-policy":
        os.link(root / _POLICY, root / "rigor-foundry-policy-hardlink.json")
    else:
        root.rename(root.with_name(root.name + "-original"))
        root.mkdir(mode=0o700)


def _bootstrap_with_real_mutation(
    repository: GitRepository,
    mutation: Mutation,
    *,
    ledger_path: Path = _LEDGER,
) -> None:
    """Mutate real state immediately before bootstrap's final root revalidation."""
    real_stat = os.stat
    mutated = False

    def revalidation_stat(path, *args, **kwargs):
        nonlocal mutated
        if not mutated and Path(path) == repository.root:
            try:
                real_stat(repository.root / _POLICY, follow_symlinks=False)
                real_stat(repository.root / _TODO, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                mutated = True
                _apply_real_mutation(repository, mutation)
        return real_stat(path, *args, **kwargs)

    os.stat = revalidation_stat
    try:
        _bootstrap(repository, ledger_path=ledger_path)
    finally:
        os.stat = real_stat
    assert mutated


def _repository(path: Path) -> GitRepository:
    """Create one adopter repository with explicit roots and ignored internals."""
    repository = GitRepository.create(path)
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text(
        "tests/test_core.py",
        "from pkg import core\n\ndef test_value() -> None:\n    assert core.VALUE == 1\n",
    )
    repository.write_text(".gitignore", "docs/internal/\n")
    repository.commit()
    (repository.root / "docs/internal").mkdir(parents=True)
    return repository


def _bootstrap(repository: GitRepository, *, ledger_path: Path = _LEDGER):
    """Run the public bootstrap with the fixture's explicit contract."""
    return bootstrap_repository(
        repository.root,
        policy_path=_POLICY,
        todo_path=_TODO,
        review_ledger_path=ledger_path,
        source_roots=(Path("src"),),
        test_roots=(Path("tests"),),
    )


def test_bootstrap_creates_exact_fail_closed_policy_and_private_todo(tmp_path: Path) -> None:
    """One call creates only the explicit files with all domains initially required."""
    repository = _repository(tmp_path / "repository")
    result = _bootstrap(repository)
    policy = AuditPolicy.from_path(repository.root / _POLICY)

    assert result.policy_path == repository.root / _POLICY
    assert result.todo_path == repository.root / _TODO
    assert result.policy_digest == policy.policy_digest
    assert policy.canonical_todo == _TODO.as_posix()
    assert policy.review_ledger == _LEDGER.as_posix()
    assert policy.source_roots == ("src",)
    assert policy.test_roots == ("tests",)
    assert tuple(item.name for item in policy.audit_domains) == AUDIT_DOMAINS
    assert {item.applicability for item in policy.audit_domains} == {"required"}
    assert "candidates, not verdicts" in (repository.root / _TODO).read_text(encoding="utf-8")
    assert stat_mode(repository.root / _POLICY) == 0o644
    assert stat_mode(repository.root / _TODO) == 0o600
    assert not (repository.root / _LEDGER).exists()


def stat_mode(path: Path) -> int:
    """Return the permission bits of one real created file."""
    return path.stat(follow_symlinks=False).st_mode & 0o777


def test_bootstrap_never_overwrites_and_leaves_no_partial_policy(tmp_path: Path) -> None:
    """Existing canonical state aborts without changing bytes or leaving a policy."""
    repository = _repository(tmp_path / "repository")
    todo = repository.root / _TODO
    todo.write_text("# Existing owner TODO\n", encoding="utf-8")
    before = todo.read_bytes()

    with pytest.raises(ValueError, match="never overwrites"):
        _bootstrap(repository)

    assert todo.read_bytes() == before
    assert not (repository.root / _POLICY).exists()


@pytest.mark.parametrize(
    ("policy", "todo", "ledger", "message"),
    [
        (Path("../policy.json"), _TODO, _LEDGER, "policy path"),
        (_POLICY, Path("../TODO.md"), _LEDGER, "TODO path"),
        (_POLICY, _TODO, _TODO, "must be distinct"),
    ],
)
def test_bootstrap_rejects_ambiguous_or_escaping_paths(
    tmp_path: Path,
    policy: Path,
    todo: Path,
    ledger: Path,
    message: str,
) -> None:
    """Every adopter-owned path is explicit, distinct, and repository relative."""
    repository = _repository(tmp_path / "repository")
    with pytest.raises(ValueError, match=message):
        bootstrap_repository(
            repository.root,
            policy_path=policy,
            todo_path=todo,
            review_ledger_path=ledger,
            source_roots=(Path("src"),),
            test_roots=(Path("tests"),),
        )


def test_bootstrap_rejects_ignore_and_index_mismatches(tmp_path: Path) -> None:
    """Policy remains trackable while internal paths must be ignored and untracked."""
    unignored = _repository(tmp_path / "unignored")
    unignored.write_text(".gitignore", "")
    unignored.commit("test: remove internal ignore")
    (unignored.root / "docs/internal").mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="TODO path must be covered"):
        _bootstrap(unignored)

    ignored_policy = _repository(tmp_path / "ignored-policy")
    ignored_policy.write_text(".gitignore", "docs/internal/\nrigor-foundry-policy.json\n")
    ignored_policy.commit("test: ignore policy")
    with pytest.raises(ValueError, match="policy path must be trackable"):
        _bootstrap(ignored_policy)

    tracked_policy = _repository(tmp_path / "tracked-policy")
    tracked_policy.write_text(_POLICY.as_posix(), "{}\n")
    tracked_policy.commit("test: track policy")
    os.unlink(tracked_policy.root / _POLICY)
    with pytest.raises(ValueError, match="already tracked"):
        _bootstrap(tracked_policy)


def test_bootstrap_rejects_symlinked_parent_and_missing_roots(tmp_path: Path) -> None:
    """Descriptor traversal rejects aliases and typoed source/test roots before writes."""
    repository = _repository(tmp_path / "repository")
    (repository.root / "docs/internal").rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, repository.root / "docs/internal")
    with pytest.raises(ValueError, match="symlink-free"):
        _bootstrap(repository)
    assert not (repository.root / _POLICY).exists()

    os.unlink(repository.root / "docs/internal")
    (repository.root / "docs/internal").mkdir()
    with pytest.raises(ValueError, match="source root parent"):
        bootstrap_repository(
            repository.root,
            policy_path=_POLICY,
            todo_path=_TODO,
            review_ledger_path=_LEDGER,
            source_roots=(Path("absent"),),
            test_roots=(Path("tests"),),
        )


def test_bootstrap_requires_exact_real_git_root_and_unique_existing_roots(
    tmp_path: Path,
) -> None:
    """Root aliases, subdirectories, empty roots, duplicates, and files fail closed."""
    repository = _repository(tmp_path / "repository")
    alias = tmp_path / "alias"
    os.symlink(repository.root, alias)
    with pytest.raises(ValueError, match="real directory"):
        bootstrap_repository(
            alias,
            policy_path=_POLICY,
            todo_path=_TODO,
            review_ledger_path=_LEDGER,
            source_roots=(Path("src"),),
            test_roots=(Path("tests"),),
        )
    with pytest.raises(ValueError, match="exact Git worktree root"):
        bootstrap_repository(
            repository.root / "src",
            policy_path=_POLICY,
            todo_path=_TODO,
            review_ledger_path=_LEDGER,
            source_roots=(Path("pkg"),),
            test_roots=(Path("pkg"),),
        )
    with pytest.raises(ValueError, match="at least one source root"):
        bootstrap_repository(
            repository.root,
            policy_path=_POLICY,
            todo_path=_TODO,
            review_ledger_path=_LEDGER,
            source_roots=(),
            test_roots=(Path("tests"),),
        )
    with pytest.raises(ValueError, match="source root values must be unique"):
        bootstrap_repository(
            repository.root,
            policy_path=_POLICY,
            todo_path=_TODO,
            review_ledger_path=_LEDGER,
            source_roots=(Path("src"), Path("src")),
            test_roots=(Path("tests"),),
        )
    with pytest.raises(ValueError, match="test root parent"):
        bootstrap_repository(
            repository.root,
            policy_path=_POLICY,
            todo_path=_TODO,
            review_ledger_path=_LEDGER,
            source_roots=(Path("src"),),
            test_roots=(Path("tests/test_core.py"),),
        )


def test_bootstrap_rejects_tracked_internal_paths_and_invalid_thresholds(
    tmp_path: Path,
) -> None:
    """Tracked ledgers and invalid policy numbers cannot enter generated state."""
    tracked_todo = _repository(tmp_path / "tracked-todo")
    tracked_todo.write_text(".gitignore", "")
    tracked_todo.write_text(_TODO.as_posix(), "# Tracked\n")
    tracked_todo.commit("test: track TODO")
    tracked_todo.write_text(".gitignore", "docs/internal/\n")
    tracked_todo.commit("test: ignore internal namespace")
    os.unlink(tracked_todo.root / _TODO)
    with pytest.raises(ValueError, match="TODO path must not be tracked"):
        _bootstrap(tracked_todo)

    existing_ledger = _repository(tmp_path / "existing-ledger")
    ledger = existing_ledger.root / _LEDGER
    ledger.write_text("adopter-owned ledger\n", encoding="utf-8")
    before = ledger.read_bytes()
    with pytest.raises(ValueError, match="existing review-ledger path"):
        _bootstrap(existing_ledger)
    assert ledger.read_bytes() == before
    assert not (existing_ledger.root / _POLICY).exists()
    assert not (existing_ledger.root / _TODO).exists()

    repository = _repository(tmp_path / "invalid-threshold")
    with pytest.raises(ValueError, match="source_line_threshold"):
        bootstrap_repository(
            repository.root,
            policy_path=_POLICY,
            todo_path=_TODO,
            review_ledger_path=_LEDGER,
            source_roots=(Path("src"),),
            test_roots=(Path("tests"),),
            source_line_threshold=0,
        )


def test_bootstrap_preserves_created_policy_when_private_todo_cannot_be_created(
    tmp_path: Path,
) -> None:
    """A failed write preserves evidence rather than risking destructive rollback."""
    repository = _repository(tmp_path / "repository")
    internal = repository.root / "docs/internal"
    internal.chmod(0o500)
    try:
        with pytest.raises(PermissionError):
            _bootstrap(repository)
    finally:
        internal.chmod(0o700)
    assert (repository.root / _POLICY).is_file()
    assert not (repository.root / _TODO).exists()


def test_bootstrap_detects_real_parent_replacement_and_preserves_evidence(
    tmp_path: Path,
) -> None:
    """A process replacing the TODO parent cannot redirect descriptor-bound writes."""
    repository = _repository(tmp_path / "repository")
    with pytest.raises(RuntimeError, match="TODO parent changed"):
        _bootstrap_with_real_mutation(repository, "replace-todo-parent")
    assert (repository.root / _POLICY).is_file()
    assert not (repository.root / _TODO).exists()
    assert (repository.root / "docs/internal-original/TODO.md").is_file()


def test_bootstrap_detects_real_review_ledger_parent_replacement(tmp_path: Path) -> None:
    """The separately retained ledger parent cannot be swapped before return."""
    repository = _repository(tmp_path / "repository")
    repository.write_text(".gitignore", "docs/internal/\nreviews/\n")
    repository.commit("test: ignore separate review ledger")
    (repository.root / "reviews").mkdir()
    ledger = Path("reviews/reviews.json")

    with pytest.raises(RuntimeError, match="review-ledger parent changed"):
        _bootstrap_with_real_mutation(
            repository,
            "replace-ledger-parent",
            ledger_path=ledger,
        )

    assert (repository.root / _POLICY).is_file()
    assert (repository.root / _TODO).is_file()
    assert not (repository.root / ledger).exists()
    assert (repository.root / "reviews-original").is_dir()


def test_bootstrap_detects_real_git_ownership_drift_and_preserves_evidence(
    tmp_path: Path,
) -> None:
    """A concurrent real Git add cannot turn bootstrap output into an accepted result."""
    repository = _repository(tmp_path / "repository")
    with pytest.raises(RuntimeError, match="policy Git ownership changed"):
        _bootstrap_with_real_mutation(repository, "track-policy")
    assert (repository.root / _POLICY).is_file()
    assert (repository.root / _TODO).is_file()
    assert repository.git_command("ls-files", _POLICY.as_posix()).stdout.strip() == (
        _POLICY.as_posix()
    )


@pytest.mark.parametrize(
    ("mutation", "watch_internal", "message"),
    [
        ("replace-policy", False, "policy path changed"),
        ("replace-root", False, "repository root identity changed"),
        ("replace-todo", True, "TODO path changed"),
        ("drop-todo-ignore", True, "TODO path Git ownership changed"),
    ],
)
def test_bootstrap_detects_real_path_and_ignore_drift(
    tmp_path: Path,
    mutation: Mutation,
    watch_internal: bool,
    message: str,
) -> None:
    """Ready-synchronised real mutations activate each public fail-closed boundary."""
    repository = _repository(tmp_path / mutation)
    original_root = repository.root.with_name(repository.root.name + "-original")
    assert watch_internal is (mutation in {"drop-todo-ignore", "replace-todo"})
    with pytest.raises(RuntimeError, match=message):
        _bootstrap_with_real_mutation(repository, mutation)
    if mutation == "replace-root":
        assert (original_root / _POLICY).is_file()
        assert (original_root / _TODO).is_file()
    elif mutation == "replace-policy":
        assert (repository.root / _POLICY).read_text(encoding="utf-8") == "concurrent policy\n"
        assert (repository.root / "rigor-foundry-policy-original.json").is_file()
        assert (repository.root / _TODO).is_file()
    elif mutation == "replace-todo":
        assert (repository.root / _TODO).read_text(encoding="utf-8") == "concurrent TODO\n"
        assert (repository.root / "docs/internal/TODO-original.md").is_file()
        assert (repository.root / _POLICY).is_file()
    else:
        assert (repository.root / _POLICY).is_file()
        assert (repository.root / _TODO).is_file()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("create-ledger", "existing review-ledger path"),
        ("hardlink-policy", "single-link regular file"),
    ],
)
def test_bootstrap_detects_real_ledger_and_hardlink_races(
    tmp_path: Path,
    mutation: Mutation,
    message: str,
) -> None:
    """Real concurrent filesystem changes fail closed without deleting evidence."""
    repository = _repository(tmp_path / mutation)
    with pytest.raises((RuntimeError, ValueError), match=message):
        _bootstrap_with_real_mutation(repository, mutation)
    assert (repository.root / _POLICY).is_file()
    assert (repository.root / _TODO).is_file()
    if mutation == "create-ledger":
        assert (repository.root / _LEDGER).read_text(encoding="utf-8") == ("concurrent ledger\n")
    else:
        assert (repository.root / "rigor-foundry-policy-hardlink.json").is_file()


def test_bootstrap_normalises_real_git_index_failure(tmp_path: Path) -> None:
    """Corrupt Git index state cannot be interpreted as an untracked bootstrap target."""
    repository = _repository(tmp_path / "repository")
    (repository.root / ".git/index").write_bytes(b"invalid index")
    with pytest.raises(RuntimeError, match="Git tracked-path check failed"):
        _bootstrap(repository)


def test_real_cli_bootstrap_uses_explicit_paths_and_refuses_second_run(tmp_path: Path) -> None:
    """The installed command boundary creates once and returns input-error status thereafter."""
    repository = _repository(tmp_path / "repository")
    arguments = (
        "bootstrap",
        "--root",
        ".",
        "--policy",
        _POLICY.as_posix(),
        "--todo",
        _TODO.as_posix(),
        "--review-ledger",
        _LEDGER.as_posix(),
        "--source-root",
        "src",
        "--test-root",
        "tests",
    )
    first = repository.run_audit(*arguments)
    assert first.returncode == 0, first.stderr
    assert "policy_digest=" in first.stdout
    second = repository.run_audit(*arguments)
    assert second.returncode == 2
    assert "never overwrites" in second.stderr
