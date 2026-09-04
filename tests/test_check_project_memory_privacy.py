# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory privacy guard tests
"""Exercise the project-memory privacy boundary against real Git worktrees."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.check_project_memory_privacy import (
    PublicationInventory,
    main,
    project_memory_privacy_errors,
)


def _git(root: Path, *arguments: str) -> None:
    """Run one required Git fixture command."""
    subprocess.run(  # nosec B603
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        shell=False,
        text=True,
        timeout=10,
    )


def _repository(tmp_path: Path) -> Path:
    """Create one real worktree with a portable private-root boundary."""
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.name", "Memory Guard")
    _git(root, "config", "user.email", "memory-guard@example.invalid")
    (root / ".gitignore").write_text("/agentic_project_memory/\n", encoding="utf-8")
    _git(root, "add", ".gitignore")
    _git(root, "commit", "-m", "test: seed privacy boundary")
    memory = root / "agentic_project_memory"
    memory.mkdir(mode=0o700)
    index = memory / "memory_index.md"
    index.write_text("# Synthetic private index\n", encoding="utf-8")
    index.chmod(0o600)
    return root


def _inventory(path: Path, *entries: str) -> Path:
    """Write one canonical NUL-delimited publication inventory."""
    path.write_bytes(b"".join(entry.encode("utf-8") + b"\0" for entry in entries))
    return path


def test_guard_accepts_portable_boundary_and_complete_safe_inventories(tmp_path: Path) -> None:
    """A tracked ignore plus exact safe surface set passes."""
    root = _repository(tmp_path)
    package = _inventory(tmp_path / "package.inventory", "src/example.py", "LICENSE")
    docs = _inventory(tmp_path / "docs.inventory", "site/index.html")
    inventories = (
        PublicationInventory("package", package),
        PublicationInventory("docs", docs),
    )

    assert (
        project_memory_privacy_errors(
            root,
            inventories,
            frozenset({"package", "docs"}),
        )
        == []
    )


def test_guard_rejects_local_only_ignore_policy(tmp_path: Path) -> None:
    """A local exclude cannot substitute for a tracked portable rule."""
    root = _repository(tmp_path)
    _git(root, "rm", "--cached", ".gitignore")
    (root / ".gitignore").write_text("/different-private-root/\n", encoding="utf-8")
    (root / ".git" / "info" / "exclude").write_text(
        "/agentic_project_memory/\n",
        encoding="utf-8",
    )
    assert "portable-ignore-file-not-cached" in project_memory_privacy_errors(root)


def test_guard_rejects_mismatched_or_overridden_ignore_policy(tmp_path: Path) -> None:
    """Working/index drift and later negations cannot masquerade as protection."""
    root = _repository(tmp_path)
    (root / ".gitignore").write_text("/different-private-root/\n", encoding="utf-8")
    assert "portable-ignore-file-index-mismatch" in project_memory_privacy_errors(root)

    (root / ".gitignore").write_text(
        "/agentic_project_memory/\n"
        "!/agentic_project_memory/\n"
        "!/agentic_project_memory/.rigor-memory-leak-canary\n",
        encoding="utf-8",
    )
    _git(root, "add", ".gitignore")
    assert "portable-ignore-rule-overridden" in project_memory_privacy_errors(root)


def test_guard_rejects_force_added_private_content(tmp_path: Path) -> None:
    """A force-added file is caught through the real cached Git inventory."""
    root = _repository(tmp_path)
    _git(root, "add", "--force", "agentic_project_memory/memory_index.md")

    assert "private-root-content-cached" in project_memory_privacy_errors(root)


def test_guard_rejects_private_tree_aliases_and_permissions(tmp_path: Path) -> None:
    """Symlinks, hard links, and broad modes fail without reading file content."""
    root = _repository(tmp_path)
    memory = root / "agentic_project_memory"
    secret = memory / "record.md"
    secret.write_text("synthetic\n", encoding="utf-8")
    secret.chmod(0o600)
    os.link(secret, tmp_path / "alias.md")
    (memory / "external-link").symlink_to(tmp_path)
    memory.chmod(0o755)

    errors = project_memory_privacy_errors(root)
    assert "private-root-mode-invalid" in errors
    assert "private-file-access-invalid" in errors
    assert "private-tree-symlink" in errors


def test_guard_rejects_missing_or_leaking_publication_surfaces(tmp_path: Path) -> None:
    """Required inventories are exact and private-root paths never pass."""
    root = _repository(tmp_path)
    leaking = _inventory(
        tmp_path / "container.inventory",
        "app/main.py",
        "agentic_project_memory/decisions.md",
    )
    inventories = (PublicationInventory("container", leaking),)

    errors = project_memory_privacy_errors(
        root,
        inventories,
        frozenset({"container", "upload"}),
    )
    assert "publication-includes-private-root:container" in errors
    assert "publication-surface-set-mismatch" in errors


def test_guard_rejects_ambiguous_publication_inventories(tmp_path: Path) -> None:
    """Newline lists, path traversal, and duplicate labels fail closed."""
    root = _repository(tmp_path)
    malformed = tmp_path / "malformed.inventory"
    malformed.write_bytes(
        b"../agentic_project_memory/record.md\0"
        b"windows\\agentic_project_memory\\record.md\0"
        b"same/path\0same/path\0"
    )
    newline = tmp_path / "newline.inventory"
    newline.write_text("src/example.py\n", encoding="utf-8")

    errors = project_memory_privacy_errors(
        root,
        (
            PublicationInventory("artifact", malformed),
            PublicationInventory("artifact", newline),
        ),
        frozenset({"artifact"}),
    )
    assert "publication-inventory-entry-invalid:artifact" in errors
    assert "publication-inventory-entry-duplicate:artifact" in errors
    assert "publication-inventory-not-nul-terminated:artifact" in errors
    assert "publication-surface-duplicate" in errors


def test_cli_redacts_findings_and_returns_status(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The process surface reveals only a fixed pass/fail statement."""
    root = _repository(tmp_path)
    assert main(["--repository-root", str(root)]) == 0
    assert capsys.readouterr().out == "Project-memory privacy guard passed\n"
    (root / "agentic_project_memory").chmod(0o755)
    assert main(["--repository-root", str(root)]) == 1
    assert capsys.readouterr().out == (
        "Project-memory privacy guard failed; finding details are redacted.\n"
    )


def test_guard_rejects_repository_root_alias(tmp_path: Path) -> None:
    """A symlink argument is not accepted as the exact worktree root."""
    root = _repository(tmp_path)
    alias = tmp_path / "repository-alias"
    alias.symlink_to(root, target_is_directory=True)

    assert project_memory_privacy_errors(alias) == ["repository-root-not-real-directory"]


def test_standalone_process_has_no_repository_package_dependency(tmp_path: Path) -> None:
    """The guard runs from outside the checkout as a self-contained script."""
    root = _repository(tmp_path)
    script = Path(__file__).resolve().parents[1] / "tools" / "check_project_memory_privacy.py"

    completed = subprocess.run(  # nosec B603
        [sys.executable, str(script), "--repository-root", str(root)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        shell=False,
        text=True,
        timeout=20,
    )

    assert completed.returncode == 0
    assert completed.stdout == "Project-memory privacy guard passed\n"
    assert completed.stderr == ""
