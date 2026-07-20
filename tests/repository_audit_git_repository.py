# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real Git repository audit test support
"""Create real isolated Git repositories for repository-audit verification."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from rigor_foundry.candidate_anchor import RepositoryTreeAnchor
from rigor_foundry.git_provenance import GitExecutableProvenance, GitTrustPolicy
from rigor_foundry.models import AUDIT_DOMAINS


def sample_git_provenance() -> GitExecutableProvenance:
    """Return deterministic well-formed executable evidence for model tests."""
    return GitExecutableProvenance.build(
        resolved_path="/usr/bin/git",
        trusted_root="/usr/bin",
        version="2.43.0",
        executable_digest="4" * 64,
        trust_policy=GitTrustPolicy(trusted_roots=("/usr/bin",)),
    )


def sample_tree_anchor(path: str) -> RepositoryTreeAnchor:
    """Return a deterministic repository-tree anchor for model tests."""
    return RepositoryTreeAnchor(
        path=path,
        line_start=1,
        line_end=1,
        tree_oid="2" * 40,
        tracked_content_sha256="3" * 64,
    )


@dataclass(frozen=True)
class CommandResult:
    """Observed real process result used by CLI integration assertions."""

    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class GitRepository:
    """One real isolated Git worktree with deterministic local identity."""

    root: Path
    git: str

    @classmethod
    def create(cls, root: Path, *, object_format: str = "sha1") -> GitRepository:
        """Initialise a real repository with internal paths ignored."""
        git = shutil.which("git")
        if git is None:
            raise RuntimeError("git is required for repository-audit tests")
        root.mkdir(parents=True)
        repository = cls(root=root, git=str(Path(git).resolve(strict=True)))
        arguments = ["init", "--initial-branch=main"]
        if object_format == "sha256":
            arguments.append("--object-format=sha256")
        elif object_format != "sha1":
            raise ValueError("unsupported test repository object format")
        repository.git_command(*arguments)
        repository.git_command("config", "user.name", "Repository Audit Tests")
        repository.git_command("config", "user.email", "audit-tests@example.invalid")
        repository.write_text(".gitignore", ".coordination/\n.rigor/\ndocs/internal/\n")
        return repository

    def git_command(self, *arguments: str) -> CommandResult:
        """Run Git with an absolute executable and no shell."""
        completed = subprocess.run(  # nosec B603
            [self.git, *arguments],
            cwd=self.root,
            check=False,
            capture_output=True,
            shell=False,
            text=True,
        )
        result = CommandResult(completed.returncode, completed.stdout, completed.stderr)
        if result.returncode != 0:
            raise RuntimeError(f"git {' '.join(arguments)} failed: {result.stdout}{result.stderr}")
        return result

    def write_text(self, relative: str, text: str) -> Path:
        """Write one UTF-8 worktree path."""
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def write_bytes(self, relative: str, payload: bytes) -> Path:
        """Write one binary worktree path."""
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return target

    def symlink(self, relative: str, target: str) -> Path:
        """Create one real worktree symlink."""
        link = self.root / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, link)
        return link

    def commit(self, message: str = "test: repository audit fixture") -> str:
        """Commit every non-ignored path and return the exact commit SHA."""
        self.git_command("add", "--all")
        self.git_command("commit", "-m", message)
        return self.git_command("rev-parse", "HEAD").stdout.strip()

    def write_policy(
        self,
        *,
        source_threshold: int = 1000,
        test_threshold: int = 1000,
        native_audits: list[dict[str, object]] | None = None,
        required_domains: frozenset[str] = frozenset(
            {
                "test-authenticity",
                "architecture-and-wiring",
                "godfile-responsibility",
                "ownership-and-maintenance",
            }
        ),
        registries: list[str] | None = None,
        ignored_inventory: list[dict[str, str]] | None = None,
        enforcement_mode: str = "observe",
        maturity_policy_digest: str | None = None,
        cra: dict[str, object] | None = None,
    ) -> Path:
        """Write a complete internal repository policy for this worktree."""
        policy: dict[str, object] = {
            "schema_version": "1.4" if cra is not None else "1.3",
            "source_line_threshold": source_threshold,
            "test_line_threshold": test_threshold,
            "source_roots": ["src", "tools"],
            "test_roots": ["tests"],
            "production_packages": ["pkg"],
            "module_size_registries": registries or [],
            "canonical_todo": "docs/internal/work/INDEX.md",
            "review_ledger": "docs/internal/audit/reviews.json",
            "enforcement_mode": enforcement_mode,
            "maturity_policy_digest": maturity_policy_digest,
            "ignored_inventory": ignored_inventory or [],
            "audit_domains": [
                {
                    "name": domain,
                    "applicability": (
                        "required" if domain in required_domains else "not-applicable"
                    ),
                    "rationale": f"repository-specific decision for {domain}",
                }
                for domain in AUDIT_DOMAINS
            ],
            "native_audits": native_audits or [],
        }
        if cra is not None:
            policy["cra"] = cra
        return self.write_text(
            "rigor-foundry-policy.json",
            json.dumps(policy, indent=2, sort_keys=True) + "\n",
        )

    def run_audit(self, *arguments: str) -> CommandResult:
        """Run the real repository-audit CLI with the active interpreter."""
        completed = subprocess.run(  # nosec B603
            [sys.executable, "-m", "rigor_foundry", *arguments],
            cwd=self.root,
            check=False,
            capture_output=True,
            shell=False,
            text=True,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)
