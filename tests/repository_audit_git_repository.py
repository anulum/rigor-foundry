# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
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

from rigor_foundry.models import AUDIT_DOMAINS


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
    def create(cls, root: Path) -> GitRepository:
        """Initialise a real repository with internal paths ignored."""
        git = shutil.which("git")
        if git is None:
            raise RuntimeError("git is required for repository-audit tests")
        root.mkdir(parents=True)
        repository = cls(root=root, git=str(Path(git).resolve(strict=True)))
        repository.git_command("init", "--initial-branch=main")
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
    ) -> Path:
        """Write a complete internal repository policy for this worktree."""
        policy: dict[str, object] = {
            "schema_version": "1.0",
            "source_line_threshold": source_threshold,
            "test_line_threshold": test_threshold,
            "source_roots": ["src", "tools"],
            "test_roots": ["tests"],
            "production_packages": ["pkg"],
            "module_size_registries": registries or [],
            "canonical_todo": "docs/internal/work/INDEX.md",
            "review_ledger": "docs/internal/audit/reviews.json",
            "enforcement_mode": "observe",
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
