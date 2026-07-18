# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — incremental changed-file scan view
"""Restrict a full deterministic scan report to files changed since a Git reference."""

from __future__ import annotations

import re
from pathlib import Path

from .candidate_anchor import Candidate
from .git_provenance import GitRunner

_GIT_REVISION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@~^{}-]*\Z")


def require_git_revision(reference: str) -> str:
    """Return a validated Git revision, rejecting flag- or path-injection shapes.

    Parameters
    ----------
    reference:
        Caller-supplied ``--changed-since`` revision.

    Raises
    ------
    ValueError
        If the reference is not a plain Git revision (it must start with an
        alphanumeric character, so a leading dash can never reach Git as a flag).
    """
    if _GIT_REVISION.fullmatch(reference) is None:
        raise ValueError("changed-since reference is not a valid Git revision")
    return reference


def resolve_changed_paths(runner: GitRunner, root: Path, reference: str) -> frozenset[str]:
    """Return the repository-relative paths changed between ``reference`` and HEAD.

    The diff runs through the trusted, provenance-bound Git runner; the reference
    is validated first, and ``--`` terminates option parsing so it can only be a
    revision, never a flag or pathspec.
    """
    revision = require_git_revision(reference)
    safe_value = str(root.resolve())
    try:
        completed = runner.run(
            root,
            "-c",
            f"safe.directory={safe_value}",
            "diff",
            "--name-only",
            "-z",
            revision,
            "HEAD",
            "--",
        )
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"git diff for {revision} failed") from exc
    return frozenset(part.decode("utf-8") for part in completed.stdout.split(b"\x00") if part)


def select_changed_candidates(
    candidates: tuple[Candidate, ...],
    changed_paths: frozenset[str],
) -> tuple[Candidate, ...]:
    """Return the candidates anchored in a changed path, in their original order."""
    return tuple(candidate for candidate in candidates if candidate.path in changed_paths)
