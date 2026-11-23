# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Isolated Semgrep environment guard
"""Require the audited interpreter to exclude the isolated Semgrep installation."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import re
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

from tools._repository import ROOT, redacted_guard_exit_code
from tools.check_dependency_audits import PYTHON_LOCKS, SEMGREP_LOCK

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==", re.MULTILINE)


def canonical_name(name: str) -> str:
    """Return the normalised distribution name shared by installs and locks.

    Parameters
    ----------
    name:
        Distribution name as written in a lock or in installed metadata.

    Returns
    -------
    str
        Lower-case name with every run of ``-``, ``_`` and ``.`` replaced by ``-``.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_names(text: str) -> set[str]:
    """Return the distributions pinned by one hash-locked requirements file.

    Parameters
    ----------
    text:
        Complete requirements lock text with one ``name==version`` line per pin.

    Returns
    -------
    set[str]
        Canonical names of every pinned distribution.
    """
    return {canonical_name(name) for name in _PIN.findall(text)}


def semgrep_only_names(root: Path = ROOT) -> set[str]:
    """Return the distributions pinned by the isolated Semgrep lock and no audited lock.

    Parameters
    ----------
    root:
        Repository containing the isolated Semgrep lock and every audited Python lock.

    Returns
    -------
    set[str]
        Canonical names that only the isolated Semgrep environment may install.
    """
    isolated = locked_names((root / SEMGREP_LOCK).read_text(encoding="utf-8"))
    audited: set[str] = set()
    for path in PYTHON_LOCKS:
        audited |= locked_names((root / path).read_text(encoding="utf-8"))
    return isolated - audited


def isolation_errors(
    root: Path = ROOT,
    *,
    prefix: str | None = None,
    base_prefix: str | None = None,
    installed: Iterable[str] | None = None,
    find_spec: Callable[[str], object | None] = importlib.util.find_spec,
) -> list[str]:
    """Check that the running interpreter is a base install without Semgrep.

    Parameters
    ----------
    root:
        Repository containing the isolated Semgrep lock and every audited Python lock.
    prefix:
        Interpreter prefix; the running ``sys.prefix`` when omitted.
    base_prefix:
        Base installation prefix; the running ``sys.base_prefix`` when omitted.
    installed:
        Installed distribution names; the running interpreter's metadata when omitted.
    find_spec:
        Module lookup used to decide whether ``semgrep`` can be imported.

    Returns
    -------
    list[str]
        Findings for a virtual environment, an importable Semgrep package, or an
        installed distribution that only the isolated Semgrep lock pins.
    """
    actual_prefix = sys.prefix if prefix is None else prefix
    actual_base = sys.base_prefix if base_prefix is None else base_prefix
    names = (
        {canonical_name(item.metadata["Name"]) for item in importlib.metadata.distributions()}
        if installed is None
        else {canonical_name(name) for name in installed}
    )
    errors: list[str] = []
    if actual_prefix != actual_base:
        errors.append("the audited interpreter must be a base installation, not a virtual one")
    if find_spec("semgrep") is not None:
        errors.append("the audited interpreter can import Semgrep")
    present = sorted(semgrep_only_names(root) & names)
    if present:
        errors.append(
            "the audited interpreter contains Semgrep-only distributions: " + ", ".join(present)
        )
    return errors


def main() -> int:
    """Validate the running interpreter and return a process exit code."""
    return redacted_guard_exit_code("Semgrep isolation guard", isolation_errors)


if __name__ == "__main__":
    raise SystemExit(main())
