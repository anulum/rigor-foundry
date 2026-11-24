# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — checkout guard for the hosted SARIF upload
"""Refuse a SARIF upload whose checkout is not the commit that the audit report describes.

GitHub code scanning fills result fingerprints from the files of the checkout it uploads
from. So the hosted upload is admitted only when that checkout's HEAD and HEAD tree are
exactly the report's ``head`` and ``head_tree``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from rigor_foundry.models import AuditReport
from tools._repository import ROOT, run


def _resolve(root: Path, revision: str) -> str:
    """Return the full object id of ``revision`` in the checkout, or refuse an unresolved one."""
    completed = run("git", "rev-parse", "--verify", revision, cwd=root)
    if completed.returncode != 0:
        raise ValueError(f"cannot resolve {revision} in the checkout")
    return completed.stdout.strip()


def checkout_errors(report_path: Path, root: Path = ROOT) -> list[str]:
    """Compare the checkout at ``root`` with the commit that the report describes.

    Parameters
    ----------
    report_path : Path
        An audit report, verified through ``AuditReport.from_path``.
    root : Path
        The checkout that the SARIF upload would run in.

    Returns
    -------
    list[str]
        One finding per mismatch; empty when HEAD and its tree equal the report's.

    Raises
    ------
    ValueError
        If the report fails verification or the checkout cannot be resolved.
    """
    report = AuditReport.from_path(report_path)
    head = _resolve(root, "HEAD")
    tree = _resolve(root, "HEAD^{tree}")
    errors = []
    if head != report.head:
        errors.append(f"checkout HEAD {head} is not the report head {report.head}")
    if tree != report.head_tree:
        errors.append(f"checkout tree {tree} is not the report head tree {report.head_tree}")
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    """Check one report against the checkout and print every mismatch.

    Parameters
    ----------
    argv : Sequence[str] or None
        Command-line arguments; ``None`` reads the process arguments.

    Returns
    -------
    int
        ``0`` when the checkout is the report's commit, ``1`` when it is not, and ``2`` when
        the report or the checkout cannot be verified.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="audit report JSON written by rigor scan")
    parser.add_argument("--root", type=Path, default=ROOT, help="checkout of the upload")
    arguments = parser.parse_args(argv)
    try:
        errors = checkout_errors(arguments.report, arguments.root)
    except (OSError, ValueError) as error:
        print(f"cannot verify the SARIF upload checkout: {error}", file=sys.stderr)
        return 2
    for finding in errors:
        print(finding, file=sys.stderr)
    if errors:
        return 1
    print("SARIF upload checkout is the report's commit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
