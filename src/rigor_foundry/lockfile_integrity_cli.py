# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the lockfile integrity command
"""Register the provisional, read-only ``lockfile-integrity`` command.

It classifies every tracked lockfile and prints the report. Findings and refusals are
observations, not a gate: which of them fails a build is the consumer's policy, so the
command exits zero whenever it produced a report.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from functools import partial
from pathlib import Path

from .git_inventory import load_git_inventory
from .git_provenance import GitTrustPolicy
from .lockfile_report import lockfile_integrity_report


def _run(
    args: argparse.Namespace, *, git_policy: Callable[[argparse.Namespace], GitTrustPolicy]
) -> int:
    """Print the report of the repository's tracked lockfiles."""
    inventory = load_git_inventory(args.root, git_trust_policy=git_policy(args))
    report = lockfile_integrity_report(inventory)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(report.render_text(), end="")
    return 0


def add_lockfile_integrity_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    add_git_arguments: Callable[[argparse.ArgumentParser], None],
    git_policy: Callable[[argparse.Namespace], GitTrustPolicy],
) -> None:
    """Register the command with the shared Git controls.

    Parameters
    ----------
    subparsers : argparse._SubParsersAction[argparse.ArgumentParser]
        The top-level command set.
    add_git_arguments : Callable[[argparse.ArgumentParser], None]
        Adds the shared Git provenance options.
    git_policy : Callable[[argparse.Namespace], GitTrustPolicy]
        Builds the Git trust policy from those options.
    """
    command = subparsers.add_parser(
        "lockfile-integrity",
        help="Classify every tracked lockfile entry's integrity pin (provisional).",
    )
    command.add_argument("--root", type=Path, required=True)
    command.add_argument("--json", action="store_true", help="Print the full JSON report.")
    add_git_arguments(command)
    command.set_defaults(handler=partial(_run, git_policy=git_policy))
