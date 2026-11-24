# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the import-sarif command of the public CLI
"""Wire the declared third-party SARIF import into the public CLI."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from functools import partial
from pathlib import Path

from .git_inventory import load_git_inventory
from .git_provenance import GitTrustPolicy
from .safe_output import write_new_output
from .sarif_import import import_sarif
from .sarif_import_document import MAX_SARIF_BYTES
from .sarif_import_producers import PRODUCERS


def _bounded_read(path: Path) -> bytes:
    """Read at most one byte past the whole-file limit, so a larger file is refused unread."""
    with path.open("rb") as handle:
        return handle.read(MAX_SARIF_BYTES + 1)


def _run(
    args: argparse.Namespace, *, git_policy: Callable[[argparse.Namespace], GitTrustPolicy]
) -> int:
    """Write one import report and print its digest and counts."""
    payload = _bounded_read(args.sarif)
    inventory = load_git_inventory(args.root, git_trust_policy=git_policy(args))
    report = import_sarif(
        payload,
        args.producer,
        inventory,
        head=args.head,
        checkout_root=args.checkout_root,
    )
    write_new_output(args.output, report.to_json())
    summary = {
        "counts": report.counts,
        "provenance": report.provenance,
        "report_digest": report.report_digest,
    }
    print(json.dumps(summary, sort_keys=True))
    unanchored = any(item.reason == "unanchored" for item in report.observations)
    return int(bool(args.require_all_anchored and (report.skipped or unanchored)))


def add_import_sarif_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    add_git_arguments: Callable[[argparse.ArgumentParser], None],
    git_policy: Callable[[argparse.Namespace], GitTrustPolicy],
) -> None:
    """Register the import command with the shared Git trust controls.

    Parameters
    ----------
    subparsers : argparse._SubParsersAction[argparse.ArgumentParser]
        The root parser's command registry.
    add_git_arguments : Callable[[argparse.ArgumentParser], None]
        Adds the shared Git trust options.
    git_policy : Callable[[argparse.Namespace], GitTrustPolicy]
        Builds the Git trust policy from parsed options.
    """
    command = subparsers.add_parser(
        "import-sarif",
        help="Import a declared producer's SARIF as unreviewed anchored candidates.",
    )
    command.add_argument("--sarif", type=Path, required=True, help="The producer's SARIF file.")
    command.add_argument(
        "--producer", required=True, choices=sorted(PRODUCERS), help="The declared producer."
    )
    command.add_argument(
        "--root", type=Path, required=True, help="The Git checkout the file describes."
    )
    command.add_argument(
        "--head", help="The checkout's HEAD, required when the file states no revision."
    )
    command.add_argument(
        "--checkout-root",
        help="The absolute path at which the producer saw the checkout, if it differs.",
    )
    command.add_argument(
        "--require-all-anchored",
        action="store_true",
        help="Exit 1 after writing the report if a result was skipped or a finding is unanchored.",
    )
    command.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New import report path; the parent must already exist.",
    )
    add_git_arguments(command)
    command.epilog = (
        "The import report is separate from the audit report. Candidates stay unreviewed, "
        "provenance is declared, and the rule registry never changes."
    )
    command.set_defaults(handler=partial(_run, git_policy=git_policy))
