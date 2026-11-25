# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the import-sarif and verify-import commands of the public CLI
"""Wire the declared and executed third-party SARIF imports, and their verifier, into the CLI."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from functools import partial
from pathlib import Path

from .git_inventory import GitInventory, load_git_inventory
from .git_provenance import GitTrustPolicy
from .safe_output import write_new_output
from .sarif_import import import_executed_sarif, import_sarif
from .sarif_import_binding import verify_executed_binding, verify_executed_import
from .sarif_import_document import MAX_SARIF_BYTES
from .sarif_import_execution import run_import_profile
from .sarif_import_producers import PRODUCERS
from .sarif_import_profile import IMPORT_PROFILES, import_profile_by_name
from .sarif_import_report import ImportReport, read_import_report


def _bounded_read(path: Path) -> bytes:
    """Read at most one byte past the whole-file limit, so a larger file is refused unread."""
    with path.open("rb") as handle:
        return handle.read(MAX_SARIF_BYTES + 1)


def _summarise(report: ImportReport, args: argparse.Namespace) -> int:
    """Print the report's digest and counts and return the strict-mode exit status."""
    summary = {
        "counts": report.counts,
        "provenance": report.provenance,
        "report_digest": report.report_digest,
    }
    print(json.dumps(summary, sort_keys=True))
    unanchored = any(item.reason == "unanchored" for item in report.observations)
    return int(bool(args.require_all_anchored and (report.skipped or unanchored)))


def _require_tracked_configuration(inventory: GitInventory, configuration: str) -> None:
    """Refuse a configuration that is not one clean tracked regular file of the checkout."""
    item = next((entry for entry in inventory.files if entry.path == configuration), None)
    if (
        item is None
        or configuration in inventory.dirty_paths
        or item.content_kind not in {"text", "binary", "non-utf8"}
    ):
        raise ValueError("--configuration must be a clean tracked regular file of the checkout")


def _execute(args: argparse.Namespace, inventory: GitInventory) -> int:
    """Run one import-only profile, then write its executed report and binding."""
    if args.sarif is not None or args.producer is not None or args.checkout_root is not None:
        raise ValueError(
            "--execute runs its own producer; omit --sarif, --producer and --checkout-root"
        )
    if args.configuration is None or not args.target or args.binding_output is None:
        raise ValueError(
            "--execute needs --configuration, at least one --target and --binding-output"
        )
    if args.head != inventory.head:
        raise ValueError("--execute needs --head equal to the checkout's HEAD")
    _require_tracked_configuration(inventory, args.configuration)
    if args.output.resolve() == args.binding_output.resolve():
        raise ValueError("--output and --binding-output must be two different paths")
    for path in (args.output, args.binding_output):
        if path.exists() or path.is_symlink():
            raise ValueError(f"the output path already exists: {path}")
    profile = import_profile_by_name(args.execute)
    run = run_import_profile(
        args.root,
        profile,
        configuration_path=args.configuration,
        target_paths=tuple(args.target),
        timeout_seconds=args.timeout_seconds,
        expected_tracked_content_digest=inventory.tracked_content_digest,
        git_trust_policy=args.git_trust_policy,
    )
    report, binding = import_executed_sarif(run, inventory=inventory, head=args.head)
    write_new_output(args.binding_output, binding.to_json())
    write_new_output(args.output, report.to_json())
    return _summarise(report, args)


def _run(
    args: argparse.Namespace, *, git_policy: Callable[[argparse.Namespace], GitTrustPolicy]
) -> int:
    """Write one declared or executed import report and print its digest and counts."""
    args.git_trust_policy = git_policy(args)
    inventory = load_git_inventory(args.root, git_trust_policy=args.git_trust_policy)
    if args.execute is not None:
        return _execute(args, inventory)
    if args.sarif is None or args.producer is None:
        raise ValueError("a declared import needs --sarif and --producer, or use --execute")
    if args.configuration is not None or args.target or args.binding_output is not None:
        raise ValueError("--configuration, --target and --binding-output need --execute")
    report = import_sarif(
        _bounded_read(args.sarif),
        args.producer,
        inventory,
        head=args.head,
        checkout_root=args.checkout_root,
    )
    write_new_output(args.output, report.to_json())
    return _summarise(report, args)


def _verify(args: argparse.Namespace) -> int:
    """Verify one executed import report against its binding and print what was checked."""
    report = read_import_report(args.report)
    try:
        decoded = json.loads(args.binding.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("the binding is not JSON") from error
    binding = verify_executed_binding(decoded)
    verify_executed_import(report, binding)
    summary = {
        "binding_digest": binding["binding_digest"],
        "report_digest": report["report_digest"],
        "verified": True,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


def add_import_sarif_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    add_git_arguments: Callable[[argparse.ArgumentParser], None],
    git_policy: Callable[[argparse.Namespace], GitTrustPolicy],
) -> None:
    """Register the import and verify commands with the shared Git trust controls.

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
        help="Import a producer's SARIF as unreviewed anchored candidates.",
    )
    command.add_argument("--sarif", type=Path, help="A declared producer's SARIF file.")
    command.add_argument("--producer", choices=sorted(PRODUCERS), help="The declared producer.")
    command.add_argument(
        "--execute",
        choices=sorted(IMPORT_PROFILES),
        help="Run this import-only profile and import its SARIF as executed.",
    )
    command.add_argument(
        "--configuration", help="With --execute: the tracked configuration file to run."
    )
    command.add_argument(
        "--target", action="append", default=[], help="With --execute: one tracked target."
    )
    command.add_argument(
        "--timeout-seconds", type=int, default=300, help="With --execute: the run's timeout."
    )
    command.add_argument(
        "--binding-output", type=Path, help="With --execute: the new binding record path."
    )
    command.add_argument(
        "--root", type=Path, required=True, help="The Git checkout the file describes."
    )
    command.add_argument(
        "--head",
        help="The checkout's HEAD; required with --execute or when no revision is stated.",
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
        "The import report is separate from the audit report. Candidates stay unreviewed, and "
        "the rule registry never changes. With --execute, the report and its binding are "
        "written only after the binding succeeds."
    )
    command.set_defaults(handler=partial(_run, git_policy=git_policy))
    verify = subparsers.add_parser(
        "verify-import", help="Verify an executed import report against its binding record."
    )
    verify.add_argument("--report", type=Path, required=True, help="The executed import report.")
    verify.add_argument("--binding", type=Path, required=True, help="Its binding record.")
    verify.set_defaults(handler=_verify)
