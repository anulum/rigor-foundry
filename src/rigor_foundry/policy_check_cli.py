# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Read-only policy-check command
"""Register bounded draft-policy diagnostics for an explicit repository root."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .policy_diagnostic_rows import repository_path
from .policy_diagnostics import diagnose_repository_policy
from .policy_read_budget import PolicyReadBudget1
from .policy_source_reads import parse_policy_document_payload
from .source_capture import read_source_payload

_DOCUMENT_BUDGET = PolicyReadBudget1.build(
    max_document_bytes=1024 * 1024,
    max_source_bytes=1024 * 1024,
    max_total_source_bytes=1024 * 1024,
    max_sources=1,
    max_rules=4096,
    max_references=4096,
    max_depth=32,
)


def add_policy_check_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Expose the provisional read-only policy-check command."""
    parser = subparsers.add_parser(
        "policy-check", help="Diagnose repository policy fields and scoped declarations."
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--policy", default="rigor-foundry-policy.json")
    parser.set_defaults(handler=_policy_check)


def _policy_check(args: argparse.Namespace) -> int:
    """Read only a single stable scoped file and emit value-redacted diagnostics."""
    if not repository_path(args.policy):
        print(
            "policy check: use a normalised policy path relative to the declared root",
            file=sys.stderr,
        )
        return 2
    try:
        root = args.root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("policy root must be a directory")
        content = read_source_payload(
            root / args.policy,
            maximum_bytes=_DOCUMENT_BUDGET.max_document_bytes,
        )
    except (OSError, RuntimeError, ValueError):
        print(
            "policy check: cannot read a bounded regular policy under the declared root",
            file=sys.stderr,
        )
        return 2
    try:
        value = parse_policy_document_payload(content, budget=_DOCUMENT_BUDGET)
    except json.JSONDecodeError as exc:
        print(
            f'"" Invalid JSON at line {exc.lineno}, column {exc.colno}. Correct the document syntax.'
        )
        return 1
    except (RecursionError, ValueError):
        print('"" Invalid policy document. Use bounded strict UTF-8 JSON with unique members.')
        return 1
    diagnostics = diagnose_repository_policy(value)
    if not diagnostics:
        print("policy check: PASS")
        return 0
    for diagnostic in diagnostics:
        print(f"{json.dumps(diagnostic.pointer)} {diagnostic.problem}. {diagnostic.fix}.")
    return 1
