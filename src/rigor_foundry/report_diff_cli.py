# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — report-diff CLI adapter
"""Wire exact report comparison into the public CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit_primitives import require_mapping
from .report_diff import (
    REPORT_DIFF_SCHEMA_VERSION,
    CandidateAnchorMatch,
    ReportDiffCompatibility,
    compare_reports,
    read_report_for_diff,
)
from .safe_output import write_new_output


def _anchor_matches(path: Path | None) -> tuple[CandidateAnchorMatch, ...]:
    """Read optional strict operator-declared anchor mappings."""
    if path is None:
        return ()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read anchor matches {path}") from exc
    data = require_mapping(value, "anchor matches document")
    if frozenset(data) != {"schema_version", "matches"}:
        raise ValueError("anchor matches document fields do not match the schema")
    if data.get("schema_version") != REPORT_DIFF_SCHEMA_VERSION:
        raise ValueError("unsupported anchor matches schema version")
    raw_matches = data.get("matches")
    if not isinstance(raw_matches, list):
        raise ValueError("anchor matches must be an array")
    return tuple(CandidateAnchorMatch.from_dict(item) for item in raw_matches)


def _report_diff_command(args: argparse.Namespace) -> int:
    """Compare two exact reports and emit one replay-verifiable record."""
    before = read_report_for_diff(args.before)
    after = read_report_for_diff(args.after)
    compatibility = ReportDiffCompatibility(
        repository_change=args.declare_repository_change,
        branch_change=args.declare_branch_change,
        policy_change=args.declare_policy_change,
        rule_pack_change=args.declare_rule_pack_change,
        scanner_change=args.declare_scanner_change,
        justification=args.justification,
    )
    diff = compare_reports(
        before,
        after,
        compatibility=compatibility,
        anchor_matches=_anchor_matches(args.anchor_matches),
    )
    output = diff.to_json()
    if args.output is None:
        print(output, end="")
    else:
        write_new_output(args.output, output)
    return 0


def add_report_diff_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Add the evidence-only report-diff command to the root parser."""
    parser = subparsers.add_parser(
        "report-diff",
        help="Compare two exact audit reports without inferring correctness or chronology.",
    )
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--anchor-matches", type=Path)
    parser.add_argument("--declare-repository-change", action="store_true")
    parser.add_argument("--declare-branch-change", action="store_true")
    parser.add_argument("--declare-policy-change", action="store_true")
    parser.add_argument("--declare-rule-pack-change", action="store_true")
    parser.add_argument("--declare-scanner-change", action="store_true")
    parser.add_argument(
        "--justification",
        default="",
        help="Required when any compatibility change is declared.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional exclusive output path; parent must already exist.",
    )
    parser.set_defaults(handler=_report_diff_command)
