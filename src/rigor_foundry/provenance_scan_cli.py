# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Offline provenance scan command
"""Register a read-only scan command with a separately versioned evidence output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .git_inventory import load_git_inventory
from .provenance_scan import build_provenance_scan
from .safe_output import write_new_output
from .scanner import scan_repository


def add_provenance_scan_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Add opt-in offline provenance scanning with an independently pinned profile."""
    parser = subparsers.add_parser(
        "scan-provenance", help="Scan with retained distribution provenance."
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.set_defaults(handler=_scan_provenance)


def _scan_provenance(args: argparse.Namespace) -> int:
    """Emit one exact audit report and provenance companion through safe output."""
    report = scan_repository(args.root, args.policy)
    inventory = load_git_inventory(args.root)
    result = build_provenance_scan(report, inventory, args.profile, args.profile_sha256)
    write_new_output(
        args.output, json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    return 0
