# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — interrupted project registry recovery operator
"""Recover one exact named project registry transaction with fixed output."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from rigor_foundry.project_registry_recovery import recover_project_registry_cutover


def build_parser() -> argparse.ArgumentParser:
    """Build the explicit recovery parser."""
    parser = argparse.ArgumentParser(
        description="Recover one exact interrupted project registry transaction."
    )
    parser.add_argument("monorepo", type=Path, help="exact monorepo root")
    parser.add_argument("registry", help="monorepo-relative canonical registry path")
    parser.add_argument("transaction_root", type=Path, help="owner-only transaction directory")
    parser.add_argument("generation_id", help="exact interrupted generation identifier")
    parser.add_argument("registry_sha256", help="exact interrupted registry digest")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="perform recovery; omission refuses mutation",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Apply explicitly requested recovery without disclosing transaction content."""
    arguments = build_parser().parse_args(argv)
    if not arguments.apply:
        print("project-registry-recovery: APPLY_REQUIRED")
        return 2
    try:
        receipt = recover_project_registry_cutover(
            arguments.monorepo,
            arguments.registry,
            arguments.transaction_root,
            arguments.generation_id,
            arguments.registry_sha256,
        )
    except (OSError, RuntimeError, ValueError):
        print("project-registry-recovery: FAIL")
        return 1
    outcome = "COMMITTED" if receipt.outcome == "committed" else "ROLLED_BACK"
    print(f"project-registry-recovery: {outcome}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
