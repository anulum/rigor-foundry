# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry integrity checker
"""Validate the canonical project registry and every declared consumer."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from rigor_foundry.project_registry_cutover import load_project_registry_state


def build_parser() -> argparse.ArgumentParser:
    """Build the fixed-argument registry integrity parser."""
    parser = argparse.ArgumentParser(
        description="Validate one canonical registry and its consumers with redacted output."
    )
    parser.add_argument("monorepo", type=Path, help="exact monorepo root")
    parser.add_argument("registry", help="monorepo-relative canonical registry path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one fail-closed registry integrity check with fixed output."""
    arguments = build_parser().parse_args(argv)
    try:
        load_project_registry_state(arguments.monorepo, arguments.registry)
    except (OSError, RuntimeError, ValueError):
        print("project-registry-integrity: FAIL")
        return 1
    print("project-registry-integrity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
