# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory integrity checker
"""Validate a private current view or its complete retained history."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from rigor_foundry.project_memory_store import (
    load_project_memory_generation,
    verify_project_memory_history,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the fixed-argument project-memory integrity parser."""
    parser = argparse.ArgumentParser(
        description="Validate one private project-memory store with redacted output."
    )
    parser.add_argument("repository", type=Path, help="exact Git worktree root")
    parser.add_argument(
        "--history",
        action="store_true",
        help="verify every retained manifest and the complete predecessor chain",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one fail-closed integrity check with fixed redacted output."""
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.history:
            verify_project_memory_history(arguments.repository)
        else:
            load_project_memory_generation(arguments.repository)
    except (OSError, RuntimeError, ValueError):
        print("project-memory-integrity: FAIL")
        return 1
    print("project-memory-integrity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
