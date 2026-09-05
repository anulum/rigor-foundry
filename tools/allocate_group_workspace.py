# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit group workspace operator
"""Allocate one new group workspace without granting work or cleanup authority."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from rigor_foundry.group_workspace import allocate_group_workspace


def main(argv: Sequence[str] | None = None) -> int:
    """Run an explicit allocation and redact failures, including partial creation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("monorepo", type=Path)
    parser.add_argument("registry")
    parser.add_argument("--project", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--registry-sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        path = allocate_group_workspace(
            arguments.monorepo,
            arguments.registry,
            project_id=arguments.project,
            session_id=arguments.session,
            expected_registry_sha256=arguments.registry_sha256,
        )
    except (ValueError, RuntimeError, OSError):
        print("group-workspace: FAIL; preserve any partial allocation for inspection")
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
