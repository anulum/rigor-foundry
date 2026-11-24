# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — generated rule catalogue writer and staleness check
"""Write the generated rule catalogue page, or refuse a stale tracked copy with ``--check``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from rigor_foundry.rule_catalogue import RULE_CATALOGUE_PATH, render_rule_catalogue
from tools._repository import ROOT


def main(argv: Sequence[str] | None = None) -> int:
    """Render the rule catalogue and write it, or compare it with the tracked page.

    Parameters
    ----------
    argv : Sequence[str] or None
        Command-line arguments; ``None`` reads the process arguments.

    Returns
    -------
    int
        ``0`` when the page was written or is current, ``1`` when ``--check`` finds it stale.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="refuse a stale page, write nothing")
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root holding the page")
    arguments = parser.parse_args(argv)
    path = arguments.root / RULE_CATALOGUE_PATH
    expected = render_rule_catalogue()
    if arguments.check:
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current != expected:
            print(
                f"{RULE_CATALOGUE_PATH} is stale; run python -m tools.render_rule_catalogue",
                file=sys.stderr,
            )
            return 1
        print("Rule catalogue is current")
        return 0
    path.write_text(expected, encoding="utf-8", newline="")
    print(f"Wrote {RULE_CATALOGUE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
