# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — SARIF golden fixture writer and staleness check
"""Render the SARIF golden fixtures from their committed real reports, or refuse stale copies."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from rigor_foundry.models import AuditReport, reviews_from_path
from rigor_foundry.sarif import report_sarif
from rigor_foundry.sarif_github_profile import GITHUB_CODE_SCANNING_PROFILE
from tools._repository import ROOT

FIXTURE_DIRECTORY = "tests/fixtures/sarif"
FIXTURE_INPUTS = ("report-states.json", "reviews-states.json", "report-empty.json")


@dataclass(frozen=True)
class SarifGolden:
    """One byte-equal SARIF golden fixture and the committed inputs it is rendered from."""

    name: str
    report: str
    reviews: str | None
    profile: str | None
    purpose: str


GOLDENS = (
    SarifGolden(
        "canonical-states.sarif",
        "report-states.json",
        "reviews-states.json",
        None,
        "Every review state (unreviewed, needs-evidence, valid P0-P4, invalid, accepted-boundary), "
        "tracked-blob and repository-tree anchors, and a percent-encoded non-ASCII path.",
    ),
    SarifGolden(
        "canonical-unreviewed.sarif",
        "report-states.json",
        None,
        None,
        "The same real report exported with no review ledger: every result is an unreviewed note.",
    ),
    SarifGolden(
        "github-states.sarif",
        "report-states.json",
        "reviews-states.json",
        GITHUB_CODE_SCANNING_PROFILE,
        "The GitHub code-scanning profile: only the valid results, the declared count of every "
        "omitted state, and the canonical document digest.",
    ),
    SarifGolden(
        "canonical-empty.sarif",
        "report-empty.json",
        None,
        None,
        "A zero-result report keeps its run, rules, taxonomy and provenance properties.",
    ),
    SarifGolden(
        "github-empty.sarif",
        "report-empty.json",
        None,
        GITHUB_CODE_SCANNING_PROFILE,
        "The GitHub profile of a zero-result report: no results and every omitted count zero.",
    ),
)


def render_sarif_goldens(root: Path = ROOT) -> dict[str, str]:
    """Render every golden fixture from its committed inputs.

    Parameters
    ----------
    root : Path
        Repository root holding the committed fixture inputs.

    Returns
    -------
    dict[str, str]
        The exact text of each golden fixture, keyed by its file name.
    """
    directory = root / FIXTURE_DIRECTORY
    rendered: dict[str, str] = {}
    for golden in GOLDENS:
        report = AuditReport.from_path(directory / golden.report)
        reviews = () if golden.reviews is None else reviews_from_path(directory / golden.reviews)
        rendered[golden.name] = report_sarif(report, reviews, profile=golden.profile)
    return rendered


def main(argv: Sequence[str] | None = None) -> int:
    """Write the golden fixtures, or compare them with the tracked copies.

    Parameters
    ----------
    argv : Sequence[str] or None
        Command-line arguments; ``None`` reads the process arguments.

    Returns
    -------
    int
        ``0`` when the fixtures were written or are current, ``1`` when ``--check`` finds a
        stale or missing fixture.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="refuse stale fixtures, write nothing"
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root holding them")
    arguments = parser.parse_args(argv)
    directory = arguments.root / FIXTURE_DIRECTORY
    rendered = render_sarif_goldens(arguments.root)
    if arguments.check:
        stale = sorted(
            name
            for name, text in rendered.items()
            if not (directory / name).is_file()
            or (directory / name).read_text(encoding="utf-8") != text
        )
        if stale:
            print(
                "stale SARIF fixtures: "
                + ", ".join(stale)
                + "; run python -m tools.render_sarif_fixtures",
                file=sys.stderr,
            )
            return 1
        print("SARIF fixtures are current")
        return 0
    for name, text in rendered.items():
        (directory / name).write_text(text, encoding="utf-8", newline="")
    print(f"Wrote {len(rendered)} SARIF fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
