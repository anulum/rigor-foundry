# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — OSCAL export CLI adapter
"""Wire deterministic OSCAL assessment-results export into the public CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

from .compliance_maps import NON_CERTIFICATION_NOTICE, builtin_template, builtin_template_ids
from .control_assessment import ControlAssessment
from .effective_profile import EffectiveProfileLock
from .oscal_export import report_oscal
from .safe_output import write_new_output


def _document(path: Path) -> object:
    """Read one explicit UTF-8 JSON protocol document."""
    return json.loads(path.read_text(encoding="utf-8"))


def _assessments(path: Path, lock: EffectiveProfileLock) -> tuple[ControlAssessment, ...]:
    """Parse one JSON array of assessments bound to the supplied lock."""
    raw = _document(path)
    if not isinstance(raw, list):
        raise ValueError("assessments document must be a JSON array")
    items = cast(list[object], raw)
    return tuple(ControlAssessment.from_dict(item, lock) for item in items)


def _oscal_command(args: argparse.Namespace) -> int:
    """Export sealed lock + assessments as deterministic OSCAL JSON."""
    lock = EffectiveProfileLock.from_dict(_document(args.lock))
    assessments = _assessments(args.assessments, lock)
    template = builtin_template(str(args.template))
    output = report_oscal(lock, assessments, template, str(args.generated_at))
    if args.output is None:
        print(output, end="")
    else:
        write_new_output(args.output, output)
    return 0


def add_oscal_commands(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Add the OSCAL export command to the root parser."""
    known = ", ".join(builtin_template_ids())
    oscal = subparsers.add_parser(
        "oscal",
        help=(
            "Export sealed lock assessments as candidate OSCAL 1.1.3 JSON "
            "(triage only; not a certification)."
        ),
    )
    oscal.add_argument(
        "--lock",
        type=Path,
        required=True,
        help="Serialised EffectiveProfileLock JSON (to_dict output).",
    )
    oscal.add_argument(
        "--assessments",
        type=Path,
        required=True,
        help="JSON array of ControlAssessment records bound to the lock.",
    )
    oscal.add_argument(
        "--template",
        required=True,
        help=f"Built-in evidence-map template id ({known}).",
    )
    oscal.add_argument(
        "--generated-at",
        required=True,
        help="Explicit UTC timestamp (no wall clock is used).",
    )
    oscal.add_argument(
        "--output",
        type=Path,
        help="Optional exclusive output path; parent must already exist.",
    )
    oscal.epilog = (
        f"Boundary: {NON_CERTIFICATION_NOTICE} "
        "Findings and risks are omitted; import-ap is the documented boundary."
    )
    oscal.set_defaults(handler=_oscal_command)
