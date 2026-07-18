# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Atheris fuzz target for ReviewRecord.from_dict
"""Fuzz ReviewRecord.from_dict for fail-closed parsing of hostile ledger JSON."""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from _record_fuzz import fuzz_mapping_parser

    from rigor_foundry import ReviewRecord


def _consume(data: bytes) -> None:
    fuzz_mapping_parser(data, ReviewRecord.from_dict)


def main() -> None:
    """Configure Atheris and run the coverage-guided fuzzing loop."""
    atheris.Setup(sys.argv, _consume)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
