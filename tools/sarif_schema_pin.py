# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the single tracked pin of the OASIS SARIF 2.1.0 schema
"""Print the pinned OASIS SARIF 2.1.0 Errata 01 schema URL or SHA-256 for CI fetch steps."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from typing import Final

SARIF_SCHEMA_URL: Final = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
SARIF_SCHEMA_SHA256: Final = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
SARIF_SCHEMA_ENV: Final = "RIGOR_SARIF_SCHEMA_PATH"
LOCAL_FETCH_COMMAND: Final = (
    'curl --proto "=https" --tlsv1.2 --fail --location --output sarif-schema-2.1.0.json '
    '"$(python -m tools.sarif_schema_pin url)" && printf "%s  %s\\n" '
    '"$(python -m tools.sarif_schema_pin sha256)" sarif-schema-2.1.0.json | sha256sum --check --strict'
)


def main(argv: Sequence[str] | None = None) -> int:
    """Print one field of the schema pin.

    Parameters
    ----------
    argv : Sequence[str] or None
        ``url`` or ``sha256``; ``None`` reads the process arguments.

    Returns
    -------
    int
        Always ``0``; an unknown field is refused by the argument parser.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("field", choices=("url", "sha256"))
    arguments = parser.parse_args(argv)
    print(SARIF_SCHEMA_URL if arguments.field == "url" else SARIF_SCHEMA_SHA256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
