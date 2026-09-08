# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — discovery source validation
"""Run explicit, read-only discovery verification with content-free failures."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NoReturn

from .discovery_source_schema import DiscoveryLimits, DiscoveryReadError
from .discovery_source_validation import validate_discovery_sources


class _Parser(argparse.ArgumentParser):
    """Keep argument failures from echoing arbitrary input into diagnostics."""

    def error(self, message: str) -> NoReturn:
        """Replace untrusted argparse detail with a fixed refusal."""
        raise argparse.ArgumentError(None, "invalid-arguments")


def main(argv: list[str] | None = None) -> int:
    """Print one integrity receipt or a bounded error, never both.

    Require the capture root, manifest and all six resource limits. Exit zero
    means declared snapshot integrity only, two means invalid input, and one
    means inaccessible input or unsupported platform. There are no writes.
    """
    parser = _Parser(description=__doc__, exit_on_error=False)
    parser.add_argument("--root", required=True)
    parser.add_argument("--manifest", required=True)
    for name in ("total-bytes", "file-bytes", "sources", "shards", "candidates", "spans"):
        parser.add_argument("--max-" + name, required=True)
    try:
        args = parser.parse_args(argv)
        limits = DiscoveryLimits(
            **{
                name: int(getattr(args, "max_" + name))
                for name in (
                    "total_bytes",
                    "file_bytes",
                    "sources",
                    "shards",
                    "candidates",
                    "spans",
                )
            }
        )
        receipt = validate_discovery_sources(Path(args.root), args.manifest, limits=limits)
    except DiscoveryReadError:
        print("discovery-error:capture-read-failed", file=sys.stderr)
        return 1
    except (ValueError, argparse.ArgumentError):
        print("discovery-error:invalid-input", file=sys.stderr)
        return 2
    print(
        json.dumps(
            receipt, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
