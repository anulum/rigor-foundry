# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — condition-evaluation command
"""Evaluate supplied observations offline through the provisional module CLI."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, cast

from .audit_primitives import require_exact_fields
from .condition_evaluation import evaluate_condition_state
from .condition_facts import ConditionFact, ConditionTruth
from .condition_language import ConditionExpression
from .git_inventory import StableReadError
from .models import canonical_digest, require_mapping
from .source_capture import read_source_payload

CONDITION_OBSERVATIONS_SCHEMA_VERSION = "rigor.condition-observations.v1"
CONDITION_EVALUATION_SCHEMA_VERSION = "rigor.condition-evaluation.v1"
MAX_CONDITION_DOCUMENT_BYTES = 65_536


class _InputParser(argparse.ArgumentParser):
    """Keep argument failures independent of caller-supplied paths or values."""

    def error(self, message: str) -> NoReturn:
        """Refuse malformed arguments without echoing their contents."""
        del message
        raise ValueError("condition evaluation arguments are invalid")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject a duplicate key before a JSON object loses its original identity."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("condition evaluation JSON has duplicate keys")
        result[key] = value
    return result


def _nonfinite(value: str) -> NoReturn:
    """Reject the non-JSON numeric extensions accepted by the standard decoder."""
    del value
    raise ValueError("condition evaluation JSON has a non-finite number")


def _document(path: Path) -> object:
    """Read one bounded single-link regular UTF8 document without following aliases."""
    payload = read_source_payload(path, maximum_bytes=MAX_CONDITION_DOCUMENT_BYTES)
    return json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_unique_pairs,
        parse_constant=_nonfinite,
    )


def _observations(value: object) -> tuple[dict[str, ConditionFact], str]:
    """Parse the explicit inert operand document, not an authenticated FactContext."""
    data = require_mapping(value, "condition observations")
    require_exact_fields(data, frozenset({"schema_version", "facts"}), "condition observations")
    if data["schema_version"] != CONDITION_OBSERVATIONS_SCHEMA_VERSION:
        raise ValueError("condition observation schema is unsupported")
    raw = require_mapping(data["facts"], "condition observation facts")
    facts = {reference: ConditionFact.from_dict(item) for reference, item in raw.items()}
    return facts, canonical_digest(data)


def main(argv: Sequence[str] | None = None) -> int:
    """Evaluate explicit condition and observation files without granting effects.

    Parameters
    ----------
    argv : Sequence[str] or None
        Arguments excluding the module name. None uses the actual process argv.

    Returns
    -------
    int
        Zero for true, one for false, three for unknown, two for invalid input.
        Successful data evaluation does not authenticate the supplied facts.

    Raises
    ------
    SystemExit
        The caller requests the normal command-line help output.
    """
    parser = _InputParser(description=__doc__)
    parser.add_argument("--expression", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        expression = ConditionExpression.from_dict(_document(cast(Path, args.expression)))
        facts, facts_digest = _observations(_document(cast(Path, args.observations)))
        result = evaluate_condition_state(expression, facts)
        print(
            json.dumps(
                {
                    "schema_version": CONDITION_EVALUATION_SCHEMA_VERSION,
                    "evaluation_kind": "supplied-observations",
                    "expression_digest": expression.expression_digest,
                    "observations_digest": facts_digest,
                    "result": result.value,
                    "guard_admissible": False,
                },
                sort_keys=True,
                allow_nan=False,
            )
        )
        return {ConditionTruth.TRUE: 0, ConditionTruth.FALSE: 1, ConditionTruth.UNKNOWN: 3}[result]
    except (OSError, ValueError, RecursionError, OverflowError, StableReadError):
        print("condition evaluation error: CE001 invalid input", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
