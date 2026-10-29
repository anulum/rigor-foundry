# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Complete collection timing schedules
"""Use advisory module durations to balance a complete current collection."""

from __future__ import annotations

import json
import re
import statistics
from pathlib import Path
from typing import Any

TIMINGS_PATH = Path(".github/test-timings.json")
MAX_TIMINGS_BYTES = 1_048_576
WARM_STRATEGY = "module-lpt-v1"
COLD_STRATEGY = "item-round-robin-v1"


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate timing fields before interpreting their values."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate test timing field")
        result[key] = value
    return result


def validate_timings(value: object) -> dict[str, float]:
    """Validate bounded advisory durations without admitting test membership.

    Parameters
    ----------
    value : object
        Module-path to positive finite seconds mapping.

    Returns
    -------
    dict[str, float]
        Validated normalized duration hints.
    """
    if not isinstance(value, dict) or not value or len(value) > 10_000:
        raise ValueError("invalid test timings")
    result: dict[str, float] = {}
    for name, seconds in value.items():
        if (
            not isinstance(name, str)
            or len(name) > 512
            or re.fullmatch(r"tests/(?:[A-Za-z0-9_]+/)*test_[A-Za-z0-9_]+\.py", name) is None
            or type(seconds) not in (int, float)
            or not 0 < seconds <= 86_400
        ):
            raise ValueError("invalid test timing")
        result[name] = float(seconds)
    return result


def read_timings(root: Path, strategy: str = WARM_STRATEGY) -> dict[str, float]:
    """Read the required snapshot or an explicitly declared no-profile cohort.

    Parameters
    ----------
    root : Path
        Actual collection's repository.
    strategy : str
        Versioned module scheduling or explicit no-profile round-robin.

    Returns
    -------
    dict[str, float]
        Complete validated snapshot, or an empty cold-start profile.
    """
    path = root / TIMINGS_PATH
    if strategy == COLD_STRATEGY and not path.is_symlink() and not path.exists():
        return {}
    if (
        strategy != WARM_STRATEGY
        or path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > MAX_TIMINGS_BYTES
    ):
        raise ValueError("invalid test timing file")
    record = json.loads(path.read_bytes(), object_pairs_hook=_unique_fields)
    if (
        not isinstance(record, dict)
        or set(record) != {"schema_version", "durations"}
        or type(record["schema_version"]) is not int
        or record["schema_version"] != 1
    ):
        raise ValueError("invalid test timing schema")
    return validate_timings(record["durations"])


def partition(
    collected: list[str], count: int, timings: dict[str, float], strategy: str = WARM_STRATEGY
) -> list[list[str]]:
    """Assign every current item once, keeping warm modules and item order intact.

    Parameters
    ----------
    collected : list[str]
        Complete final ordered pytest node identities.
    count : int
        Positive partition count.
    timings : dict[str, float]
        Advisory module durations, shared by the entire run.
    strategy : str
        Exact versioned cohort algorithm.

    Returns
    -------
    list[list[str]]
        Deterministic disjoint partitions of only the current collection.
    """
    if type(count) is not int or count < 1:
        raise ValueError("invalid test partition count")
    if strategy == COLD_STRATEGY and timings == {}:
        return [collected[index::count] for index in range(count)]
    if strategy != WARM_STRATEGY:
        raise ValueError("invalid test scheduling strategy")
    durations = validate_timings(timings)
    units = {name: max(1, round(seconds * 1_000_000)) for name, seconds in durations.items()}
    modules = {node.split("::", 1)[0] for node in collected}
    default = statistics.median_low(units.values()) + statistics.median_high(units.values())
    costs = {name: seconds * 2 for name, seconds in units.items()}
    loads = [0] * count
    owners: dict[str, int] = {}
    for module in sorted(modules, key=lambda name: (-costs.get(name, default), name)):
        index = min(range(count), key=lambda candidate: (loads[candidate], candidate))
        owners[module] = index
        loads[index] += costs.get(module, default)
    parts: list[list[str]] = [[] for _ in range(count)]
    for node in collected:
        parts[owners[node.split("::", 1)[0]]].append(node)
    return parts
