# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — strict parsing and whole-file limits of an imported SARIF file
"""Parse one third-party SARIF 2.1.0 file strictly, refusing it whole at any file limit.

Every whole-file limit fails closed: a file that is too large, not strict JSON, nested too
deeply, or holding too many runs, results or rules is refused as a whole, never imported in
part. Per-result problems are a later stage's concern and are recorded there, not here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final, cast

MAX_SARIF_BYTES: Final = 32 * 1024 * 1024
MAX_NESTING: Final = 64
MAX_RUNS: Final = 8
MAX_RESULTS_PER_RUN: Final = 100_000
MAX_RULES_PER_RUN: Final = 20_000
SARIF_VERSION: Final = "2.1.0"


class SarifImportRefused(ValueError):
    """A SARIF file refused as a whole, with a stable reason code."""

    def __init__(self, reason: str, detail: str) -> None:
        """Record the reason code and a readable detail.

        Parameters
        ----------
        reason : str
            Stable machine-readable refusal code.
        detail : str
            Human-readable explanation, free of the file's content.
        """
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


@dataclass(frozen=True)
class SarifDocument:
    """A strictly parsed SARIF 2.1.0 document within every whole-file limit."""

    document: dict[str, Any]
    runs: tuple[dict[str, Any], ...]


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object, refusing a repeated key."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SarifImportRefused("duplicate-key", "a JSON object repeats a key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    """Refuse the non-finite JSON number spellings that Python would otherwise accept."""
    raise SarifImportRefused("non-finite-number", f"the JSON holds {value}")


def _nesting(value: object) -> int:
    """Return the deepest array or object nesting of a decoded JSON value, iteratively."""
    deepest = 0
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if isinstance(item, dict):
            children: list[object] = list(item.values())
        elif isinstance(item, list):
            children = item
        else:
            continue
        deepest = max(deepest, depth)
        if deepest > MAX_NESTING:
            return deepest
        pending.extend((child, depth + 1) for child in children)
    return deepest


def _items(record: dict[str, Any], key: str) -> list[Any]:
    """Return one optional array field, refusing the run when it is not an array."""
    items = record.get(key, [])
    if not isinstance(items, list):
        raise SarifImportRefused("malformed-run", f"{key} must be an array")
    return items


def _component_rules(component: dict[str, Any]) -> int:
    """Return one tool component's rule count after checking its identity and rule ids."""
    if not isinstance(component.get("name"), str):
        raise SarifImportRefused("malformed-run", "every tool component must have a name")
    if any(
        key in component and not isinstance(component[key], str)
        for key in ("semanticVersion", "version")
    ):
        raise SarifImportRefused("malformed-run", "a tool component version must be a string")
    rules = _items(component, "rules")
    ids = [
        rule["id"] for rule in rules if isinstance(rule, dict) and isinstance(rule.get("id"), str)
    ]
    if len(ids) != len(set(ids)):
        raise SarifImportRefused("malformed-run", "a tool component repeats a rule id")
    return len(rules)


def _component_identity(component: dict[str, Any]) -> tuple[str, str | None]:
    """Return the name and version that identify one checked tool component."""
    semantic = component.get("semanticVersion")
    return component["name"], semantic if semantic is not None else component.get("version")


def _limit(count: int, label: str, limit: int, reason: str) -> None:
    """Refuse the file when one counted run field holds more items than allowed."""
    if count > limit:
        raise SarifImportRefused(reason, f"{count} {label} exceed the limit of {limit}")


def parse_sarif_document(payload: bytes) -> SarifDocument:
    """Parse one SARIF file and enforce every whole-file limit before anything is imported.

    Parameters
    ----------
    payload : bytes
        The exact bytes of the SARIF file.

    Returns
    -------
    SarifDocument
        The decoded document and its runs.

    Raises
    ------
    SarifImportRefused
        With reason ``too-large``, ``not-json``, ``duplicate-key``, ``non-finite-number``,
        ``too-deep``, ``not-sarif-2.1.0``, ``malformed-run``, ``too-many-runs``,
        ``too-many-results`` or ``too-many-rules``. The rules limit counts the rules of the
        driver and of every tool extension together. A tool component without a name, with
        a version that is not a string, or repeating a rule id is a ``malformed-run``, and so
        are two components of one run with the same name and version.
    """
    if len(payload) > MAX_SARIF_BYTES:
        raise SarifImportRefused(
            "too-large", f"{len(payload)} bytes exceed the limit of {MAX_SARIF_BYTES}"
        )
    try:
        decoded = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise SarifImportRefused("not-json", "the file is not strict UTF-8 JSON") from error
    depth = _nesting(decoded)
    if depth > MAX_NESTING:
        raise SarifImportRefused("too-deep", f"nesting exceeds the limit of {MAX_NESTING}")
    if not isinstance(decoded, dict) or decoded.get("version") != SARIF_VERSION:
        raise SarifImportRefused("not-sarif-2.1.0", "the document is not SARIF version 2.1.0")
    runs = decoded.get("runs")
    if not isinstance(runs, list) or not all(isinstance(run, dict) for run in runs):
        raise SarifImportRefused("malformed-run", "runs must be an array of objects")
    if len(runs) > MAX_RUNS:
        raise SarifImportRefused(
            "too-many-runs", f"{len(runs)} runs exceed the limit of {MAX_RUNS}"
        )
    for run in runs:
        _limit(len(_items(run, "results")), "results", MAX_RESULTS_PER_RUN, "too-many-results")
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        if not isinstance(driver, dict):
            raise SarifImportRefused("malformed-run", "every run must name its tool driver")
        extensions = _items(cast(dict[str, Any], tool), "extensions")
        if not all(isinstance(extension, dict) for extension in extensions):
            raise SarifImportRefused("malformed-run", "tool extensions must be objects")
        # A run's rules live in its driver and in every extension, and all of them count.
        rules = sum(_component_rules(component) for component in (driver, *extensions))
        _limit(rules, "rules", MAX_RULES_PER_RUN, "too-many-rules")
        # A candidate names its rule's component by name and version, so they must be unique.
        identities = [_component_identity(component) for component in (driver, *extensions)]
        if len(identities) != len(set(identities)):
            raise SarifImportRefused(
                "malformed-run", "two tool components share a name and version"
            )
    return SarifDocument(decoded, tuple(runs))
