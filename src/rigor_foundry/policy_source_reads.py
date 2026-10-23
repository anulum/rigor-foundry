# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded policy document and source reads
"""Read exact supplied policy inputs without appointing a trusted source owner."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from pathlib import Path
from typing import NoReturn

from .model_primitives import require_identifier
from .policy_read_budget import PolicyReadBudget1
from .source_capture import read_source_payload


def _checked_budget(budget: PolicyReadBudget1) -> PolicyReadBudget1:
    """Revalidate a direct instance before any input is opened."""
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    return PolicyReadBudget1.from_dict(budget.to_dict())


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Preserve JSON identity by refusing duplicate or non-UTF8 object keys."""
    result: dict[str, object] = {}
    for key, value in pairs:
        key.encode("utf-8")
        if key in result:
            raise ValueError("policy document has duplicate keys")
        result[key] = value
    return result


def _nonfinite(value: str) -> NoReturn:
    """Refuse non-JSON constants without including caller content."""
    del value
    raise ValueError("policy document has a non-finite number")


def _finite_float(value: str) -> float:
    """Reject overflow of a syntactically valid JSON floating-point number."""
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("policy document has a non-finite number")
    return parsed


def _check_depth(payload: bytes, maximum: int) -> None:
    """Bound container nesting before the recursive JSON decoder allocates it."""
    depth = 0
    quoted = False
    escaped = False
    for byte in payload:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > maximum:
                raise ValueError("policy document exceeds the depth budget")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise ValueError("policy document has invalid nesting")


def _check_strings(value: object) -> None:
    """Reject unpaired escaped surrogates in string values at any depth."""
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, dict):
        for child in value.values():
            _check_strings(child)
    elif isinstance(value, list):
        for child in value:
            _check_strings(child)


def read_policy_document(path: Path, *, budget: PolicyReadBudget1) -> object:
    """Read one strict UTF8 JSON input within its explicit byte and depth bounds.

    Parameters
    ----------
    path : Path
        Supplied local regular file. No network retrieval occurs.
    budget : PolicyReadBudget1
        Explicit allocation ceilings, revalidated before opening the input.

    Returns
    -------
    object
        Parsed JSON value for the owning closed-record parser.

    Raises
    ------
    ValueError
        Input is oversized, malformed, duplicate-keyed, nonfinite or too deep.
    OSError
        The file cannot be opened.
    StableReadError
        The descriptor reader refuses an alias, nonregular or unstable input.

    Notes
    -----
    Parsing proves neither semantic acceptance nor source-access authority.
    """
    checked = _checked_budget(budget)
    payload = read_source_payload(path, maximum_bytes=checked.max_document_bytes)
    return parse_policy_document_payload(payload, budget=checked)


def parse_policy_document_payload(payload: bytes, *, budget: PolicyReadBudget1) -> object:
    """Decode retained exact policy bytes under the explicit document/depth limits.

    Parameters
    ----------
    payload : bytes
        Actual source bytes already retained by the calling source owner.
    budget : PolicyReadBudget1
        Explicit allocation ceilings, revalidated before decoding.

    Returns
    -------
    object
        Strict JSON data without any source-selection or authentication claim.

    Raises
    ------
    ValueError
        Bytes are malformed, oversized, duplicate-keyed, nonfinite or too deep.
    """
    checked = _checked_budget(budget)
    if not isinstance(payload, bytes) or len(payload) > checked.max_document_bytes:
        raise ValueError("policy document payload exceeds the byte budget or has invalid type")
    _check_depth(payload, checked.max_depth)
    value: object = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_unique_pairs,
        parse_constant=_nonfinite,
        parse_float=_finite_float,
    )
    _check_strings(value)
    return value


def read_policy_source_payloads(
    paths: Mapping[str, Path], *, budget: PolicyReadBudget1
) -> dict[str, bytes]:
    """Read a complete supplied source cohort under per-file and aggregate bounds.

    Parameters
    ----------
    paths : Mapping[str, Path]
        Exact source IDs and retained local files chosen by the owning caller.
    budget : PolicyReadBudget1
        Explicit ceilings for source count, each source and total retained bytes.

    Returns
    -------
    dict[str, bytes]
        Exact immutable payloads in source-ID order, only after all reads succeed.

    Raises
    ------
    ValueError
        Source identity, count, individual bytes or aggregate bytes are invalid.
    OSError
        A retained source cannot be opened.
    StableReadError
        A source is aliased, nonregular or changes during its read.

    Notes
    -----
    This supplies bytes for compilation; caller-supplied paths authenticate no
    producer, corpus completeness, policy meaning or live host selection.
    """
    checked = _checked_budget(budget)
    if len(paths) > checked.max_sources:
        raise ValueError("policy sources exceed the count budget")
    items = tuple(paths.items())
    for source_id, path in items:
        require_identifier(source_id, "policy source identity")
        if not isinstance(path, Path):
            raise ValueError("policy source path must be a Path")
    result: dict[str, bytes] = {}
    used = 0
    for source_id, path in sorted(items):
        remaining = checked.max_total_source_bytes - used
        limit = min(checked.max_source_bytes, max(1, remaining))
        payload = read_source_payload(path, maximum_bytes=limit)
        if len(payload) > remaining:
            raise ValueError("policy sources exceed the total byte budget")
        used += len(payload)
        result[source_id] = payload
    return result
