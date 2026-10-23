# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded policy source read tests
"""Exercise strict JSON and cohort limits using actual regular source files."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.git_inventory import StableReadError
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import (
    parse_policy_document_payload,
    read_policy_document,
    read_policy_source_payloads,
)


def test_retained_payload_parser_preserves_exact_json_semantics() -> None:
    """Retained bytes use the same bounded decoder without reopening their source path."""
    payload = b'{"known":null,"empty":[],"nested":{"x":1}}'
    assert parse_policy_document_payload(
        payload, budget=budget(max_document_bytes=len(payload))
    ) == json.loads(payload)
    for invalid in [cast(bytes, "{}"), b"x" * 1025, b'{"x":1,"x":2}', b"[[[[[]]]]]"]:
        with pytest.raises(ValueError):
            parse_policy_document_payload(invalid, budget=budget())


def budget(**changes: int) -> PolicyReadBudget1:
    """Return explicit limits for one bounded input transaction."""
    limits = {
        "max_document_bytes": 1024,
        "max_source_bytes": 8,
        "max_total_source_bytes": 12,
        "max_sources": 2,
        "max_rules": 8,
        "max_references": 16,
        "max_depth": 4,
    }
    return PolicyReadBudget1.build(**{**limits, **changes})


def test_document_strict_utf8_and_exact_byte_limit(tmp_path: Path) -> None:
    """Original UTF8 is decoded only after the exact file-byte ceiling passes."""
    path = tmp_path / "rules.json"
    payload = '{"statement":"Pravidlá žijú","condition":[{"value":null}]}'.encode()
    path.write_bytes(payload)
    limits = budget(max_document_bytes=len(payload))
    assert read_policy_document(path, budget=limits) == json.loads(payload)
    with pytest.raises(ValueError):
        read_policy_document(path, budget=budget(max_document_bytes=len(payload) - 1))


@pytest.mark.parametrize(
    "payload",
    [
        b'{"a":1,"a":2}',
        b'{"a":{"x":1,"x":2}}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":-Infinity}',
        b'{"a":1e999}',
        b'{"a":"\\ud800"}',
        b'{"\\udfff":1}',
        b'["\\ud800"]',
        b'{"a":1} trailing',
        b"\xff",
        b"\xef\xbb\xbf{}",
        b"]",
        b'{"a":',
        b"[}",
        b"[[[[[]]]]]",
    ],
)
def test_invalid_documents_refuse_without_partial_value(tmp_path: Path, payload: bytes) -> None:
    """Duplicate keys, nonfinite numbers, invalid Unicode and nesting never succeed."""
    path = tmp_path / "input"
    path.write_bytes(payload)
    with pytest.raises(ValueError):
        read_policy_document(path, budget=budget())


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        1,
        1.25,
        "text",
        "astral \U0001f9e0",
        [],
        {},
        {"text": '[ ] { } " \\ \\"', "children": [[{}]]},
    ],
)
def test_depth_scanner_respects_escaped_strings_and_json_scalars(
    tmp_path: Path,
    value: object,
) -> None:
    """Brackets, escapes and quotes in strings do not consume container depth."""
    path = tmp_path / "input"
    path.write_text(json.dumps(value), encoding="utf-8")
    assert read_policy_document(path, budget=budget()) == value


def test_depth_ceiling_accepts_exact_and_refuses_next_level(tmp_path: Path) -> None:
    """Nesting is bounded before deeply recursive decoding occurs."""
    path = tmp_path / "input"
    path.write_bytes(b"[[[[]]]]")
    assert read_policy_document(path, budget=budget()) == [[[[]]]]
    path.write_bytes(b"[" * 2000 + b"]" * 2000)
    with pytest.raises(ValueError, match="depth"):
        read_policy_document(path, budget=budget(max_document_bytes=4000))


def test_source_cohort_exact_bytes_order_and_aggregate_bound(tmp_path: Path) -> None:
    """Multiple real source files share one aggregate allocation budget."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.write_bytes(b"\xc5\xbe\r\n")
    b.write_bytes(b"12345678")
    paths = {"source-b": b, "source-a": a}
    actual = read_policy_source_payloads(paths, budget=budget())
    assert list(actual) == ["source-a", "source-b"]
    assert actual == {"source-a": b"\xc5\xbe\r\n", "source-b": b"12345678"}
    with pytest.raises(ValueError):
        read_policy_source_payloads(paths, budget=budget(max_total_source_bytes=11))
    b.write_bytes(b"123456789")
    with pytest.raises(ValueError):
        read_policy_source_payloads(paths, budget=budget(max_total_source_bytes=16))


def test_exhausted_total_allows_empty_sources_but_refuses_one_more_byte(tmp_path: Path) -> None:
    """An empty final file does not require a fabricated byte allowance."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.write_bytes(b"12345678")
    b.write_bytes(b"")
    paths = {"a": a, "b": b}
    assert read_policy_source_payloads(paths, budget=budget(max_total_source_bytes=8))["b"] == b""
    b.write_bytes(b"x")
    with pytest.raises(ValueError, match="total"):
        read_policy_source_payloads(paths, budget=budget(max_total_source_bytes=8))


def test_count_and_all_source_identities_are_checked_before_opening(tmp_path: Path) -> None:
    """Malformed cohorts refuse before accessing even their first absent source."""
    absent = tmp_path / "absent"
    with pytest.raises(ValueError, match="count"):
        read_policy_source_payloads({"a": absent, "b": absent, "c": absent}, budget=budget())
    with pytest.raises(ValueError, match="identifier"):
        read_policy_source_payloads({"a": absent, "bad id": absent}, budget=budget())
    assert read_policy_source_payloads({}, budget=budget()) == {}


@pytest.mark.parametrize("reader", [read_policy_document, read_policy_source_payloads])
def test_budget_revalidation_precedes_io(tmp_path: Path, reader: object) -> None:
    """A forged instance cannot enlarge limits at a public reader boundary."""
    limits = budget()
    object.__setattr__(limits, "max_depth", 33)
    with pytest.raises(ValueError):
        if reader is read_policy_document:
            read_policy_document(tmp_path / "absent", budget=limits)
        else:
            read_policy_source_payloads({"a": tmp_path / "absent"}, budget=limits)


def test_source_aliases_and_nonregular_inputs_refuse(tmp_path: Path) -> None:
    """Both public read paths use the existing descriptor-custody checks."""
    original = tmp_path / "original"
    original.write_bytes(b"{}")
    alias = tmp_path / "alias"
    alias.symlink_to(original)
    with pytest.raises(StableReadError):
        read_policy_document(alias, budget=budget())
    with pytest.raises(StableReadError):
        read_policy_source_payloads({"a": tmp_path}, budget=budget())
    hardlink = tmp_path / "hardlink"
    hardlink.hardlink_to(original)
    with pytest.raises(StableReadError):
        read_policy_source_payloads({"a": hardlink}, budget=budget())


def test_missing_regular_source_propagates_io_failure(tmp_path: Path) -> None:
    """No missing source is replaced with an empty or partial cohort."""
    with pytest.raises((OSError, StableReadError)):
        read_policy_source_payloads({"a": tmp_path / "absent"}, budget=budget())


def test_dataclass_replace_is_not_an_authority_to_change_budget() -> None:
    """Even Python-side edits require matching validated limits and identity."""
    with pytest.raises(ValueError, match="digest"):
        replace(budget(), max_sources=1)


def test_invalid_budget_and_source_path_types_refuse_before_io(tmp_path: Path) -> None:
    """Runtime records cannot substitute a mapping or string for typed input owners."""
    invalid_budget = cast(PolicyReadBudget1, {})
    with pytest.raises(ValueError, match="budget is required"):
        read_policy_document(tmp_path / "absent", budget=invalid_budget)
    with pytest.raises(ValueError, match="Path"):
        read_policy_source_payloads({"a": cast(Path, "source")}, budget=budget())
