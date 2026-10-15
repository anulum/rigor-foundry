# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded workflow YAML public contract tests
"""Verify real YAML parsing, source locations and explicit incomplete outcomes."""

from __future__ import annotations

import pytest

from rigor_foundry.workflow_yaml import (
    MAX_WORKFLOW_ALIASES,
    MAX_WORKFLOW_BYTES,
    MAX_WORKFLOW_DEPTH,
    MAX_WORKFLOW_EVENTS,
    WorkflowFormatError,
    parse_workflow_yaml,
)


def test_literal_on_unicode_crlf_and_alias_definition_locations() -> None:
    """YAML 1.1 keys and Unicode values keep exact original physical locations."""
    root = parse_workflow_yaml(
        "on: [pull_request_target]\r\n"
        "first: &script |\r\n"
        "  echo žluťoučký\r\n"
        "second: *script\r\n"
        "empty: {}\r\n"
    ).mapping()
    assert root["on"].sequence()[0].scalar() == "pull_request_target"
    assert root["first"].scalar() == "echo žluťoučký\n"
    assert (root["first"].line, root["first"].end_line) == (2, 3)
    assert root["second"] is root["first"]
    assert root["empty"].mapping() == {}
    assert parse_workflow_yaml("!!str true").scalar() == "true"
    assert parse_workflow_yaml("[]").sequence() == ()


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", "missing-yaml-document"),
        ("---\na: 1\n---\nb: 2", "multiple-yaml-documents"),
        ("a: [", "invalid-yaml"),
        ("\x00", "invalid-yaml"),
        ("a: 1\na: 2", "duplicate-yaml-key"),
        ("? [a, b]\n: value", "expected-scalar"),
        ("a: &first {nested: *first}", "unresolved-or-cyclic-alias"),
        ("a: *missing", "unresolved-or-cyclic-alias"),
        ("a: &one 1\nb: &one 2", "duplicate-yaml-anchor"),
        ("a: &one [&one value]", "duplicate-yaml-anchor"),
        ("a: !!seq scalar", "yaml-tag-shape-mismatch"),
        ("a: !!str []", "yaml-tag-shape-mismatch"),
        ("a: !!int {}", "yaml-tag-shape-mismatch"),
        ("a: &one {}\nb: {<<: *one}", "unsupported-yaml-merge"),
        ("value: !!python/object:os.system {}", "unsupported-yaml-tag"),
        ("value: !custom text", "unsupported-yaml-tag"),
        (
            "[" * (MAX_WORKFLOW_DEPTH + 2) + "0" + "]" * (MAX_WORKFLOW_DEPTH + 2),
            "yaml-depth-limit",
        ),
        ("[" + ",".join("0" for _ in range(MAX_WORKFLOW_EVENTS)) + "]", "yaml-event-limit"),
        (
            "a: &one value\nb: ["
            + ",".join("*one" for _ in range(MAX_WORKFLOW_ALIASES + 1))
            + "]",
            "yaml-alias-limit",
        ),
        ("#" + "x" * MAX_WORKFLOW_BYTES, "yaml-byte-limit"),
    ],
)
def test_native_invalid_or_over_budget_yaml_refuses_without_source_disclosure(
    text: str, reason: str
) -> None:
    """Real parser inputs exercise ambiguity, construction and resource boundaries."""
    with pytest.raises(WorkflowFormatError, match=reason) as caught:
        parse_workflow_yaml(text)
    assert str(caught.value) == reason
    assert caught.value.line >= 1


@pytest.mark.parametrize(
    ("text", "method", "reason"),
    [
        ("[]", "mapping", "expected-mapping"),
        ("{}", "sequence", "expected-sequence"),
        ("{}", "scalar", "expected-scalar"),
    ],
)
def test_representation_accessors_refuse_structural_mismatches(
    text: str, method: str, reason: str
) -> None:
    """Public consumers cannot reinterpret one YAML kind as another."""
    value = parse_workflow_yaml(text)
    with pytest.raises(WorkflowFormatError, match=reason):
        if method == "mapping":
            value.mapping()
        elif method == "sequence":
            value.sequence()
        else:
            value.scalar()
