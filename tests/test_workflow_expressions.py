# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — workflow expression public contract tests
"""Verify expression literals, context access and shell generation boundaries."""

from __future__ import annotations

import pytest

from rigor_foundry.workflow_expressions import (
    expression_context_paths,
    has_untrusted_run_interpolation,
    selects_pull_request_code,
)
from rigor_foundry.workflow_yaml import WorkflowFormatError


@pytest.mark.parametrize(
    "text",
    [
        "${{ github.event.pull_request.title }}",
        "${{ GITHUB['event']['issue'].body }}",
        "echo '${{ github.head_ref }}'",
        "# ${{ github.ref_name }}",
        "${{ inputs.command }}",
        "${{ toJSON(github) }}",
        "${{ github.event[inputs.key] }}",
        "${{ github.event.commits[0].message }}",
        "${{ format('value ''quoted'' }}', github.event.comment.body) }}",
        "${{ github.sha }} ${{ github.event.review.body }}",
    ],
)
def test_untrusted_context_interpolation_is_identified_before_shell_parsing(text: str) -> None:
    """Shell comments and quotes do not stop GitHub expression substitution."""
    assert has_untrusted_run_interpolation(text)


@pytest.mark.parametrize(
    "text",
    [
        "echo github.event.pull_request.title",
        "${{ 'github.event.pull_request.title' }}",
        "${{ 'it''s }} still a string' }}",
        "${{ github.sha }}",
        "${{ github.event.pull_request.head.sha }}",
        "${{ github.event.pull_request.base.sha }}",
        "${{ github.event.pull_request.merge_commit_sha }}",
        "${{ github.event.pull_request.number }}",
        "${{ github.event.issue.number }}",
        "${{ github.event.number }}",
        "${{ github.repository }}",
        "${{ object.github.event.title }}",
        "${{ env.TITLE }}",
        "${{ 1 + 2 }}",
    ],
)
def test_constants_and_known_safe_identity_paths_do_not_become_injection_candidates(
    text: str,
) -> None:
    """Literal text and narrowly identified SHA/number paths have a distinct result."""
    assert not has_untrusted_run_interpolation(text)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("refs/pull/42/head", True),
        ("refs/pull/42/merge", True),
        ("${{ github.head_ref }}", True),
        ("${{ github.event.pull_request.head.sha }}", True),
        ("${{ github['event'].pull_request.head.repo.full_name }}", True),
        ("${{ github.event.pull_request.merge_commit_sha }}", True),
        ("${{ github.event.pull_request.base.ref }}", False),
        ("${{ github.sha }}", False),
        ("main", False),
        ("${{ env.REF }}", True),
        ("${{ inputs.ref }}", True),
        ("${{ format('refs/pull/{0}/head', github.event.number) }}", True),
        ("${{ 'main' }}", False),
        ("${{ github.repository }}", False),
        ("${{ format('refs/{0}/42/merge', 'pull') }}", True),
        ("refs/${{ 'pull' }}/42/head", True),
        ("${{ format('{0}/fork', github.repository) }}", True),
        ("${{ '' || 'refs/pull/42/head' }}", True),
        ("${{ github.sha }}${{ '' }}", True),
        ("${{ 'refs/pull/42/head' }}", True),
        ("${{ github.sha[0] }}", True),
        ("${{ (github.sha) }}", True),
        ("${{ 42 }}", True),
        ("${{ }}", True),
        ("${{ unknown }}", True),
        ("${{ github '.' sha }}", True),
        ("${{ github['sha' ']' }}", True),
        ("${{ github['sha'] }}", False),
        ("${{ github.ref }}", False),
        ("${{ github.ref_name }}", False),
        ("${{ github.event.repository.full_name }}", False),
        ("${{ github.event.pull_request.base.sha }}", False),
        ("${{ github.event.pull_request.base.repo.full_name }}", False),
        ("  ${{ GITHUB ['event'] ['pull_request'] ['base'] ['ref'] }}\n", False),
        ("${{ 'release''branch' }}", False),
    ],
)
def test_checkout_selector_distinguishes_pull_request_code_from_base_code(
    text: str, expected: bool
) -> None:
    """Target-event checkout classification retains trusted base controls."""
    assert selects_pull_request_code(text) is expected


def test_context_paths_preserve_constant_brackets_and_ignore_literal_context_names() -> None:
    """Only identifiers and actual property access form a context path."""
    assert expression_context_paths("${{ github['event'].issue['title'] }}") == (
        ("github", "event", "issue", "title"),
    )
    assert expression_context_paths("${{ github. }}") == (("github",),)
    assert expression_context_paths("${{ github['event' }}") == (("github",),)
    assert expression_context_paths("${{ github[0] }}") == (("github",),)


@pytest.mark.parametrize("text", ["${{ github.event.title", "${{ 'open }}", "${{ 'open }"])
def test_unterminated_expression_refuses_instead_of_reporting_safe(text: str) -> None:
    """Incomplete generated-script expressions cannot receive a clean disposition."""
    with pytest.raises(WorkflowFormatError, match="invalid-actions-expression"):
        expression_context_paths(text)
