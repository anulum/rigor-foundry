# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Protected package publication workflow contracts
"""Verify the public PyPI publication workflow's protected entry points."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
RELEASE_TAG_EXPRESSION = "${{ github.event.release.tag_name || inputs.release_tag }}"


def _workflow_text() -> str:
    """Return the tracked publication workflow."""
    return PUBLISH_WORKFLOW.read_text(encoding="utf-8")


def test_publish_workflow_has_owner_confirmed_manual_recovery() -> None:
    """The recovery path requires the owner, a public repo, and explicit consent."""
    workflow = _workflow_text()

    assert "workflow_dispatch:\n    inputs:\n      release_tag:" in workflow
    assert "confirm_public_pypi:" in workflow
    assert "github.actor == github.repository_owner" in workflow
    assert "github.event.repository.private == false" in workflow
    assert "github.event.action == 'published'" in workflow
    assert "github.ref_type == 'tag'" in workflow
    assert "github.ref_name == inputs.release_tag" in workflow
    assert "inputs.confirm_public_pypi == 'publish'" in workflow
    assert "github.event.release.author.login" not in workflow
    assert workflow.count(RELEASE_TAG_EXPRESSION) == 3


def test_publish_workflow_requires_a_published_release_and_oidc() -> None:
    """Both event and recovery paths bind a published tag before OIDC upload."""
    workflow = _workflow_text()

    assert "name: Validate published release" in workflow
    assert "GH_TOKEN: ${{ github.token }}" in workflow
    assert 'gh release view "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY"' in workflow
    assert "--json isDraft,publishedAt,tagName" in workflow
    assert "select(.isDraft == false and .publishedAt != null)" in workflow
    assert 'test "$published_tag" = "$RELEASE_TAG"' in workflow
    assert "name: pypi" in workflow
    assert "id-token: write" in workflow
    assert "pypa/gh-action-pypi-publish@" in workflow
    assert "password:" not in workflow
