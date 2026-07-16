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
QUALIFIED_TAG_EXPRESSION = f"refs/tags/{RELEASE_TAG_EXPRESSION}"


def _workflow_text() -> str:
    """Return the tracked publication workflow."""
    return PUBLISH_WORKFLOW.read_text(encoding="utf-8")


def test_publish_workflow_has_owner_confirmed_manual_recovery() -> None:
    """Recovery runs only from a release ref or the protected default branch."""
    workflow = _workflow_text()

    assert "workflow_dispatch:\n    inputs:\n      release_tag:" in workflow
    assert "confirm_public_pypi:" in workflow
    assert "github.actor == github.repository_owner" in workflow
    assert "github.event.repository.private == false" in workflow
    assert "github.event.action == 'published'" in workflow
    assert "github.ref_type == 'tag'" in workflow
    assert "github.ref_name == inputs.release_tag" in workflow
    assert "github.ref_type == 'branch'" in workflow
    assert "github.ref_name == github.event.repository.default_branch" in workflow
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
    assert (
        "    permissions:\n"
        "      contents: write\n"
        "      id-token: write\n"
        "      attestations: write\n"
    ) in workflow
    assert f"          ref: {QUALIFIED_TAG_EXPRESSION}" in workflow
    assert f"          ref: {RELEASE_TAG_EXPRESSION}" not in workflow
    assert "          persist-credentials: false" in workflow
    assert "release-signing-artifacts: true" in workflow
    assert "pypa/gh-action-pypi-publish@" in workflow
    assert "password:" not in workflow


def test_publish_workflow_keeps_signatures_out_of_distribution_uploads() -> None:
    """Sigstore bundles leave ``dist`` before attestation and publication."""
    workflow = _workflow_text()

    isolate_step = workflow.index("name: Isolate signing bundles")
    attest_step = workflow.index("actions/attest-build-provenance@")
    publish_step = workflow.index("pypa/gh-action-pypi-publish@")

    assert isolate_step < attest_step < publish_step
    assert "mkdir --mode=0700 signing-bundles" in workflow
    assert "mv dist/*.sigstore.json signing-bundles/" in workflow
    assert 'test "$(find dist -maxdepth 1 -type f | wc -l)" -eq 2' in workflow
    assert "name: Attach recovery signing bundles" in workflow
    assert "if: github.event_name == 'workflow_dispatch'" in workflow
    assert 'test "$bundle_count" -eq 2' in workflow
    assert 'gh release upload "$RELEASE_TAG" signing-bundles/*.sigstore.json' in workflow
    assert "--clobber" in workflow
