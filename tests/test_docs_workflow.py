# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — documentation deployment workflow contract

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "docs.yml"


def test_docs_workflow_has_read_only_build_and_bounded_branch_writer() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in workflow
    assert "permissions:\n      contents: write" in workflow
    assert "if: github.event_name != 'pull_request'" in workflow
    assert "persist-credentials: false" in workflow
    assert "retention-days: 1" in workflow
    assert "refs/heads/gh-pages:refs/remotes/origin/gh-pages" in workflow
    assert "switch --orphan gh-pages" in workflow
    assert 'git -C "$PAGES_DIR" push origin gh-pages' in workflow
    assert "push --force" not in workflow
    assert "x-access-token" not in workflow
    assert "secrets." not in workflow


def test_docs_workflow_rejects_unbounded_generated_content() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    assert "test -f site/index.html" in workflow
    assert 'test -z "$(find site -type l -print -quit)"' in workflow
    assert 'test -z "$(find site -name .git -print -quit)"' in workflow
    assert 'test -f "$PAGES_DIR/index.html"' in workflow
    assert ': > "$PAGES_DIR/.nojekyll"' in workflow


def test_docs_workflow_uses_only_immutable_action_revisions() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    action_refs = re.findall(r"uses: [^@\n]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_refs)
    assert "actions/deploy-pages" not in workflow
    assert "actions/upload-pages-artifact" not in workflow
