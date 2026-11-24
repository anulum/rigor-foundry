# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — rule guidance and generated rule catalogue tests
"""Verify published rule guidance, its real candidates, and the generated catalogue command."""

from __future__ import annotations

import importlib
import os
import re
import subprocess
import sys
from pathlib import Path

from repository_audit_git_repository import GitRepository

import rigor_foundry
from rigor_foundry.rule_catalogue import (
    RULE_CATALOGUE_PATH,
    render_rule_catalogue,
    rule_catalogue_anchor,
    rule_guidance,
)
from rigor_foundry.rules import RULES

ROOT = Path(__file__).resolve().parents[1]
_PUBLISHER = re.compile(r"^RULE_GUIDANCE: ", re.MULTILINE)


def _published_guidance_owners() -> list[str]:
    """Return every package module that declares a top-level ``RULE_GUIDANCE`` mapping."""
    package = ROOT / "src" / "rigor_foundry"
    return sorted(
        f"rigor_foundry.{path.stem}"
        for path in package.glob("*.py")
        if _PUBLISHER.search(path.read_text(encoding="utf-8"))
    )


def _catalogue_command(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the real catalogue command from the repository checkout."""
    return subprocess.run(
        [sys.executable, "-m", "tools.render_rule_catalogue", *arguments],
        cwd=ROOT,
        env=dict(os.environ),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_each_registered_rule_is_published_exactly_once_in_registry_order() -> None:
    """Every detector-published entry is one registered rule, and no rule lacks one."""
    published: dict[str, object] = {}
    for name in _published_guidance_owners():
        for rule_id, guidance in importlib.import_module(name).RULE_GUIDANCE.items():
            assert rule_id not in published, f"{rule_id} is published twice"
            published[rule_id] = guidance
    registered = [rule.rule_id for rule in RULES]
    assert sorted(published) == sorted(registered)
    provided = rule_guidance()
    assert list(provided) == registered
    assert all(provided[rule_id] is published[rule_id] for rule_id in registered)


def test_real_candidates_carry_the_guidance_their_detector_publishes(tmp_path: Path) -> None:
    """A real scan's candidates hold exactly one published case of their own rule.

    Parameters
    ----------
    tmp_path : Path
        Owned real Git repository allocation.
    """
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/runner.py",
        "import hashlib\nimport logging\nimport pickle\nimport ssl\nimport subprocess\n"
        "import tempfile\n\nimport requests\n\n\n"
        "def run(command, items=[]):\n"
        "    try:\n"
        "        print(command)\n"
        "        eval(command)\n"
        "        subprocess.run(command, shell=True)\n"
        "        hashlib.md5(command).hexdigest()\n"
        "        tempfile.mktemp()\n"
        "        requests.get(command, verify=False)\n"
        "        ssl._create_unverified_context()\n"
        "        password = 'fixture-only-credential'\n"
        "        logging.info(password)\n"
        "        return pickle.loads(items[0])\n"
        "    except:\n"
        "        return None\n",
    )
    repository.write_text("src/pkg/wild.py", "from pkg.runner import *\n")
    repository.write_text(
        "src/pkg/optional.py",
        "try:\n    import pkg.extension\nexcept Exception:\n    extension = None\n",
    )
    repository.write_text(
        "tests/test_runner.py",
        "import random\n\nimport pytest\n\n\n"
        "def test_sum():\n    assert 0.1 + 0.2 == 0.3\n\n\n"
        "def test_draw():\n    assert random.random() < 2\n\n\n"
        "@pytest.mark.skip(reason='contract')\ndef test_skipped():\n    assert True\n",
    )
    repository.write_text(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo ${{ github.event.head_commit.message }}\n",
    )
    repository.write_text("Dockerfile", "FROM python:3.12\n")
    repository.write_text("requirements.txt", "requests @ git+https://github.com/psf/requests\n")
    repository.commit()

    report = rigor_foundry.scan_repository(repository.root)
    guidance = rule_guidance()
    for candidate in report.candidates:
        cases = {
            (case.rationale, case.verification) for case in guidance[candidate.rule_id].all_cases()
        }
        assert (candidate.rationale, candidate.verification) in cases, candidate.rule_id
    produced = {candidate.rule_id for candidate in report.candidates}
    assert produced == {
        "AR002-wildcard-import-boundary",
        "AR003-broad-optional-import-boundary",
        "AR005-no-module-named-test-owner",
        "AS001-dynamic-code-execution",
        "AS002-shell-command-execution",
        "AS003-unsafe-deserialization",
        "AS004-weak-hash-primitive",
        "AS005-insecure-temporary-file",
        "AS012-disabled-tls-verification",
        "AS013-insecure-ssl-context",
        "DC001-missing-license-header",
        "DK001-unpinned-base-image",
        "DK002-root-runtime-user",
        "DP001-hardcoded-credential",
        "GA001-unpinned-action-reference",
        "GA002-run-context-interpolation",
        "GV001-missing-repository-audit-policy",
        "GV003-undeclared-audit-domain",
        "OP001-print-in-library-code",
        "OP002-credential-in-log-call",
        "RL001-bare-except",
        "RL002-mutable-default-argument",
        "SC002-vcs-url-requirement",
        "SN001-exact-float-equality-in-test",
        "SN002-unseeded-stochastic-test",
        "TA003-skip-or-xfail",
    }


def test_catalogue_has_one_anchored_section_per_rule_with_all_its_cases() -> None:
    """The rendered page holds each rule heading once, with every guidance case."""
    page = render_rule_catalogue()
    headings = [line[4:] for line in page.splitlines() if line.startswith("### ")]
    assert headings == [
        rule.rule_id for rule in sorted(RULES, key=lambda r: _category_order(r.category))
    ]
    for rule_id, entry in rule_guidance().items():
        assert rule_catalogue_anchor(rule_id) == rule_id.lower()
        for case in entry.all_cases():
            assert case.rationale in page
            assert case.verification in page


def _category_order(category: str) -> int:
    """Return a category's first-registry position, the catalogue's section order."""
    return list(dict.fromkeys(rule.category for rule in RULES)).index(category)


def test_tracked_catalogue_is_current_and_the_command_refuses_stale_copies(
    tmp_path: Path,
) -> None:
    """The real command accepts the tracked page and refuses a missing or stale one.

    Parameters
    ----------
    tmp_path : Path
        Owned copy root for the written and stale pages.
    """
    current = _catalogue_command("--check")
    assert current.returncode == 0, current.stderr
    assert current.stdout == "Rule catalogue is current\n"
    assert (ROOT / RULE_CATALOGUE_PATH).read_text(encoding="utf-8") == render_rule_catalogue()

    (tmp_path / "docs").mkdir()
    missing = _catalogue_command("--check", "--root", str(tmp_path))
    assert missing.returncode == 1
    assert "is stale" in missing.stderr

    written = _catalogue_command("--root", str(tmp_path))
    assert written.returncode == 0, written.stderr
    page = tmp_path / RULE_CATALOGUE_PATH
    assert page.read_text(encoding="utf-8") == render_rule_catalogue()
    assert _catalogue_command("--check", "--root", str(tmp_path)).returncode == 0

    page.write_text(
        render_rule_catalogue().replace("Introduced in", "Added in", 1), encoding="utf-8"
    )
    stale = _catalogue_command("--check", "--root", str(tmp_path))
    assert stale.returncode == 1
    assert stale.stderr == (
        f"{RULE_CATALOGUE_PATH} is stale; run python -m tools.render_rule_catalogue\n"
    )
