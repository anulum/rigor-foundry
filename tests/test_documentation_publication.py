# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Documentation publication boundary tests
"""Build the real documentation with private records outside the public surface."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import yaml

from tools._repository import ROOT


def test_documentation_build_preserves_private_records(tmp_path: Path) -> None:
    """HTML, search data and static output exclude private input bytes and paths."""
    repository = tmp_path / "repository"
    repository.mkdir()
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "--", "docs", "mkdocs.yml"],
        check=True,
        capture_output=True,
        timeout=10,
    )
    for raw in tracked.stdout.split(b"\0")[:-1]:
        tracked_path = Path(raw.decode())
        source = ROOT / tracked_path
        assert source.is_file() and not source.is_symlink()
        target = repository / tracked_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    markers = {
        "agentic_project_memory/memory_index.md": b"MEMORYPRIVATECANARY791643\n",
        "docs/internal/publication_canary.md": b"INTERNALPRIVATECANARY582137\n",
    }
    before = {}
    for relative, marker in markers.items():
        record = repository / relative
        record.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        record.write_bytes(marker)
        record.chmod(0o600)
        before[relative] = (record.read_bytes(), record.stat())

    build = subprocess.run(
        [
            os.environ.get("RIGOR_DOCUMENTATION_PYTHON", sys.executable),
            "-m",
            "mkdocs",
            "build",
            "--strict",
        ],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert build.returncode == 0, build.stderr[-4000:]
    site = repository / "site"
    assert (site / "index.html").is_file()
    search = json.loads((site / "search/search_index.json").read_text())
    assert search["docs"]
    assert any("RigorFoundry" in item["text"] for item in search["docs"])
    files = [path for path in site.rglob("*") if path.is_file()]
    assert files
    for path in files:
        assert not path.is_symlink()
        assert not {"internal", "agentic_project_memory"} & set(path.relative_to(site).parts)
        content = path.read_bytes()
        assert all(marker.strip() not in content for marker in markers.values())
    for relative, (content, status) in before.items():
        record = repository / relative
        assert record.read_bytes() == content
        assert stat.S_IMODE(record.stat().st_mode) == 0o600
        assert record.stat().st_mtime_ns == status.st_mtime_ns
        assert record.stat().st_ino == status.st_ino


def test_exhaustive_job_installs_documentation_dependencies() -> None:
    """The job exercising the real privacy build installs its locked renderer."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["test"]["steps"]
    install = next(
        step for step in steps if step.get("name") == "Install hash-locked test environment"
    )
    commands = install["run"].splitlines()
    create = 'python -m venv "$RUNNER_TEMP/rigor-docs-venv"'
    provision = '"$RUNNER_TEMP/rigor-docs-venv/bin/python" -m pip install --require-hashes -r requirements/ci.txt'
    assert commands.index(create) < commands.index(provision)
    suite = next(step for step in steps if step.get("name") == "Run exhaustive CI-owned suite")
    assert (
        suite["env"]["RIGOR_DOCUMENTATION_PYTHON"]
        == "${{ runner.temp }}/rigor-docs-venv/bin/python"
    )
    setup = next(
        step for step in steps if step.get("uses", "").startswith("actions/setup-python@")
    )
    assert "requirements/ci.txt" in setup["with"]["cache-dependency-path"].splitlines()
    lock = (ROOT / "requirements/ci.txt").read_text()
    assert "\nmkdocs==" in lock
    assert "\nmkdocs-material==" in lock


def test_documentation_upload_is_bounded_to_built_site() -> None:
    """Changing the approved output/upload roots requires a new boundary review."""
    configuration = (ROOT / "mkdocs.yml").read_text()
    assert "docs_dir:" not in configuration
    assert "site_dir:" not in configuration
    workflow = (ROOT / ".github/workflows/docs.yml").read_text()
    producer = "      - run: python -m mkdocs build --strict\n"
    assert workflow.count(producer) == 1
    assert workflow.count("uses: actions/upload-artifact@") == 1
    assert workflow.index(producer) < workflow.index("uses: actions/upload-artifact@")
    assert workflow.count("          name: rigor-foundry-site\n          path: site\n") == 2
    assert "          if-no-files-found: error\n" in workflow
    assert "    needs: build\n" in workflow
    assert '          cp --archive site/. "$PAGES_DIR/"\n' in workflow
