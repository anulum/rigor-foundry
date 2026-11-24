# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — byte-equal SARIF golden fixture tests
"""Verify the committed SARIF golden fixtures byte for byte and the facts each one fixes."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from tools.render_sarif_fixtures import (
    FIXTURE_DIRECTORY,
    FIXTURE_INPUTS,
    GOLDENS,
    render_sarif_goldens,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / FIXTURE_DIRECTORY


def _run(path: str) -> dict[str, Any]:
    """Return the only run of one committed golden fixture."""
    document = json.loads((FIXTURES / path).read_text(encoding="utf-8"))
    (run,) = document["runs"]
    result: dict[str, Any] = run
    return result


def _fixture_command(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the real fixture command from the repository checkout."""
    return subprocess.run(
        [sys.executable, "-m", "tools.render_sarif_fixtures", *arguments],
        cwd=ROOT,
        env=dict(os.environ),
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )


def test_every_golden_is_byte_equal_to_its_committed_inputs_rendering() -> None:
    """Each tracked golden equals the export of its committed real report and reviews."""
    rendered = render_sarif_goldens(ROOT)
    for golden in GOLDENS:
        assert golden.purpose
        assert (FIXTURES / golden.name).read_text(encoding="utf-8") == rendered[golden.name]
    assert sorted(path.name for path in FIXTURES.iterdir()) == sorted(
        [*FIXTURE_INPUTS, *(golden.name for golden in GOLDENS)]
    )


def test_the_command_accepts_current_fixtures_and_refuses_a_stale_copy(tmp_path: Path) -> None:
    """The real command passes on the tracked fixtures and names a stale or missing one.

    Parameters
    ----------
    tmp_path : Path
        Owned copy of the fixture inputs.
    """
    current = _fixture_command("--check")
    assert current.returncode == 0, current.stderr
    assert current.stdout == "SARIF fixtures are current\n"

    copy = tmp_path / FIXTURE_DIRECTORY
    copy.mkdir(parents=True)
    for name in FIXTURE_INPUTS:
        shutil.copyfile(FIXTURES / name, copy / name)
    missing = _fixture_command("--check", "--root", str(tmp_path))
    assert missing.returncode == 1
    assert "stale SARIF fixtures: canonical-empty.sarif" in missing.stderr

    written = _fixture_command("--root", str(tmp_path))
    assert written.returncode == 0, written.stderr
    assert _fixture_command("--check", "--root", str(tmp_path)).returncode == 0
    stale = copy / "github-states.sarif"
    stale.write_text(
        stale.read_text(encoding="utf-8").replace("valid", "VALID", 1), encoding="utf-8"
    )
    refused = _fixture_command("--check", "--root", str(tmp_path))
    assert refused.returncode == 1
    assert refused.stderr == (
        "stale SARIF fixtures: github-states.sarif; run python -m tools.render_sarif_fixtures\n"
    )


def test_the_states_golden_fixes_every_state_level_anchor_and_encoded_path() -> None:
    """The canonical states golden holds each review state, its level, both anchors and the path."""
    results = _run("canonical-states.sarif")["results"]
    by_state: dict[str, set[str]] = {}
    for result in results:
        by_state.setdefault(result["properties"]["rigorFoundry/verdictState"], set()).add(
            result["level"]
        )
    assert by_state == {
        "valid": {"error", "warning", "note"},
        "invalid": {"none"},
        "accepted-boundary": {"note"},
        "needs-evidence": {"note"},
        "unreviewed": {"note"},
    }
    severities = sorted(
        result["properties"]["rigorFoundry/review"]["severity"]
        for result in results
        if result["properties"]["rigorFoundry/verdictState"] == "valid"
    )
    assert severities == ["P0", "P1", "P2", "P3", "P4"]
    kinds = {result["properties"]["rigorFoundry/anchor"]["kind"] for result in results}
    assert kinds == {"tracked-blob", "repository-tree"}
    uris = {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in results
    }
    assert "src/pkg/%C3%BCber%20file.py" in uris
    unreviewed = _run("canonical-unreviewed.sarif")["results"]
    assert {result["properties"]["rigorFoundry/verdictState"] for result in unreviewed} == {
        "unreviewed"
    }
    assert len(unreviewed) == len(results)


def test_the_profile_goldens_declare_their_omissions_and_canonical_digest() -> None:
    """Each profile golden keeps only valid results and binds its canonical golden's bytes."""
    states = _run("github-states.sarif")
    assert {result["properties"]["rigorFoundry/verdictState"] for result in states["results"]} == {
        "valid"
    }
    canonical = _run("canonical-states.sarif")
    omitted = states["properties"]["rigorFoundry/omittedResults"]
    assert sum(omitted.values()) + len(states["results"]) == len(canonical["results"])
    assert omitted == {
        "unreviewed": len(canonical["results"]) - 8,
        "needs-evidence": 1,
        "invalid": 1,
        "accepted-boundary": 1,
    }
    canonical_bytes = (FIXTURES / "canonical-states.sarif").read_bytes()
    assert (
        states["properties"]["rigorFoundry/canonicalDocumentDigest"]
        == hashlib.sha256(canonical_bytes).hexdigest()
    )
    empty = _run("github-empty.sarif")
    assert empty["results"] == []
    assert set(empty["properties"]["rigorFoundry/omittedResults"].values()) == {0}
    assert (
        empty["properties"]["rigorFoundry/canonicalDocumentDigest"]
        == hashlib.sha256((FIXTURES / "canonical-empty.sarif").read_bytes()).hexdigest()
    )
    assert _run("canonical-empty.sarif")["results"] == []
