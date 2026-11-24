# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — SARIF output validation against the pinned OASIS schema
"""Validate real SARIF exports and every golden fixture against the digest-pinned schema."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

import rigor_foundry
from rigor_foundry.models import ReviewRecord
from rigor_foundry.sarif_github_profile import GITHUB_CODE_SCANNING_PROFILE
from tools.render_sarif_fixtures import FIXTURE_DIRECTORY, GOLDENS
from tools.sarif_schema_pin import LOCAL_FETCH_COMMAND, SARIF_SCHEMA_ENV, SARIF_SCHEMA_SHA256

ROOT = Path(__file__).resolve().parents[1]
_VALIDATOR = (
    "import json, sys\n"
    "from jsonschema import Draft4Validator\n"
    "schema = json.load(open(sys.argv[1], encoding='utf-8'))\n"
    "errors = []\n"
    "for path in sys.argv[2:]:\n"
    "    document = json.load(open(path, encoding='utf-8'))\n"
    "    errors += [f'{path}: {error.message}' for error in Draft4Validator(schema).iter_errors(document)]\n"
    "print('\\n'.join(errors))\n"
    "raise SystemExit(1 if errors else 0)\n"
)


def pinned_schema(path: Path) -> Path:
    """Return ``path`` only when its bytes have the pinned SARIF schema SHA-256.

    Parameters
    ----------
    path : Path
        A supplied copy of the OASIS SARIF 2.1.0 Errata 01 schema.

    Returns
    -------
    Path
        The same path, once its digest matches the pin.

    Raises
    ------
    AssertionError
        If the file's SHA-256 differs from the tracked pin.
    """
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == SARIF_SCHEMA_SHA256, f"SARIF schema digest {digest} differs from the pin"
    return path


@pytest.fixture(scope="module")
def schema_path() -> Path:
    """Require the CI-fetched, digest-pinned schema; locally, fetch it with LOCAL_FETCH_COMMAND.

    Returns
    -------
    Path
        The verified schema copy named by ``RIGOR_SARIF_SCHEMA_PATH``.
    """
    value = os.environ.get(SARIF_SCHEMA_ENV)
    assert value, (
        f"The pinned SARIF schema must be supplied through {SARIF_SCHEMA_ENV}; "
        f"fetch it with: {LOCAL_FETCH_COMMAND}"
    )
    return pinned_schema(Path(value))


def _validate(schema: Path, *documents: Path) -> subprocess.CompletedProcess[str]:
    """Validate SARIF documents with jsonschema from the CI documentation interpreter."""
    python = os.environ.get("RIGOR_DOCUMENTATION_PYTHON")
    assert python, "The documentation interpreter with jsonschema must be supplied"
    return subprocess.run(
        [python, "-I", "-c", _VALIDATOR, str(schema), *(str(path) for path in documents)],
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )


def test_every_committed_golden_fixture_is_schema_valid(schema_path: Path) -> None:
    """Each byte-equal golden, canonical and profile alike, validates against the pinned schema.

    Parameters
    ----------
    schema_path : Path
        The verified pinned schema.
    """
    fixtures = [ROOT / FIXTURE_DIRECTORY / golden.name for golden in GOLDENS]
    completed = _validate(schema_path, *fixtures)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_a_fresh_real_export_and_its_profile_are_schema_valid(
    schema_path: Path, tmp_path: Path
) -> None:
    """A newly scanned and reviewed repository exports schema-valid canonical and profile SARIF.

    Parameters
    ----------
    schema_path : Path
        The verified pinned schema.
    tmp_path : Path
        Owned real Git repository and output allocation.
    """
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/runner.py", "def run(command):\n    eval(command)\n")
    repository.commit()
    report = rigor_foundry.scan_repository(repository.root)
    reviews = (ReviewRecord.template(report.report_digest, report.candidates[0].candidate_id),)
    canonical = tmp_path / "canonical.sarif"
    profiled = tmp_path / "github.sarif"
    canonical.write_text(rigor_foundry.report_sarif(report, reviews), encoding="utf-8")
    profiled.write_text(
        rigor_foundry.report_sarif(report, reviews, profile=GITHUB_CODE_SCANNING_PROFILE),
        encoding="utf-8",
    )
    completed = _validate(schema_path, canonical, profiled)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_a_schema_copy_with_another_digest_is_refused(schema_path: Path, tmp_path: Path) -> None:
    """A schema whose bytes differ from the pin is refused before any validation.

    Parameters
    ----------
    schema_path : Path
        The verified pinned schema.
    tmp_path : Path
        Owned allocation for the altered copy.
    """
    altered = tmp_path / "sarif-schema-2.1.0.json"
    altered.write_bytes(schema_path.read_bytes() + b"\n")
    with pytest.raises(AssertionError, match="differs from the pin"):
        pinned_schema(altered)


def test_both_workflows_fetch_the_schema_through_the_single_pin() -> None:
    """The shard job and the distribution job read the URL and digest from the one tracked pin."""
    for workflow in ("ci-tests.yml", "ci-distribution.yml"):
        text = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
        assert '"$(python -m tools.sarif_schema_pin url)"' in text, workflow
        assert '"$(python -m tools.sarif_schema_pin sha256)"' in text, workflow
        assert "sha256sum --check --strict" in text, workflow
        assert SARIF_SCHEMA_SHA256 not in text, workflow
