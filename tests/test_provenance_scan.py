# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Offline provenance scan owner tests
"""Exercise the real Git-bound provenance scan command and stable report."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.cli import main
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditReport
from rigor_foundry.provenance_scan import build_provenance_scan
from rigor_foundry.scanner import scan_repository

WHEEL_DIGEST = "c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf"


def _lock_repository(tmp_path: Path) -> GitRepository:
    """Commit the exact cffi distribution hash through a real Git test repository."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_bytes(
        "requirements/runtime.txt",
        f"cffi==2.1.1 \\\n    --hash=sha256:{WHEEL_DIGEST}\n".encode(),
    )
    repo.commit()
    return repo


def _distribution(*, predicate: str) -> dict[str, object]:
    """Return the known cffi wheel input with no published PEP 740 evidence."""
    return {
        "project": "cffi",
        "version": "2.1.1",
        "artifact": "cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
        "sha256": WHEEL_DIGEST,
        "predicate": predicate,
        "identity": "https://github.com/python-cffi/cffi",
        "issuer": "https://token.actions.githubusercontent.com",
        "source_commit": None,
        "bundle": None,
        "bundle_sha256": None,
        "root": None,
        "root_sha256": None,
    }


def _cli(
    repo: GitRepository,
    directory: Path,
    distributions: object,
    *,
    scorecard: dict[str, object] | None = None,
    pin: str | None = None,
    schema_version: str = "1.0",
    lock: str = "requirements/runtime.txt",
) -> tuple[int, Path]:
    """Run the production command with a real fingerprinted local profile."""
    path = directory / "profile.json"
    output = directory / "provenance-output.json"
    data = json.dumps(
        {
            "schema_version": schema_version,
            "lock": lock,
            "distributions": distributions,
            "scorecard": scorecard,
        },
        sort_keys=True,
    ).encode()
    path.write_bytes(data)
    status = main(
        [
            "scan-provenance",
            "--root",
            str(repo.root),
            "--profile",
            str(path),
            "--profile-sha256",
            pin or sha256(data).hexdigest(),
            "--output",
            str(output),
        ]
    )
    return status, output


@pytest.mark.parametrize(
    ("predicate", "expected"),
    [
        ("https://docs.pypi.org/attestations/publish/v1", "unavailable"),
        ("https://example.invalid/unsupported", "unsupported"),
    ],
)
def test_optional_attestation_keeps_static_report_identity(
    tmp_path: Path, predicate: str, expected: str
) -> None:
    """Emit explicit states without changing a report body or its candidates."""
    repo = _lock_repository(tmp_path)
    status, output = _cli(repo, tmp_path, [_distribution(predicate=predicate)])
    assert status == 0
    result = json.loads(output.read_bytes())
    original = scan_repository(repo.root)
    assert AuditReport.from_dict(result["audit_report"]) == original
    provenance = result["provenance"]
    assert provenance["report_digest"] == original.report_digest
    assert provenance["distributions"][0]["status"] == expected
    assert provenance["distributions"][0]["verification"] is None
    claimed = provenance.pop("provenance_digest")
    assert canonical_digest(provenance) == claimed


def test_scan_refuses_wrong_fingerprint_and_unlocked_distribution(tmp_path: Path) -> None:
    """Reject source drift and unlisted artefacts before writing any output."""
    repo = _lock_repository(tmp_path)
    row = _distribution(predicate="https://docs.pypi.org/attestations/publish/v1")
    status, output = _cli(repo, tmp_path, [row], pin="0" * 64)
    assert status == 2
    assert not output.exists()
    row["sha256"] = "0" * 64
    status, output = _cli(repo, tmp_path, [row])
    assert status == 2
    assert not output.exists()


@pytest.mark.parametrize(
    ("linked", "error"),
    [(True, "multiple hard links"), (False, "exceeds the configured byte limit")],
)
def test_scan_requires_a_single_link_and_bounded_profile(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], linked: bool, error: str
) -> None:
    """Refuse hard links and oversized input through each platform's native reader."""
    repo = _lock_repository(tmp_path)
    data = (
        b'{"schema_version":"1.0","lock":"requirements/runtime.txt",'
        b'"distributions":[],"scorecard":null}'
    )
    if not linked:
        data += b" " * 131_072
    profile = tmp_path / "profile.json"
    profile.write_bytes(data)
    if linked:
        (tmp_path / "alias.json").hardlink_to(profile)
    output = tmp_path / "scan.json"
    assert (
        main(
            [
                "scan-provenance",
                "--root",
                str(repo.root),
                "--profile",
                str(profile),
                "--profile-sha256",
                sha256(data).hexdigest(),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert error in capsys.readouterr().err
    assert not output.exists()


def test_scan_refuses_changed_lock_and_duplicate_request(tmp_path: Path) -> None:
    """Keep the proof bound to a single staged release lock and distribution."""
    repo = _lock_repository(tmp_path)
    row = _distribution(predicate="https://docs.pypi.org/attestations/publish/v1")
    status, output = _cli(repo, tmp_path, [row, row])
    assert status == 2
    assert not output.exists()
    repo.write_bytes(
        "requirements/runtime.txt", f"cffi==2.1.1 --hash=sha256:{WHEEL_DIGEST}\n".encode()
    )
    status, output = _cli(repo, tmp_path, [row])
    assert status == 2
    assert not output.exists()


def test_scan_rejects_a_distribution_pin_in_lock_comments(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only actual requirements can authorise a distribution hash."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_bytes(
        "requirements/runtime.txt",
        f"--require-hashes\n# cffi==2.1.1 --hash=sha256:{WHEEL_DIGEST}\n".encode(),
    )
    repo.commit()
    row = _distribution(predicate="https://docs.pypi.org/attestations/publish/v1")
    status, output = _cli(repo, tmp_path, [row])
    assert status == 2
    assert "absent from the exact tracked hash lock" in capsys.readouterr().err
    assert not output.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact", "../outside.whl"),
        ("artifact", "/var/tmp/outside.whl"),
        ("artifact", "C:\\archive\\outside.whl"),
        ("sha256", "not-a-hash"),
        ("source_commit", "not-a-commit"),
        ("bundle", "evidence.json"),
        ("predicate", "https://slsa.dev/provenance/v1"),
    ],
)
def test_scan_rejects_invalid_distribution_profile(
    tmp_path: Path, field: str, value: object
) -> None:
    """Reject invalid operator inputs before consuming any retained evidence."""
    repo = _lock_repository(tmp_path)
    row = _distribution(predicate="https://docs.pypi.org/attestations/publish/v1")
    row[field] = value
    status, output = _cli(repo, tmp_path, [row])
    assert status == 2
    assert not output.exists()


@pytest.mark.parametrize(
    ("schema_version", "lock"),
    [("2.0", "requirements/runtime.txt"), ("1.0", "requirements/absent.txt")],
)
def test_scan_refuses_unsupported_or_untracked_profile(
    tmp_path: Path, schema_version: str, lock: str
) -> None:
    """Require a supported profile schema and an observed Git lock path."""
    repo = _lock_repository(tmp_path)
    status, output = _cli(repo, tmp_path, [], schema_version=schema_version, lock=lock)
    assert status == 2
    assert not output.exists()


@pytest.mark.parametrize("distributions", [{}, [None] * 257])
def test_scan_refuses_invalid_distribution_collection(
    tmp_path: Path, distributions: object
) -> None:
    """Enforce the collection bound before parsing or opening any evidence."""
    repo = _lock_repository(tmp_path)
    status, output = _cli(repo, tmp_path, distributions)
    assert status == 2
    assert not output.exists()


def test_provenance_rejects_other_observed_git_snapshot(tmp_path: Path) -> None:
    """Reject a genuine Git inventory that differs from the completed scan."""
    repo = _lock_repository(tmp_path)
    report = scan_repository(repo.root)
    repo.write_text("README.md", "# Changed after the scan\n")
    repo.commit("test: advance the observed snapshot")
    current = load_git_inventory(repo.root)
    with pytest.raises(ValueError, match="repository changed during provenance scan"):
        build_provenance_scan(report, current, tmp_path / "absent.json", "0" * 64)


def test_scan_does_not_replace_existing_output(tmp_path: Path) -> None:
    """Refuse to overwrite a previously accepted provenance record."""
    repo = _lock_repository(tmp_path)
    status, output = _cli(repo, tmp_path, [])
    assert status == 0
    original = output.read_bytes()
    row = _distribution(predicate="https://docs.pypi.org/attestations/publish/v1")
    status, output = _cli(repo, tmp_path, [row])
    assert status == 2
    assert output.read_bytes() == original


def test_scorecard_checks_are_bound_to_observed_source(tmp_path: Path) -> None:
    """Expose individual measurements only for the declared producer and Git revision."""
    repo = _lock_repository(tmp_path)
    head = repo.git_command("rev-parse", "HEAD").stdout.strip()
    repository = "github.com/example/qualification"
    version = "v5.6.0"
    path = tmp_path / "scorecard.json"
    data = json.dumps(
        {
            "repo": {"name": repository, "commit": head},
            "scorecard": {"version": version},
            "checks": [{"name": "Code-Review", "score": 7}, {"name": "Maintained", "score": -1}],
        }
    ).encode()
    path.write_bytes(data)
    selection: dict[str, object] = {
        "path": path.name,
        "sha256": sha256(data).hexdigest(),
        "repository": repository,
        "version": version,
    }
    status, output = _cli(repo, tmp_path, [], scorecard=selection)
    assert status == 0
    result = json.loads(output.read_bytes())["provenance"]["scorecard"]
    assert result == {
        "repository": repository,
        "head": head,
        "producer_version": version,
        "sha256": selection["sha256"],
        "checks": {"Code-Review": 7, "Maintained": None},
    }
    repo.write_text("README.md", "# Later revision\n")
    repo.commit("test: advance beyond the Scorecard measurement")
    output.unlink()
    status, output = _cli(repo, tmp_path, [], scorecard=selection)
    assert status == 2
    assert not output.exists()


@pytest.mark.parametrize(
    "invalid_checks",
    [
        {"invalid": 1},
        [{"name": "Code-Review", "score": True}],
        [{"name": "Code-Review", "score": 11}],
        [{"name": "Code-Review", "score": 0}, {"name": "Code-Review", "score": 0}],
    ],
)
def test_scorecard_requires_distinct_bounded_measurements(
    tmp_path: Path, invalid_checks: object
) -> None:
    """Reject incoherent upstream check rows at the public scan boundary."""
    repo = _lock_repository(tmp_path)
    # The local fixture provides real Git identity. Invalid observations test the parser.
    head = repo.git_command("rev-parse", "HEAD").stdout.strip()
    path = tmp_path / "scorecard.json"
    data = json.dumps(
        {
            "repo": {"name": "github.com/anulum/rigor-foundry", "commit": head},
            "scorecard": {"version": "v5.6.0"},
            "checks": invalid_checks,
        }
    ).encode()
    path.write_bytes(data)
    status, output = _cli(
        repo,
        tmp_path,
        [],
        scorecard={
            "path": path.name,
            "sha256": sha256(data).hexdigest(),
            "repository": "github.com/anulum/rigor-foundry",
            "version": "v5.6.0",
        },
    )
    assert status == 2
    assert not output.exists()
