# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Redaction-safe secret guard tests
"""Verify secret reporting never returns candidate credential values."""

from __future__ import annotations

import gzip
import hashlib
import io
import runpy
import subprocess
import tarfile
from pathlib import Path

import pytest

from tools._repository import read_text
from tools.check_secrets import main, secret_errors

ROOT = Path(__file__).resolve().parents[1]


def _initialize_repository(root: Path) -> None:
    """Create a repository whose visible-file inventory can be audited."""
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(root)],
        check=True,
        capture_output=True,
        text=True,
    )


def _path_digest(path: str) -> str:
    """Return the production-compatible opaque path identifier."""
    return hashlib.sha256(path.encode("utf-8")).hexdigest()


def _private_key_marker() -> str:
    """Build a private-key marker without embedding it in repository source."""
    return "-----BEGIN " + "OPENSSH PRIVATE KEY-----"


def _aws_access_key() -> str:
    """Build an AWS-shaped test value without embedding it in repository source."""
    return "AKIA" + "ABCDEFGHIJKLMNOP"


def _credential_url() -> str:
    """Build a credential URL without embedding it in repository source."""
    return "https://" + "operator:credential-value@" + "invalid.test"


def test_secret_guard_redacts_value_and_raw_path(tmp_path: Path) -> None:
    """Secret findings expose only an opaque path digest, line, and rule."""
    _initialize_repository(tmp_path)
    value = "deliberately" + "-sensitive-value"
    (tmp_path / "settings.toml").write_text(f'password = "{value}"\n', encoding="utf-8")
    errors = secret_errors(tmp_path)
    joined = "\n".join(errors)

    assert errors == [f"path-sha256:{_path_digest('settings.toml')}:1: credential-assignment"]
    assert value not in joined
    assert "settings.toml" not in joined


@pytest.mark.parametrize(
    ("content", "rule_id"),
    [
        (_private_key_marker(), "private-key"),
        (_aws_access_key(), "aws-access-key"),
        (_credential_url(), "credential-url"),
        ("password = " + '"credential-value"', "credential-assignment"),
    ],
)
def test_secret_guard_covers_every_rule(
    tmp_path: Path,
    content: str,
    rule_id: str,
) -> None:
    """Every credential rule emits the same redacted location contract."""
    _initialize_repository(tmp_path)
    (tmp_path / "candidate.txt").write_text(content, encoding="utf-8")

    assert secret_errors(tmp_path) == [f"path-sha256:{_path_digest('candidate.txt')}:1: {rule_id}"]


@pytest.mark.parametrize(
    "marker",
    [
        "${{ secrets.REFERENCE }}",
        "${REFERENCE}",
        "$ENV",
        "secret-provider",
        "example",
        "redacted",
    ],
)
def test_reference_markers_are_not_treated_as_values(tmp_path: Path, marker: str) -> None:
    """Provider, environment, example, and redaction markers remain references."""
    _initialize_repository(tmp_path)
    (tmp_path / "workflow.yml").write_text(
        f"{_aws_access_key()} # {marker}\n",
        encoding="utf-8",
    )

    assert secret_errors(tmp_path) == []


def test_secret_guard_skips_its_rules_assets_and_binary_files(tmp_path: Path) -> None:
    """Rule definitions, documentation assets, and binary files are not scanned."""
    _initialize_repository(tmp_path)
    (tmp_path / ".gitleaks.toml").write_text(_aws_access_key(), encoding="utf-8")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "check_secrets.py").write_text(
        _aws_access_key(),
        encoding="utf-8",
    )
    (tmp_path / "docs" / "assets").mkdir(parents=True)
    (tmp_path / "docs" / "assets" / "fixture.txt").write_text(
        _aws_access_key(),
        encoding="utf-8",
    )
    (tmp_path / "binary.dat").write_bytes(_aws_access_key().encode("ascii") + b"\0")

    assert secret_errors(tmp_path) == []


def test_secret_guard_reports_multiline_line_number_without_trailing_newline(
    tmp_path: Path,
) -> None:
    """The final unterminated line retains its deterministic line number."""
    _initialize_repository(tmp_path)
    (tmp_path / "settings.toml").write_text(
        "safe = true\npassword = credential-value",
        encoding="utf-8",
    )

    assert secret_errors(tmp_path) == [
        f"path-sha256:{_path_digest('settings.toml')}:2: credential-assignment"
    ]


def test_empty_yaml_credential_input_does_not_consume_next_field(tmp_path: Path) -> None:
    """An empty action input cannot absorb a following metadata line as its value."""
    _initialize_repository(tmp_path)
    (tmp_path / "action.yml").write_text(
        "inputs:\n"
        "  password:\n"
        "    description: Package-index password or API token.\n"
        "    required: false\n",
        encoding="utf-8",
    )

    assert secret_errors(tmp_path) == []


def test_secret_guard_cli_redacts_all_finding_details(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI failure output contains no repository-derived path or value."""
    _initialize_repository(tmp_path)
    value = "credential-value"
    (tmp_path / "sensitive-name.txt").write_text(
        f"password = {value}",
        encoding="utf-8",
    )

    assert main(tmp_path) == 1
    output = capsys.readouterr()
    assert output.out == (
        "Secret guard failed; finding details are redacted from process output.\n"
    )
    assert output.err == ""
    assert value not in output.out
    assert "sensitive-name.txt" not in output.out


def test_secret_guard_cli_reports_success(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI success remains explicit and deterministic."""
    _initialize_repository(tmp_path)
    (tmp_path / "safe.txt").write_text("safe = true\n", encoding="utf-8")

    assert main(tmp_path) == 0
    output = capsys.readouterr()
    assert output.out == "Secret guard passed\n"
    assert output.err == ""


def test_secret_guard_module_entrypoint(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The real module entrypoint propagates the deterministic success code."""
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(
            str(Path(__file__).resolve().parents[1] / "tools" / "check_secrets.py"),
            run_name="__main__",
        )

    assert raised.value.code == 0
    output = capsys.readouterr()
    assert output.out == "Secret guard passed\n"
    assert output.err == ""


def _tracked_gzip_fixtures() -> list[Path]:
    """Return every tracked gzip file, exactly as Git lists it."""
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.gz"], cwd=ROOT, check=True, capture_output=True
    ).stdout
    return [Path(name) for name in listed.decode("utf-8").split("\0") if name]


def _materialise(source: Path, relative: Path, root: Path) -> list[Path]:
    """Write one gzip file's decompressed bytes, or each member of its tar, under ``root``.

    Parameters
    ----------
    source : Path
        The gzip file to read.
    relative : Path
        Its repository-relative path, which names the written target.
    root : Path
        The repository receiving the decompressed content.

    Returns
    -------
    list[Path]
        Every written file, relative to ``root``.
    """
    payload = gzip.decompress(source.read_bytes())
    target = relative.with_suffix("")
    if relative.name.endswith(".tar.gz"):
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            archive.extractall(root / target, members=members, filter="data")
        return [target / member.name for member in members]
    (root / target).parent.mkdir(parents=True, exist_ok=True)
    (root / target).write_bytes(payload)
    return [target]


def test_compressed_fixtures_are_scanned_as_their_decompressed_bytes(tmp_path: Path) -> None:
    """The guard reads text only, so every tracked gzip and tar member is scanned decompressed.

    Parameters
    ----------
    tmp_path : Path
        Repository receiving the decompressed fixtures.
    """
    fixtures = _tracked_gzip_fixtures()
    assert {
        Path("tests/fixtures/provenance/sampleproject-4.0.0.tar.gz"),
        Path("tests/fixtures/sarif_import/codeql-2.26.0-actions-analysis-1496041210.sarif.gz"),
        Path("tests/fixtures/sarif_import/codeql-2.27.2-actions-analysis-2237134604.sarif.gz"),
    } <= set(fixtures)
    _initialize_repository(tmp_path)
    written = [
        path for fixture in fixtures for path in _materialise(ROOT / fixture, fixture, tmp_path)
    ]
    assert len(written) > len(fixtures)
    assert all(read_text(path, tmp_path) is not None for path in written)
    assert secret_errors(tmp_path) == []


def test_a_secret_inside_a_gzip_file_or_a_tar_member_is_found(tmp_path: Path) -> None:
    """A value planted through the same gzip and tar route is reported for each file.

    Parameters
    ----------
    tmp_path : Path
        Owned allocation for the planted archives and the scanned repository.
    """
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "planted.sarif.gz").write_bytes(gzip.compress(_aws_access_key().encode()))
    member = io.BytesIO()
    with tarfile.open(fileobj=member, mode="w") as archive:
        data = _aws_access_key().encode()
        info = tarfile.TarInfo("package/settings.txt")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    (sources / "planted.tar.gz").write_bytes(gzip.compress(member.getvalue()))
    repository = tmp_path / "repository"
    _initialize_repository(repository)
    written = [
        path
        for name in ("planted.sarif.gz", "planted.tar.gz")
        for path in _materialise(sources / name, Path("fixtures") / name, repository)
    ]
    assert sorted(path.as_posix() for path in written) == [
        "fixtures/planted.sarif",
        "fixtures/planted.tar/package/settings.txt",
    ]
    assert secret_errors(repository) == sorted(
        f"path-sha256:{_path_digest(path.as_posix())}:1: aws-access-key" for path in written
    )
