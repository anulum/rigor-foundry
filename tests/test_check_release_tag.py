# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Release tag guard tests
"""Verify tag and package version equality."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.check_release_tag import main, release_tag_errors

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _run_release_guard(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the public guard without site packages or source-path injection."""
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, "-S", "-m", "tools.check_release_tag", *arguments],
        cwd=_REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_release_tag_matches_the_single_package_version() -> None:
    """Release automation rejects aliases and metadata drift."""
    assert release_tag_errors("v1.0.0") == []
    assert release_tag_errors("1.0.0") == ["release tag '1.0.0' does not match 'v1.0.0'"]


def test_release_tag_cli_runs_before_package_installation() -> None:
    """The workflow guard runs without site packages or source-path injection."""
    completed = _run_release_guard("v1.0.0")

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "Release tag guard passed\n"
    assert completed.stderr == ""


def test_release_tag_module_entrypoint_executes() -> None:
    """The public module entry point delegates to the validated CLI boundary."""
    completed = subprocess.run(
        [sys.executable, "-m", "tools.check_release_tag", "v1.0.0"],
        cwd=_REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "Release tag guard passed\n"
    assert completed.stderr == ""


@pytest.mark.parametrize(
    ("arguments", "expected_code", "expected_output"),
    [
        ((), 2, "usage: python -m tools.check_release_tag <tag>\n"),
        (
            ("v9.9.9",),
            1,
            "release tag 'v9.9.9' does not match 'v1.0.0'\n",
        ),
    ],
)
def test_release_tag_cli_rejects_invalid_invocations(
    arguments: tuple[str, ...],
    expected_code: int,
    expected_output: str,
) -> None:
    """The public CLI rejects missing arguments and version mismatches."""
    completed = _run_release_guard(*arguments)

    assert completed.returncode == expected_code
    assert completed.stdout == expected_output
    assert completed.stderr == ""


@pytest.mark.parametrize(
    ("arguments", "expected_code", "expected_output"),
    [
        ([], 2, "usage: python -m tools.check_release_tag <tag>\n"),
        (["v9.9.9"], 1, "release tag 'v9.9.9' does not match 'v1.0.0'\n"),
        (["v1.0.0"], 0, "Release tag guard passed\n"),
    ],
)
def test_release_tag_main_reports_each_public_outcome(
    arguments: list[str],
    expected_code: int,
    expected_output: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The callable CLI boundary reports usage, mismatch, and success."""
    assert main(arguments) == expected_code
    assert capsys.readouterr() == (expected_output, "")


@pytest.fixture
def release_repository(tmp_path: Path) -> Path:
    """Copy the actual standalone guard and complete manifest into a repository."""
    root = tmp_path / "repository"
    (root / "tools").mkdir(parents=True)
    for name in ("tools/__init__.py", "tools/check_release_tag.py", "pyproject.toml"):
        destination = root / name
        destination.write_bytes((_REPOSITORY_ROOT / name).read_bytes())
    return root


def _replace_release_version(root: Path, value: str | None) -> None:
    """Change only the actual project-version declaration in the copied manifest."""
    manifest = root / "pyproject.toml"
    original = manifest.read_text(encoding="utf-8")
    declaration = 'version = "1.0.0"'
    assert original.count(declaration) == 1
    replacement = "" if value is None else f"version = {value}"
    manifest.write_text(original.replace(declaration, replacement, 1), encoding="utf-8")


@pytest.mark.parametrize(
    ("literal", "tag"),
    [
        ('"1.0.0"', "v1.0.0"),
        ('"0.0.0"', "v0.0.0"),
        ('"12.34.567"', "v12.34.567"),
        ('"\\u0031.0.0"', "v1.0.0"),
    ],
)
def test_release_tag_accepts_valid_declared_versions(
    release_repository: Path, literal: str, tag: str
) -> None:
    """Compare parsed release strings exactly, including valid TOML escapes."""
    _replace_release_version(release_repository, literal)
    assert release_tag_errors(tag, release_repository) == []
    assert release_tag_errors(tag + "-other", release_repository) == [
        f"release tag {tag + '-other'!r} does not match {tag!r}"
    ]


@pytest.mark.parametrize(
    ("literal", "tag"),
    [
        ("true", "vTrue"),
        ("7", "v7"),
        ("7.0", "v7.0"),
        ("[1, 0, 0]", "v[1, 0, 0]"),
        ("{major = 1}", "v{'major': 1}"),
        ("2026-10-15", "v2026-10-15"),
        ('""', "v"),
        ('"release-candidate"', "vrelease-candidate"),
        ('"1.0"', "v1.0"),
        ('"1.0.0rc1"', "v1.0.0rc1"),
        ('"1.0.0+local"', "v1.0.0+local"),
        ('"1.0.0\\n"', "v1.0.0\n"),
        (None, "vNone"),
    ],
)
def test_release_tag_rejects_invalid_declared_versions(
    release_repository: Path, literal: str | None, tag: str
) -> None:
    """Refuse invalid version values even when their text matches the tag."""
    _replace_release_version(release_repository, literal)
    assert release_tag_errors(tag, release_repository) == [
        "project.version must be a three-component release version"
    ]


@pytest.mark.parametrize("project", [None, "true", '"release"', "7", "[]"])
def test_release_tag_requires_a_project_table(
    release_repository: Path, project: str | None
) -> None:
    """Retain the full manifest while refusing missing or non-table projects."""
    manifest = release_repository / "pyproject.toml"
    original = manifest.read_text(encoding="utf-8")
    retained = original.replace("[project", "[retained-project")
    prefix = "" if project is None else f"project = {project}\n"
    manifest.write_text(prefix + retained, encoding="utf-8")
    assert release_tag_errors("v1.0.0", release_repository) == [
        "project.version must be a three-component release version"
    ]


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("missing", FileNotFoundError),
        ("directory", IsADirectoryError),
        ("syntax", ValueError),
        ("encoding", ValueError),
    ],
)
def test_release_tag_api_preserves_manifest_read_errors(
    release_repository: Path, state: str, expected: type[Exception]
) -> None:
    """Expose read and parse errors to trusted API callers without executing code."""
    manifest = release_repository / "pyproject.toml"
    if state == "missing":
        manifest.unlink()
    elif state == "directory":
        manifest.unlink()
        manifest.mkdir()
    elif state == "syntax":
        manifest.write_bytes(manifest.read_bytes() + b"\ninvalid = [\n")
    else:
        manifest.write_bytes(manifest.read_bytes() + b"\n# \xff\n")
    with pytest.raises(expected):
        release_tag_errors("v1.0.0", release_repository)


@pytest.mark.parametrize("without_site_packages", [False, True])
@pytest.mark.parametrize(
    ("state", "arguments", "code", "output"),
    [
        ("valid", ("v1.0.0",), 0, "Release tag guard passed\n"),
        ("mismatch", ("v9.9.9",), 1, "release tag 'v9.9.9' does not match 'v1.0.0'\n"),
        ("valid", (), 2, "usage: python -m tools.check_release_tag <tag>\n"),
        (
            "valid",
            ("v1.0.0", "extra"),
            2,
            "usage: python -m tools.check_release_tag <tag>\n",
        ),
        (
            "boolean",
            ("vTrue",),
            1,
            "project.version must be a three-component release version\n",
        ),
        (
            "nonrelease",
            ("vrelease-candidate",),
            1,
            "project.version must be a three-component release version\n",
        ),
        (
            "missing-version",
            ("vNone",),
            1,
            "project.version must be a three-component release version\n",
        ),
        (
            "missing",
            ("v1.0.0",),
            1,
            "Release tag guard failed; project metadata is unavailable or invalid.\n",
        ),
        (
            "directory",
            ("v1.0.0",),
            1,
            "Release tag guard failed; project metadata is unavailable or invalid.\n",
        ),
        (
            "syntax",
            ("v1.0.0",),
            1,
            "Release tag guard failed; project metadata is unavailable or invalid.\n",
        ),
        (
            "encoding",
            ("v1.0.0",),
            1,
            "Release tag guard failed; project metadata is unavailable or invalid.\n",
        ),
    ],
)
def test_repository_guard_clis_validate_release_tag(
    release_repository: Path,
    state: str,
    arguments: tuple[str, ...],
    code: int,
    output: str,
    without_site_packages: bool,
) -> None:
    """Run the actual copied module with normal and dependency-free interpreters."""
    manifest = release_repository / "pyproject.toml"
    if state == "boolean":
        _replace_release_version(release_repository, "true")
    elif state == "nonrelease":
        _replace_release_version(release_repository, '"release-candidate"')
    elif state == "missing-version":
        _replace_release_version(release_repository, None)
    elif state == "missing":
        manifest.unlink()
    elif state == "directory":
        manifest.unlink()
        manifest.mkdir()
    elif state == "syntax":
        manifest.write_bytes(manifest.read_bytes() + b"\ninvalid = [\n")
    elif state == "encoding":
        manifest.write_bytes(manifest.read_bytes() + b"\n# \xff\n")
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    options = ["-S"] if without_site_packages else []
    completed = subprocess.run(
        [sys.executable, *options, "-m", "tools.check_release_tag", *arguments],
        cwd=release_repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (completed.returncode, completed.stdout, completed.stderr) == (code, output, "")


@pytest.mark.parametrize("workflow", ["release.yml", "docker.yml", "publish.yml"])
@pytest.mark.parametrize("tag", ["v1.0.0", "v9.9.9"])
def test_repository_guard_clis_replay_release_workflow(
    release_repository: Path, workflow: str, tag: str
) -> None:
    """Replay each real workflow's tag command before a later-step marker."""
    text = (_REPOSITORY_ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
    commands = [
        command
        for line in text.splitlines()
        if (command := line.strip().removeprefix("run: ")).startswith(
            "python -m tools.check_release_tag "
        )
    ]
    assert len(commands) == 1
    command = commands[0]
    next_step = "name: Install verified Buildx" if workflow == "docker.yml" else "python -m build"
    assert text.index(command) < text.index(next_step)
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment["PATH"]
    environment["GITHUB_REF_NAME"] = tag
    environment["RELEASE_TAG"] = tag
    completed = subprocess.run(
        ["/bin/bash", "-c", "set -euo pipefail\n" + command + "\nprintf done > later-step\n"],
        cwd=release_repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if tag == "v1.0.0":
        assert (completed.returncode, completed.stdout, completed.stderr) == (
            0,
            "Release tag guard passed\n",
            "",
        )
        assert (release_repository / "later-step").read_text() == "done"
    else:
        assert (completed.returncode, completed.stdout, completed.stderr) == (
            1,
            "release tag 'v9.9.9' does not match 'v1.0.0'\n",
            "",
        )
        assert not (release_repository / "later-step").exists()
