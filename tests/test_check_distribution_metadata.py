# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Built distribution metadata truth guard tests
"""Exercise the metadata guard against real wheels built from the repository."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from zipfile import ZipFile

import pytest

from rigor_foundry import __version__
from tools.check_distribution_metadata import distribution_metadata_errors

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build one real wheel through the production packaging backend."""
    output = tmp_path_factory.mktemp("distribution-metadata")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(output),
        ],
        cwd=_REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    wheels = tuple(output.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def _rewrite_metadata(
    source: Path,
    destination: Path,
    transform: Callable[[str], str],
) -> Path:
    with ZipFile(source) as input_archive, ZipFile(destination, "w") as output_archive:
        metadata_count = 0
        for member in input_archive.infolist():
            content = input_archive.read(member)
            if member.filename.endswith(".dist-info/METADATA"):
                metadata_count += 1
                content = transform(content.decode("utf-8")).encode("utf-8")
            output_archive.writestr(member, content)
    assert metadata_count == 1
    return destination


def _rewrite_metadata_bytes(
    source: Path,
    destination: Path,
    transform: Callable[[bytes], bytes],
) -> Path:
    with ZipFile(source) as input_archive, ZipFile(destination, "w") as output_archive:
        metadata_count = 0
        for member in input_archive.infolist():
            content = input_archive.read(member)
            if member.filename.endswith(".dist-info/METADATA"):
                metadata_count += 1
                content = transform(content)
            output_archive.writestr(member, content)
    assert metadata_count == 1
    return destination


def _remove_metadata(source: Path, destination: Path) -> Path:
    with ZipFile(source) as input_archive, ZipFile(destination, "w") as output_archive:
        for member in input_archive.infolist():
            if not member.filename.endswith(".dist-info/METADATA"):
                output_archive.writestr(member, input_archive.read(member))
    return destination


def _duplicate_metadata(source: Path, destination: Path) -> Path:
    _rewrite_metadata(source, destination, lambda metadata: metadata)
    with ZipFile(source) as input_archive:
        metadata_name = next(
            name for name in input_archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = input_archive.read(metadata_name)
    with ZipFile(destination, "a") as output_archive:
        output_archive.writestr("duplicate.dist-info/METADATA", metadata)
    return destination


def _run_guard(wheel: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tools.check_distribution_metadata", str(wheel)],
        cwd=_REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_real_built_wheel_has_truthful_public_metadata(built_wheel: Path) -> None:
    """The actual release artefact binds version, registry, and installation."""
    assert distribution_metadata_errors(built_wheel) == []

    completed = _run_guard(built_wheel)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "Distribution metadata guard passed\n"
    assert completed.stderr == ""


def test_guard_rejects_pre_publication_status_in_real_wheel(
    built_wheel: Path,
    tmp_path: Path,
) -> None:
    """A real wheel cannot retain a status statement contradicted by upload."""

    def add_false_status(metadata: str) -> str:
        return metadata.replace(
            f'python -m pip install "rigor-foundry=={__version__}"',
            "RigorFoundry remains unreleased and is not published to PyPI.",
        )

    tampered = _rewrite_metadata(
        built_wheel,
        tmp_path / "false-status.whl",
        add_false_status,
    )
    completed = _run_guard(tampered)

    assert completed.returncode == 1
    assert "pre-publication status: not published to PyPI" in completed.stdout
    assert "pre-publication status: remains unreleased" in completed.stdout
    assert "missing exact install command" in completed.stdout
    assert completed.stderr == ""


@pytest.mark.parametrize(
    ("replacement", "expected_fragment"),
    [
        (
            "There is no valid `pip install rigor-foundry` instruction yet.",
            "pre-publication status: no valid pip installation",
        ),
        (
            "The repository has not been promoted, published to PyPI, or released.",
            "pre-publication status: unreleased publication list",
        ),
    ],
)
def test_guard_rejects_each_pre_publication_status_shape(
    built_wheel: Path,
    tmp_path: Path,
    replacement: str,
    expected_fragment: str,
) -> None:
    """Every known pre-publication status shape fails on a real wheel."""
    tampered = _rewrite_metadata(
        built_wheel,
        tmp_path / f"status-{len(replacement)}.whl",
        lambda metadata: metadata.replace(
            f'python -m pip install "rigor-foundry=={__version__}"',
            replacement,
        ),
    )

    errors = distribution_metadata_errors(tampered)
    assert any(expected_fragment in error for error in errors)


def test_guard_rejects_version_drift_in_real_wheel(
    built_wheel: Path,
    tmp_path: Path,
) -> None:
    """A wheel rebuilt from different metadata cannot pass the release gate."""
    tampered = _rewrite_metadata(
        built_wheel,
        tmp_path / "version-drift.whl",
        lambda metadata: metadata.replace(
            f"Version: {__version__}",
            "Version: 9.9.9",
            1,
        ),
    )

    assert distribution_metadata_errors(tampered) == [
        f"wheel Version does not match {__version__}"
    ]


def test_guard_rejects_missing_name_description_and_registry_link(
    built_wheel: Path,
    tmp_path: Path,
) -> None:
    """Required identity and long-description fields cannot disappear."""
    missing_name = _rewrite_metadata(
        built_wheel,
        tmp_path / "missing-name.whl",
        lambda metadata: metadata.replace("Name: rigor-foundry\n", "", 1),
    )
    assert "wheel Name does not match rigor-foundry" in distribution_metadata_errors(missing_name)

    no_description = _rewrite_metadata(
        built_wheel,
        tmp_path / "no-description.whl",
        lambda metadata: metadata.partition("\n\n")[0],
    )
    assert distribution_metadata_errors(no_description)[-1] == (
        "wheel METADATA has no long description"
    )

    missing_registry = _rewrite_metadata(
        built_wheel,
        tmp_path / "missing-registry.whl",
        lambda metadata: metadata.replace(
            "https://pypi.org/project/rigor-foundry/",
            "https://example.invalid/rigor-foundry/",
        ),
    )
    assert distribution_metadata_errors(missing_registry) == [
        "wheel description is missing public registry link: "
        "https://pypi.org/project/rigor-foundry/"
    ]


def test_guard_requires_one_utf8_metadata_member(
    built_wheel: Path,
    tmp_path: Path,
) -> None:
    """Missing, duplicate, and non-UTF-8 metadata fail closed."""
    missing = _remove_metadata(built_wheel, tmp_path / "missing-metadata.whl")
    assert distribution_metadata_errors(missing) == [
        "wheel must contain exactly one .dist-info/METADATA file, found 0"
    ]

    duplicate = _duplicate_metadata(built_wheel, tmp_path / "duplicate-metadata.whl")
    assert distribution_metadata_errors(duplicate) == [
        "wheel must contain exactly one .dist-info/METADATA file, found 2"
    ]

    invalid_utf8 = _rewrite_metadata_bytes(
        built_wheel,
        tmp_path / "invalid-utf8.whl",
        lambda _metadata: b"\xff",
    )
    assert distribution_metadata_errors(invalid_utf8)[0].startswith("wheel metadata is not UTF-8:")


@pytest.mark.parametrize(
    "configuration",
    [
        "name = 'missing-project'\n",
        "[project]\nversion = 1\n",
        "[project\n",
    ],
)
def test_guard_rejects_invalid_project_version_source(
    built_wheel: Path,
    tmp_path: Path,
    configuration: str,
) -> None:
    """Malformed or incomplete package metadata cannot authorise a wheel."""
    root = tmp_path / f"root-{len(configuration)}"
    root.mkdir()
    (root / "pyproject.toml").write_text(configuration, encoding="utf-8")

    assert distribution_metadata_errors(built_wheel, root=root)[0].startswith(
        "project version cannot be read:"
    )


def test_guard_rejects_missing_or_invalid_wheel(tmp_path: Path) -> None:
    """Missing arguments and malformed archives fail through the public CLI."""
    missing = subprocess.run(
        [sys.executable, "-m", "tools.check_distribution_metadata"],
        cwd=_REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert missing.returncode == 2
    assert missing.stdout == "usage: python -m tools.check_distribution_metadata <wheel>\n"

    nonexistent = tmp_path / "missing.whl"
    assert distribution_metadata_errors(nonexistent) == [f"wheel does not exist: {nonexistent}"]

    invalid_wheel = tmp_path / "invalid.whl"
    invalid_wheel.write_text("not a zip archive", encoding="utf-8")
    invalid = _run_guard(invalid_wheel)
    assert invalid.returncode == 1
    assert "wheel metadata cannot be read" in invalid.stdout
    assert invalid.stderr == ""
