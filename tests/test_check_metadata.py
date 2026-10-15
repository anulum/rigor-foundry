# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Distribution metadata guard tests
"""Verify package, citation, archive, and licence metadata agree."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tools._repository import ROOT
from tools.check_metadata import metadata_errors


def test_release_metadata_is_consistent_across_public_surfaces() -> None:
    """The production repository has one package identity and version."""
    assert metadata_errors() == []


def test_release_metadata_rejects_drift_in_the_version_owner(tmp_path: Path) -> None:
    """The public metadata guard binds releases to the single version module."""
    repository = tmp_path / "repository"
    for relative in (
        ".zenodo.json",
        "CITATION.cff",
        "LICENSE",
        "pyproject.toml",
        "src/rigor_foundry/version.py",
    ):
        source = ROOT / relative
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    version = repository / "src/rigor_foundry/version.py"
    version.write_text(
        version.read_text(encoding="utf-8").replace('"1.0.0"', '"1.0.1"'),
        encoding="utf-8",
    )

    assert metadata_errors(repository) == ["package version '1.0.1' does not match '1.0.0'"]


@pytest.fixture
def metadata_repository(tmp_path: Path) -> Path:
    """Copy the actual maintained metadata and CLI into an isolated repository."""
    repository = tmp_path / "repository"
    for relative in (
        ".zenodo.json",
        "CITATION.cff",
        "LICENSE",
        "pyproject.toml",
        "src/rigor_foundry/version.py",
        "tools/__init__.py",
        "tools/_repository.py",
        "tools/check_metadata.py",
    ):
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    return repository


@pytest.mark.parametrize(
    "source",
    (
        '__version__ = "1.0.0"\n',
        '"""Package version."""\n__version__ = "1.0.0"\n',
        '""""""\n# Release identity.\n__version__ = "1.0.0"\n',
    ),
)
def test_metadata_accepts_one_literal_version_owner(
    metadata_repository: Path, source: str
) -> None:
    """Optional documentation and comments do not change the release identity."""
    (metadata_repository / "src/rigor_foundry/version.py").write_text(source, encoding="utf-8")

    assert metadata_errors(metadata_repository) == []


@pytest.mark.parametrize(
    "source",
    (
        "",
        '"""Package version."""\n',
        '__version__ = "1.0.0"\n__version__ = "1.0.1"\n',
        '__version__ = "1.0.0"\n__version__ = "1.0.0"\n',
        '__version__: str = "1.0.0"\n',
        '__version__ = alias = "1.0.0"\n',
        '__version__, alias = "1.0.0", "1.0.0"\n',
        'alias = "1.0.0"\n',
        '__version__ = str("1.0.0")\n',
        "__version__ = 100\n",
        '__version__ = "1.0.0"\n__version__ += ".1"\n',
        'if True:\n    __version__ = "1.0.0"\n',
        '__version__ = "1.0.0"\nimport sys\n',
    ),
)
def test_metadata_rejects_ambiguous_or_nonliteral_version_owners(
    metadata_repository: Path, source: str
) -> None:
    """Only the documented static source form can establish package identity."""
    (metadata_repository / "src/rigor_foundry/version.py").write_text(source, encoding="utf-8")

    assert metadata_errors(metadata_repository) == ["package version None does not match '1.0.0'"]


def test_metadata_does_not_execute_version_source(metadata_repository: Path) -> None:
    """Static validation rejects an executable owner without creating its output."""
    sentinel = metadata_repository / "version-was-executed"
    source = (
        'from pathlib import Path\n__version__ = "1.0.0"\n'
        f"Path({str(sentinel)!r}).write_text('executed')\n"
    )
    (metadata_repository / "src/rigor_foundry/version.py").write_text(source, encoding="utf-8")

    assert metadata_errors(metadata_repository) == ["package version None does not match '1.0.0'"]
    assert not sentinel.exists()


@pytest.mark.parametrize(
    ("relative", "original", "replacement", "finding"),
    (
        (
            "pyproject.toml",
            'name = "rigor-foundry"',
            'name = "other-package"',
            "project.name is 'other-package', expected 'rigor-foundry'",
        ),
        (
            "pyproject.toml",
            'license = "Apache-2.0"',
            'license = "MIT"',
            "project.license is 'MIT', expected 'Apache-2.0'",
        ),
        (
            "pyproject.toml",
            'requires-python = ">=3.11"',
            'requires-python = ">=3.12"',
            "project.requires-python is '>=3.12', expected '>=3.11'",
        ),
        (
            "pyproject.toml",
            'Homepage = "https://github.com/anulum/rigor-foundry"',
            'Homepage = "https://example.org/other"',
            "project.urls.Homepage does not match the canonical repository",
        ),
        (
            "CITATION.cff",
            "version: 1.0.0",
            "version: 1.0.1",
            "CITATION.cff version does not match pyproject.toml",
        ),
        (
            "CITATION.cff",
            "license: Apache-2.0",
            "license: MIT",
            "CITATION.cff does not declare Apache-2.0",
        ),
        (
            "CITATION.cff",
            'repository-code: "https://github.com/anulum/rigor-foundry"',
            'repository-code: "https://example.org/other"',
            "CITATION.cff repository does not match the canonical repository",
        ),
        (
            "CITATION.cff",
            "license: Apache-2.0\n",
            "",
            "CITATION.cff does not declare Apache-2.0",
        ),
        (
            ".zenodo.json",
            '"version": "1.0.0"',
            '"version": "1.0.1"',
            ".zenodo.json version does not match pyproject.toml",
        ),
        (
            ".zenodo.json",
            '"license": "apache-2.0"',
            '"license": "mit"',
            ".zenodo.json does not declare the Zenodo Apache-2.0 identifier",
        ),
        (
            "LICENSE",
            "Apache License",
            "Different License",
            "LICENSE is not the canonical Apache-2.0 licence text",
        ),
        (
            "LICENSE",
            "Version 2.0",
            "Version 1.0",
            "LICENSE is not the canonical Apache-2.0 licence text",
        ),
    ),
)
def test_metadata_rejects_cross_file_identity_drift(
    metadata_repository: Path, relative: str, original: str, replacement: str, finding: str
) -> None:
    """Changing one actual release field produces its exact inconsistency."""
    path = metadata_repository / relative
    text = path.read_text(encoding="utf-8")
    assert original in text
    path.write_text(text.replace(original, replacement, 1), encoding="utf-8")

    assert metadata_errors(metadata_repository) == [finding]


@pytest.mark.parametrize("minor", ("3.11", "3.12", "3.13"))
def test_metadata_requires_each_supported_python_classifier(
    metadata_repository: Path, minor: str
) -> None:
    """No supported interpreter may disappear from the release classifiers."""
    path = metadata_repository / "pyproject.toml"
    classifier = f"Programming Language :: Python :: {minor}"
    path.write_text(
        path.read_text(encoding="utf-8").replace(f'    "{classifier}",\n', ""),
        encoding="utf-8",
    )

    assert metadata_errors(metadata_repository) == [f"missing classifier: {classifier}"]


@pytest.mark.parametrize("version", ('"1.0"', '"1.0.0rc1"', "100"))
def test_metadata_rejects_nonrelease_project_versions(
    metadata_repository: Path, version: str
) -> None:
    """Invalid project versions cannot agree accidentally with other surfaces."""
    path = metadata_repository / "pyproject.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace('version = "1.0.0"', f"version = {version}", 1),
        encoding="utf-8",
    )

    assert metadata_errors(metadata_repository) == [
        "project.version must be a three-component release version",
        "package version '1.0.0' does not match None",
        "CITATION.cff version does not match pyproject.toml",
        ".zenodo.json version does not match pyproject.toml",
    ]


@pytest.mark.parametrize("quote", ("", "'", '"'))
def test_metadata_accepts_citation_scalar_quoting(metadata_repository: Path, quote: str) -> None:
    """Citation release fields accept the supported unquoted or quoted scalars."""
    path = metadata_repository / "CITATION.cff"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "version: 1.0.0", f"version: {quote}1.0.0{quote}"
        ),
        encoding="utf-8",
    )

    assert metadata_errors(metadata_repository) == []


def test_metadata_cli_accepts_the_canonical_repository() -> None:
    """The actual enrolled module command succeeds with fixed process output."""
    completed = subprocess.run(
        [sys.executable, "-m", "tools.check_metadata"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0
    assert completed.stdout == "Metadata guard passed\n"
    assert completed.stderr == ""


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("version", "1.0.0"),
        ("version", "1.0.1"),
        ("license", "Apache-2.0"),
        ("license", "MIT"),
        ("repository-code", "https://github.com/anulum/rigor-foundry"),
        ("repository-code", "https://example.invalid/other"),
        ("title", "Other title"),
    ),
)
def test_metadata_rejects_duplicate_citation_fields(
    metadata_repository: Path, field: str, value: str
) -> None:
    """Repeated citation fields cannot select different release identities."""
    path = metadata_repository / "CITATION.cff"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(f"\n{field}: {value}\n")

    with pytest.raises(ValueError, match="field names must be unique"):
        metadata_errors(metadata_repository)


def test_metadata_rejects_equivalent_escaped_citation_keys(metadata_repository: Path) -> None:
    """YAML escaping cannot give a repeated version field a second spelling."""
    path = metadata_repository / "CITATION.cff"
    with path.open("a", encoding="utf-8") as stream:
        stream.write('\n"\\u0076ersion": 1.0.1\n')

    with pytest.raises(ValueError, match="field names must be unique"):
        metadata_errors(metadata_repository)


@pytest.mark.parametrize("style", ("comment", "escape", "block", "flow", "anchor"))
def test_metadata_accepts_equivalent_actual_citation_yaml(
    metadata_repository: Path, style: str
) -> None:
    """Real citation metadata keeps its identity across equivalent YAML forms."""
    path = metadata_repository / "CITATION.cff"
    original = path.read_text(encoding="utf-8")
    replacements = {
        "comment": "version: 1.0.0 # Release identity",
        "escape": 'version: "\\u0031.0.0"',
        "block": "version: >-\n  1.0.0",
        "anchor": "version: &release 1.0.0\nrelease-reference: *release",
    }
    if style == "flow":
        updated = yaml.safe_dump(
            yaml.safe_load(original), default_flow_style=True, allow_unicode=True
        )
    else:
        updated = original.replace("version: 1.0.0", replacements[style], 1)
    path.write_text(updated, encoding="utf-8")

    parsed = yaml.safe_load(updated)
    assert parsed["version"] == yaml.safe_load(original)["version"]
    assert metadata_errors(metadata_repository) == []


@pytest.mark.parametrize("state", ("empty", "sequence", "tag"))
def test_metadata_rejects_nonmapping_citation_documents(
    metadata_repository: Path, state: str
) -> None:
    """A citation document must have an ordinary mapping as its root."""
    path = metadata_repository / "CITATION.cff"
    original = path.read_text(encoding="utf-8")
    if state == "empty":
        updated = ""
    elif state == "sequence":
        updated = "-\n" + "\n".join("  " + line for line in original.splitlines()) + "\n"
    else:
        updated = "!citation\n" + original
    path.write_text(updated, encoding="utf-8")

    with pytest.raises(ValueError, match="must contain a YAML mapping"):
        metadata_errors(metadata_repository)


@pytest.mark.parametrize("key", ("? [version]\n:", "100:"))
def test_metadata_rejects_nonstring_citation_keys(metadata_repository: Path, key: str) -> None:
    """Structured or numeric field names cannot declare release identity."""
    path = metadata_repository / "CITATION.cff"
    path.write_text(
        path.read_text(encoding="utf-8").replace("\nversion:", f"\n{key}", 1), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="field names must be strings"):
        metadata_errors(metadata_repository)


@pytest.mark.parametrize(
    "value", ("[1.0.0]", "{value: 1.0.0}", "true", "100", "null", "!release 1.0.0")
)
def test_metadata_rejects_nonstring_citation_identity(
    metadata_repository: Path, value: str
) -> None:
    """Collections, typed values and custom tags cannot alias a version string."""
    path = metadata_repository / "CITATION.cff"
    path.write_text(
        path.read_text(encoding="utf-8").replace("version: 1.0.0", f"version: {value}", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="identity fields must be strings"):
        metadata_errors(metadata_repository)


@pytest.mark.parametrize("state", ("quoted-suffix", "syntax", "multiple-documents"))
def test_metadata_rejects_malformed_citation_yaml(metadata_repository: Path, state: str) -> None:
    """Syntax errors and multiple documents cannot supply one citation identity."""
    path = metadata_repository / "CITATION.cff"
    original = path.read_text(encoding="utf-8")
    if state == "quoted-suffix":
        updated = original.replace("version: 1.0.0", 'version: "1.0.0"suffix', 1)
    elif state == "syntax":
        updated = original.replace("version: 1.0.0", "version: [1.0.0", 1)
    else:
        updated = original + "\n---\n" + original
    path.write_text(updated, encoding="utf-8")

    with pytest.raises(yaml.YAMLError):
        metadata_errors(metadata_repository)


@pytest.mark.parametrize(
    "state",
    (
        "valid",
        "duplicate-version",
        "syntax",
        "toml",
        "json",
        "missing",
        "duplicate-citation",
        "invalid-citation",
        "typed-citation",
    ),
)
def test_metadata_cli_validates_copied_actual_metadata(
    metadata_repository: Path, state: str
) -> None:
    """Real module processes reject drift and unreadable or malformed inputs."""
    version = metadata_repository / "src/rigor_foundry/version.py"
    if state == "duplicate-version":
        with version.open("a", encoding="utf-8") as stream:
            stream.write('\n__version__ = "1.0.1"\n')
    elif state == "syntax":
        version.write_text("__version__ = (\n", encoding="utf-8")
    elif state == "toml":
        (metadata_repository / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    elif state == "json":
        (metadata_repository / ".zenodo.json").write_text("{\n", encoding="utf-8")
    elif state == "missing":
        (metadata_repository / "CITATION.cff").unlink()
    elif state == "duplicate-citation":
        with (metadata_repository / "CITATION.cff").open("a", encoding="utf-8") as stream:
            stream.write("\nversion: 1.0.1\n")
    elif state == "invalid-citation":
        path = metadata_repository / "CITATION.cff"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "version: 1.0.0", 'version: "1.0.0"suffix', 1
            ),
            encoding="utf-8",
        )
    elif state == "typed-citation":
        path = metadata_repository / "CITATION.cff"
        path.write_text(
            path.read_text(encoding="utf-8").replace("version: 1.0.0", "version: [1.0.0]", 1),
            encoding="utf-8",
        )
    completed = subprocess.run(
        [sys.executable, "-m", "tools.check_metadata"],
        cwd=metadata_repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == (0 if state == "valid" else 1)
    assert completed.stdout == (
        "Metadata guard passed\n"
        if state == "valid"
        else "Metadata guard failed; finding details are redacted from process output.\n"
    )
    assert completed.stderr == ""
