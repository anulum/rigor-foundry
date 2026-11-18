# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Reproducible packaging contract tests
"""Verify release inputs and resource-bounded preflight composition."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest
from packaging.utils import canonicalize_name

from rigor_foundry.version import __version__
from tools._repository import ROOT
from tools.ci_workflows import ci_jobs, read_workflow


def test_private_memory_has_portable_repository_exclusions() -> None:
    """Clones and local Docker contexts retain the private-memory boundary."""
    assert "/agentic_project_memory/" in (ROOT / ".gitignore").read_text().splitlines()
    assert "agentic_project_memory" in (ROOT / ".dockerignore").read_text().splitlines()


@pytest.mark.parametrize("distribution", ["wheel", "sdist"])
def test_distribution_build_excludes_real_private_memory(
    tmp_path: Path, distribution: str
) -> None:
    """Actual Hatch archives omit a private canary but retain the public CLI.

    Parameters
    ----------
    tmp_path : Path
        Independent repository and actual archive output directory.
    distribution : str
        Actual wheel or source distribution to build.
    """
    repository = tmp_path / "repository"
    repository.mkdir()
    inventory = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
        timeout=10,
    )
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text())
    included = configuration["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    roots = {entry.lstrip("/") for entry in included}
    for raw in inventory.stdout.split(b"\0")[:-1]:
        relative = Path(raw.decode())
        if relative.parts[0] in roots:
            target = repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
    shutil.copyfile(ROOT / ".gitignore", repository / ".gitignore")
    private = repository / "agentic_project_memory"
    private.mkdir(mode=0o700)
    marker = b"private-memory-distribution-regression-canary\n"
    record = private / "memory_index.md"
    record.write_bytes(marker)
    record.chmod(0o600)
    output = tmp_path / "distributions"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            f"--{distribution}",
            "--no-isolation",
            "--outdir",
            str(output),
            str(repository),
        ],
        capture_output=True,
        check=True,
        timeout=60,
    )
    archives = list(output.iterdir())
    assert len(archives) == 1
    if distribution == "wheel":
        with zipfile.ZipFile(archives[0]) as wheel:
            contents = {name: wheel.read(name) for name in wheel.namelist()}
    else:
        with tarfile.open(archives[0], "r:gz") as sdist:
            contents = {}
            for member in sdist.getmembers():
                assert member.isfile()
                stream = sdist.extractfile(member)
                assert stream is not None
                with stream:
                    contents[member.name] = stream.read()
    assert any(name.endswith("rigor_foundry/cli.py") for name in contents)
    assert all("agentic_project_memory" not in Path(name).parts for name in contents)
    assert all(marker not in payload for payload in contents.values())
    assert record.read_bytes() == marker


def test_build_backend_and_base_image_are_immutable() -> None:
    """Distribution and container builders use exact immutable inputs."""
    with (ROOT / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)
    assert project["build-system"]["requires"] == [
        "hatchling==1.32.4",
        "packaging==26.3",
        "pathspec==1.1.1",
        "pluggy==1.6.0",
        "trove-classifiers==2026.9.21.13",
    ]
    assert project["project"]["license"] == "Apache-2.0"
    assert project["project"]["license-files"] == ["LICENSE", "NOTICE"]
    assert project["project"]["version"] == __version__
    assert project["project"]["scripts"] == {"rigor": "rigor_foundry.cli:main"}
    assert (
        "/coverage-residuals.json"
        in project["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    )

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    bases = re.findall(r"^FROM\s+([^\s]+)", dockerfile, re.MULTILINE)
    assert len(bases) == 2
    assert all("@sha256:" in base for base in bases)
    assert "snapshot.debian.org/archive/debian/20261029T000000Z" in dockerfile
    assert "snapshot.debian.org/archive/debian-security/20261118T000000Z" in dockerfile
    assert "USER rigor" in dockerfile
    assert "COPY requirements/bootstrap.txt requirements/bootstrap.txt" in dockerfile
    assert (
        "--require-hashes --only-binary=:all: --no-build-isolation -r /tmp/runtime.txt"
        in dockerfile
    )

    assert dockerfile.count("--no-compile") == 2
    assert "--invalidation-mode checked-hash /usr/local/lib/python3.12/site-packages" in dockerfile
    assert "chage --lastday -1 rigor" in dockerfile
    assert "/var/cache/ldconfig/aux-cache" in dockerfile
    assert "/var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log" in dockerfile


def test_hash_locks_cover_each_resolved_distribution() -> None:
    """Every non-comment lock entry carries at least one SHA-256 hash."""
    for name in (
        "bootstrap.txt",
        "build.txt",
        "ci.txt",
        "runtime.txt",
        "security.txt",
        "test.txt",
    ):
        text = (ROOT / "requirements" / name).read_text(encoding="utf-8")
        entries = re.split(r"\n(?=[a-zA-Z0-9])", text)
        resolved = [entry for entry in entries if "==" in entry]
        assert resolved, name
        assert all("--hash=sha256:" in entry for entry in resolved), name


def test_ci_lock_covers_python311_conditional_dependencies() -> None:
    """The oldest CI interpreter can install its complete hash-locked graph."""
    lock = (ROOT / "requirements/ci.txt").read_text(encoding="utf-8")
    assert 'backports-tarfile==1.2.0 ; python_version < "3.12"' in lock
    for name in ("backports-tarfile", "importlib-metadata", "zipp"):
        assert re.search(rf"^{name}==[^\n]+\\\n\s+--hash=sha256:", lock, re.MULTILINE)


def test_hash_locks_share_one_version_per_distribution() -> None:
    """Combined CI, test, runtime, security and native installs cannot disagree."""
    versions: dict[str, tuple[str, str]] = {}
    for lock_name in (
        "bootstrap.txt",
        "build.txt",
        "ci.txt",
        "test.txt",
        "runtime.txt",
        "security.txt",
        "native.txt",
    ):
        lock = (ROOT / "requirements" / lock_name).read_text(encoding="utf-8")
        for name, version in re.findall(r"^([\w.-]+)==([^\s;\\]+)", lock, re.MULTILINE):
            key = canonicalize_name(name)
            previous = versions.setdefault(key, (version, lock_name))
            assert previous[0] == version, (key, previous, (version, lock_name))


def test_container_scan_uses_repository_verified_trivy() -> None:
    """Container CI executes the digest-bound Trivy installer, not its download action."""
    workflow = (ROOT / ".github/workflows/docker.yml").read_text(encoding="utf-8")
    assert "python3 -m tools.install_trivy" in workflow
    assert '"$RUNNER_TEMP/trivy" image' in workflow
    assert "aquasecurity/trivy-action@" not in workflow
    assert "python3 -m tools.install_buildx" in workflow
    assert "docker/setup-buildx-action@" not in workflow
    assert (
        "moby/buildkit@sha256:"
        "2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec" in workflow
    )


def test_ci_grants_user_namespaces_only_to_bubblewrap() -> None:
    """Ubuntu CI keeps global mediation and grants only the bwrap user namespace."""
    jobs = ci_jobs(ROOT)
    workflow = "\n".join(
        step.get("run", "") for job in jobs.values() for step in job.get("steps", [])
    )
    assert "/tmp/rigor-wheel/bin/rigor --version" in workflow
    assert "public_api_contract_errors(package.__all__, vars(package)) == ()" in workflow
    assert 'public_api_manifest()["schema_version"] == "1.1"' in workflow
    assert "cd /tmp/rigor-source-e2e" in workflow
    assert "/tmp/rigor-wheel/bin/rigor source-capture" in workflow
    assert "/tmp/rigor-wheel/bin/rigor source-verify" in workflow
    assert "SourceVerification.from_dict" in workflow
    assert "verification.verified_value is True" in workflow
    assert "/tmp/rigor-wheel/bin/rigor bootstrap --root ." in workflow
    assert 'git commit -m "test: track installed-wheel adopter policy"' in workflow
    assert "/tmp/rigor-wheel/bin/rigor cra-bootstrap --root ." in workflow
    assert "/tmp/rigor-wheel/bin/rigor sbom-import --root ." in workflow
    assert "/tmp/rigor-wheel/bin/rigor sbom-status --root ." in workflow
    assert 'document["drift"]["drifted"] is False' in workflow
    assert "/tmp/rigor-wheel/bin/rigor scan --root ." in workflow
    assert "/tmp/rigor-wheel/bin/rigor sarif --report /tmp/rigor-adopter-report.json" in workflow
    assert 'document["version"] == "2.1.0"' in workflow
    assert "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e" in workflow
    assert "Draft4Validator(schema).validate(document)" in workflow
    assert "stat -c '%a' docs/internal/TODO.md" in workflow
    assert "test ! -e docs/internal/reviews.json" in workflow
    assert set(jobs) == {
        "quality",
        "native",
        "native-primary",
        "native-quality",
        "test",
        "test-coverage",
        "coverage",
        "distribution",
        "vscode",
        "vscode-native",
        "vscode-host",
    }
    assert all(
        job["runs-on"] == "ubuntu-24.04"
        for name, job in jobs.items()
        if name not in {"native", "native-primary", "vscode-native", "vscode-host"}
    )
    assert jobs["native-primary"]["runs-on"] == "windows-latest"
    assert jobs["native"]["runs-on"] == "${{ matrix.runner }}"
    assert jobs["vscode-native"]["runs-on"] == "windows-2025"
    assert jobs["vscode-host"]["runs-on"] == "${{ matrix.runner }}"
    host_profiles = json.loads((ROOT / "editors/vscode/native/editor-hosts.json").read_text())
    assert jobs["vscode-host"]["strategy"]["matrix"]["include"] == host_profiles["profiles"]
    assert workflow.count("profile bwrap /usr/bin/bwrap flags=(unconfined)") == 2
    assert workflow.count("sudo apparmor_parser --replace /etc/apparmor.d/bwrap") == 2
    profiles = [
        body.strip()
        for body in re.findall(
            r"profile bwrap /usr/bin/bwrap flags=\(unconfined\) \{\n(?P<body>.*?)\n[ \t]*\}",
            workflow,
            re.DOTALL,
        )
    ]
    assert profiles == ["userns,", "userns,"]
    assert workflow.count('apparmor_restrict_unprivileged_userns)" = 1') == 2
    assert workflow.count("/usr/bin/bwrap --version") == 2
    assert workflow.count("/usr/bin/dpkg-query --show") == 4
    assert workflow.count("0.9.0-1ubuntu0.3") == 2
    assert workflow.count("python3 -m tools.install_bubblewrap") == 2
    assert workflow.count("e318903862396f96de3df57264e0158682b952fd3fb53ac23d876413e7b30f71") == 2
    assert "apt-get install" not in workflow
    assert workflow.count("--disable-userns --assert-userns-disabled") == 4
    assert workflow.count("/usr/bin/unshare --user -- /usr/bin/true") == 2
    assert workflow.count("--symlink usr/bin /bin --symlink usr/lib /lib") == 4
    assert workflow.count("--symlink usr/lib64 /lib64") == 4
    assert workflow.count("--clearenv -- /usr/bin/true") == 2
    assert workflow.count("python -m tools.install_trivy") == 1
    assert workflow.count("python -m tools.install_osv_scanner") == 1
    assert (
        workflow.count(
            "python -m pip install --require-hashes --no-build-isolation -r requirements/security.txt"
        )
        == 1
    )
    assert workflow.index("python -m tools.install_trivy") < workflow.index(
        "python -m tools.run_test_shard --index"
    )
    assert workflow.index("python -m tools.install_osv_scanner") < workflow.index(
        "python -m tools.run_test_shard --index"
    )
    assert "apparmor_restrict_unprivileged_userns=0" not in workflow
    assert "sysctl -w" not in workflow
    assert "apparmor_parser --remove" not in workflow
    assert "--no-sandbox" not in workflow
    assert "--disable-setuid-sandbox" not in workflow


@pytest.mark.parametrize(
    "workflow",
    [
        ".github/workflows/ci-quality.yml",
        ".github/workflows/ci-tests.yml",
        ".github/workflows/ci-vscode.yml",
        ".github/workflows/ci-distribution.yml",
        ".github/workflows/docs.yml",
        ".github/workflows/pre-commit.yml",
        ".github/workflows/security.yml",
        ".github/workflows/release.yml",
        ".github/workflows/publish.yml",
        ".github/workflows/fuzz.yml",
        "action.yml",
    ],
)
def test_actual_install_environments_prime_locked_build_backends(workflow: str) -> None:
    """Every real Python lock consumer first installs its bootstrap in that interpreter.

    Parameters
    ----------
    workflow : str
        Actual maintained workflow or distributable consumer Action definition.
    """
    document = read_workflow(ROOT / workflow)
    jobs = document["jobs"].values() if "jobs" in document else [document["runs"]]
    for job in jobs:
        primed: set[str] = set()
        cached_python = False
        for step in job.get("steps", []):
            settings = step.get("with", {})
            if (
                step.get("uses", "").startswith("actions/setup-python@")
                and settings.get("cache") == "pip"
            ):
                cached_python = True
                assert (
                    "requirements/bootstrap.txt" in settings["cache-dependency-path"].splitlines()
                )
            script = step.get("run", "").replace("\\\n", "")
            for line in script.splitlines():
                if not re.match(r'\s*(?:"[^"]+"|\S+) -m pip install\b', line):
                    continue
                command = shlex.split(line, comments=True)
                if "--require-hashes" not in command:
                    continue
                if any(token.endswith("requirements/bootstrap.txt") for token in command):
                    primed.add(command[0])
                else:
                    assert command[0] in primed, (workflow, line)
                    assert "--no-build-isolation" in command, (workflow, line)
        if cached_python or workflow == "action.yml":
            assert primed, workflow
