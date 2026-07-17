# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Reproducible packaging contract tests
"""Verify release inputs and resource-bounded preflight composition."""

from __future__ import annotations

import re
import tomllib

from rigor_foundry.version import __version__
from tools._repository import ROOT


def test_build_backend_and_base_image_are_immutable() -> None:
    """Distribution and container builders use exact immutable inputs."""

    with (ROOT / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)
    assert project["build-system"]["requires"] == ["hatchling==1.31.0"]
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
    assert "snapshot.debian.org/archive/debian/20260714T000000Z" in dockerfile
    assert "snapshot.debian.org/archive/debian-security/20260714T000000Z" in dockerfile
    assert "USER rigor" in dockerfile


def test_hash_locks_cover_each_resolved_distribution() -> None:
    """Every non-comment lock entry carries at least one SHA-256 hash."""

    for name in ("build.txt", "ci.txt", "runtime.txt", "security.txt", "test.txt"):
        text = (ROOT / "requirements" / name).read_text(encoding="utf-8")
        entries = re.split(r"\n(?=[a-zA-Z0-9])", text)
        resolved = [entry for entry in entries if "==" in entry]
        assert resolved, name
        assert all("--hash=sha256:" in entry for entry in resolved), name


def test_ci_grants_user_namespaces_only_to_bubblewrap() -> None:
    """Ubuntu CI keeps global mediation and grants only the bwrap user namespace."""

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
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
    assert "/tmp/rigor-wheel/bin/rigor scan --root ." in workflow
    assert "/tmp/rigor-wheel/bin/rigor sarif --report /tmp/rigor-adopter-report.json" in workflow
    assert 'document["version"] == "2.1.0"' in workflow
    assert "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e" in workflow
    assert "Draft4Validator(schema).validate(document)" in workflow
    assert "stat -c '%a' docs/internal/TODO.md" in workflow
    assert "test ! -e docs/internal/reviews.json" in workflow
    assert workflow.count("runs-on: ubuntu-24.04") == 3
    assert workflow.count("profile bwrap /usr/bin/bwrap flags=(unconfined)") == 2
    assert workflow.count("sudo apparmor_parser --replace /etc/apparmor.d/bwrap") == 2
    profiles = re.findall(
        r"profile bwrap /usr/bin/bwrap flags=\(unconfined\) \{\n(?P<body>.*?)\n          \}",
        workflow,
        re.DOTALL,
    )
    assert profiles == ["            userns,", "            userns,"]
    assert workflow.count('apparmor_restrict_unprivileged_userns)" = 1') == 2
    assert workflow.count("/usr/bin/bwrap --version") == 2
    assert workflow.count("/usr/bin/dpkg-query --show") == 2
    assert workflow.count("--disable-userns --assert-userns-disabled") == 4
    assert workflow.count("/usr/bin/unshare --user -- /usr/bin/true") == 2
    assert workflow.count("--symlink usr/bin /bin --symlink usr/lib /lib") == 4
    assert workflow.count("--symlink usr/lib64 /lib64") == 4
    assert workflow.count("--clearenv -- /usr/bin/true") == 2
    assert "apparmor_restrict_unprivileged_userns=0" not in workflow
    assert "sysctl -w" not in workflow
    assert "apparmor_parser --remove" not in workflow
