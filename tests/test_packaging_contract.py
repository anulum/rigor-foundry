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

from tools._repository import ROOT


def test_build_backend_and_base_image_are_immutable() -> None:
    """Distribution and container builders use exact immutable inputs."""

    with (ROOT / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)
    assert project["build-system"]["requires"] == ["hatchling==1.31.0"]
    assert project["project"]["license"] == "Apache-2.0"
    assert project["project"]["license-files"] == ["LICENSE", "NOTICE"]

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    bases = re.findall(r"^FROM\s+([^\s]+)", dockerfile, re.MULTILINE)
    assert len(bases) == 2
    assert all("@sha256:" in base for base in bases)
    assert "snapshot.debian.org/archive/debian/20260316T000000Z" in dockerfile
    assert "snapshot.debian.org/archive/debian-security/20260316T000000Z" in dockerfile
    assert "USER rigor" in dockerfile


def test_hash_locks_cover_each_resolved_distribution() -> None:
    """Every non-comment lock entry carries at least one SHA-256 hash."""

    for name in ("build.txt", "ci.txt", "runtime.txt", "security.txt", "test.txt"):
        text = (ROOT / "requirements" / name).read_text(encoding="utf-8")
        entries = re.split(r"\n(?=[a-zA-Z0-9])", text)
        resolved = [entry for entry in entries if "==" in entry]
        assert resolved, name
        assert all("--hash=sha256:" in entry for entry in resolved), name
