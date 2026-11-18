# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Signed distribution provenance tests
"""Check the production verifier against retained public distribution proofs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from gzip import decompress
from hashlib import sha256
from pathlib import Path
from shutil import copyfile

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.cli import main
from rigor_foundry.provenance_attestation import (
    PUBLISH,
    SLSA,
    binds_distribution,
    verify_attestation,
)

FIXTURES = Path(__file__).parent / "fixtures" / "provenance"
ROOT = "sigstore-public-root.json"
ROOT_SHA256 = "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"
ISSUER = "https://token.actions.githubusercontent.com"
MEDIA_TYPE = "application/vnd.in-toto+json"


@dataclass(frozen=True)
class SignedDistribution:
    """Independently pinned archive, publisher, bundle and signed statement."""

    project: str
    version: str
    filename: str
    sha256: str
    bundle: str
    bundle_sha256: str
    predicate: str
    identity: str
    source_commit: str | None
    statement_sha256: str

    def profile(self) -> dict[str, object]:
        """Provide the complete distribution input accepted by the CLI."""
        return {
            "project": self.project,
            "version": self.version,
            "artifact": self.filename,
            "sha256": self.sha256,
            "bundle": self.bundle,
            "bundle_sha256": self.bundle_sha256,
            "predicate": self.predicate,
            "identity": self.identity,
            "issuer": ISSUER,
            "source_commit": self.source_commit,
            "root": ROOT,
            "root_sha256": ROOT_SHA256,
        }


SAMPLE = SignedDistribution(
    project="sampleproject",
    version="4.0.0",
    filename="sampleproject-4.0.0.tar.gz",
    sha256="0ace7980f82c5815ede4cd7bf9f6693684cec2ae47b9b7ade9add533b8627c6b",
    bundle="sampleproject-4.0.0-publish.json",
    bundle_sha256="b0ba839d7f685902e956a15cff18796390abe0aae7cfd536e9eeda4f30b53394",
    predicate=PUBLISH,
    identity="https://github.com/pypa/sampleproject/.github/workflows/release.yml@refs/heads/main",
    source_commit=None,
    statement_sha256="95a7d0c7feaed540942edfe70af9d3bb63b63e880d2d7a1c63fd8424a56b45bc",
)

BUILD = SignedDistribution(
    project="build",
    version="1.4.4",
    filename="build-1.4.4-py3-none-any.whl",
    sha256="8c3f48a6090b39edec1a273d2d57949aaf13723b01e02f9d518396887519f64d",
    bundle="build-1.4.4-slsa.json",
    bundle_sha256="efad9164d2c7afdd6730cf32dda1fbfff08813febb6a74b6b300fb7f3d9641cf",
    predicate=SLSA,
    identity="https://github.com/pypa/build/.github/workflows/cd.yml@refs/tags/1.4.4",
    source_commit="70666a296c2e5bb7451f5a04eef259f6f943d0de",
    statement_sha256="4933f0c3b290fd76921c2195492d0d89d46dd6724facf3d8ea4a6d0e36160a39",
)


def _bundle_bytes(fixture: SignedDistribution) -> bytes:
    """Restore the exact retained upstream proof without reserialising it."""
    return decompress((FIXTURES / f"{fixture.bundle}.gz").read_bytes())


def _root_bytes() -> bytes:
    """Restore the exact Sigstore trust root used by the upstream proofs."""
    return decompress((FIXTURES / f"{ROOT}.gz").read_bytes())


def _scan(
    directory: Path, fixture: SignedDistribution, distribution: dict[str, object]
) -> dict[str, object]:
    """Run the normal scan over real pinned Git and signature inputs."""
    repo = GitRepository.create(directory / "repository")
    repo.write_bytes(
        "requirements/runtime.txt",
        f"{fixture.project}=={fixture.version} --hash=sha256:{fixture.sha256}\n".encode(),
    )
    repo.commit()
    copyfile(FIXTURES / fixture.filename, directory / fixture.filename)
    (directory / ROOT).write_bytes(_root_bytes())
    (directory / fixture.bundle).write_bytes(_bundle_bytes(fixture))
    profile = directory / "profile.json"
    raw = json.dumps(
        {
            "schema_version": "1.0",
            "lock": "requirements/runtime.txt",
            "distributions": [distribution],
            "scorecard": None,
        }
    ).encode()
    profile.write_bytes(raw)
    output = directory / "scan.json"
    assert (
        main(
            [
                "scan-provenance",
                "--root",
                str(repo.root),
                "--profile",
                str(profile),
                "--profile-sha256",
                sha256(raw).hexdigest(),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    (result,) = json.loads(output.read_bytes())["provenance"]["distributions"]
    assert isinstance(result, dict)
    return result


@pytest.mark.parametrize("fixture", [SAMPLE, BUILD], ids=["pep740-sdist", "slsa-wheel"])
def test_cli_verifies_retained_distribution_signature(
    tmp_path: Path, fixture: SignedDistribution
) -> None:
    """Exercise actual signature, certificate and timestamp checking through the CLI."""
    result = _scan(tmp_path, fixture, fixture.profile())
    assert result["status"] == "verified"
    assert result["verification"] == {
        "statement_sha256": fixture.statement_sha256,
        "sigstore_version": "4.5.1",
        "pypi_attestations_version": "0.0.31",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "identity",
            "https://github.com/example/other/.github/workflows/build.yml@refs/heads/main",
        ),
        ("source_commit", "0" * 40),
        ("root_sha256", "0" * 64),
        ("artifact", "missing-1.4.4-py3-none-any.whl"),
    ],
)
def test_cli_refuses_unbound_distribution_evidence(tmp_path: Path, field: str, value: str) -> None:
    """Refuse signer, source, local-root and missing-artifact mismatches."""
    distribution = BUILD.profile()
    distribution[field] = value
    result = _scan(tmp_path, BUILD, distribution)
    assert result["status"] == "refused"
    assert result["verification"] is None


@pytest.mark.parametrize(
    ("project", "version", "digest"),
    [
        ("other", BUILD.version, BUILD.sha256),
        (BUILD.project, "2.0.0", BUILD.sha256),
        (BUILD.project, BUILD.version, "0" * 64),
    ],
)
def test_verifier_refuses_other_distribution(project: str, version: str, digest: str) -> None:
    """Require the exact distribution identity and authenticated subject digest."""
    assert (
        verify_attestation(
            evidence=_bundle_bytes(BUILD),
            root_bytes=_root_bytes(),
            predicate=BUILD.predicate,
            identity=BUILD.identity,
            issuer=ISSUER,
            source_commit=BUILD.source_commit,
            filename=BUILD.filename,
            project=project,
            release_version=version,
            artifact_digest=digest,
        )
        is None
    )


@pytest.mark.parametrize(
    ("media_type", "statement_type", "predicate", "subjects"),
    [
        ("application/json", "https://in-toto.io/Statement/v1", PUBLISH, []),
        (MEDIA_TYPE, "https://in-toto.io/Statement/v0.1", PUBLISH, []),
        (MEDIA_TYPE, "https://in-toto.io/Statement/v1", SLSA, []),
        (MEDIA_TYPE, "https://in-toto.io/Statement/v1", PUBLISH, {}),
        (MEDIA_TYPE, "https://in-toto.io/Statement/v1", PUBLISH, []),
        (
            MEDIA_TYPE,
            "https://in-toto.io/Statement/v1",
            PUBLISH,
            [
                {"name": SAMPLE.filename, "digest": {"sha256": SAMPLE.sha256}},
                {"name": BUILD.filename, "digest": {"sha256": BUILD.sha256}},
            ],
        ),
        (MEDIA_TYPE, "https://in-toto.io/Statement/v1", PUBLISH, [{"name": "", "digest": {}}]),
    ],
)
def test_statement_contract_refuses_unrecognised_distribution_claim(
    media_type: str, statement_type: str, predicate: str, subjects: object
) -> None:
    """Reject inappropriate media, predicate and subject shapes at the statement boundary."""
    statement = json.dumps(
        {"_type": statement_type, "predicateType": predicate, "subject": subjects}
    ).encode()
    assert not binds_distribution(media_type, statement, PUBLISH, SAMPLE.filename, SAMPLE.sha256)


def test_slsa_statement_refuses_duplicate_names() -> None:
    """Require a unique subject for the signed distribution name."""
    statement = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": SLSA,
            "subject": [
                {"name": BUILD.filename, "digest": {"sha256": BUILD.sha256}},
                {"name": BUILD.filename, "digest": {"sha256": "0" * 64}},
            ],
        }
    ).encode()
    assert not binds_distribution(MEDIA_TYPE, statement, SLSA, BUILD.filename, BUILD.sha256)
