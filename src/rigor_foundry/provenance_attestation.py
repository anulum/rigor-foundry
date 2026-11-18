# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Offline signed distribution evidence
"""Verify DSSE evidence against caller-pinned local roots and exact subjects."""

from __future__ import annotations

from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory

from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from packaging.version import Version
from pypi_attestations import AttestationError, Provenance
from sigstore.errors import Error as SigstoreError
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import Verifier
from sigstore.verify.policy import AllOf, Identity, OIDCSourceRepositoryDigest

from .audit_primitives import require_mapping
from .source_provenance import _json_without_duplicate_keys

PUBLISH = "https://docs.pypi.org/attestations/publish/v1"
SLSA = "https://slsa.dev/provenance/v1"


def verify_attestation(
    *,
    evidence: bytes,
    root_bytes: bytes,
    predicate: str,
    identity: str,
    issuer: str,
    source_commit: str | None,
    filename: str,
    project: str,
    release_version: str,
    artifact_digest: str,
) -> dict[str, str] | None:
    """Return authenticated statement evidence for an exact distribution.

    Parameters
    ----------
    evidence, root_bytes : bytes
        Retained producer evidence and the independently pinned Sigstore root.
    predicate, identity, issuer : str
        Expected in-toto predicate and signing certificate identity and issuer.
    source_commit : str or None
        Optional expected certificate source repository digest.
    filename, project, release_version, artifact_digest : str
        Distribution filename, package identity, release and observed SHA-256.

    Returns
    -------
    dict[str, str] or None
        SHA-256 of the authenticated statement and verifier versions, or refusal.
    """
    try:
        if filename.endswith(".whl"):
            name, release, _, _ = parse_wheel_filename(filename)
        else:
            name, release = parse_sdist_filename(filename)
        if name != canonicalize_name(project) or release != Version(release_version):
            return None
        policy = Identity(identity=identity, issuer=issuer)
        signing_policy = (
            policy
            if source_commit is None
            else AllOf([policy, OIDCSourceRepositoryDigest(source_commit)])
        )
        if predicate == PUBLISH:
            provenance = Provenance.model_validate(
                require_mapping(_json_without_duplicate_keys(evidence), "provenance")
            )
            [publisher] = provenance.attestation_bundles
            [attestation] = publisher.attestations
            bundle = attestation.to_bundle()
        else:
            bundle = Bundle.from_json(require_unique_json(evidence))
        with TemporaryDirectory(prefix="rigor-trusted-root-") as directory:
            root = Path(directory) / "root.json"
            root.write_bytes(root_bytes)
            verifier = Verifier(trusted_root=TrustedRoot.from_file(str(root)))
            media_type, statement = verifier.verify_dsse(bundle, signing_policy)
        if not binds_distribution(media_type, statement, predicate, filename, artifact_digest):
            return None
    except (ValueError, SigstoreError, AttestationError, IndexError, TypeError):
        return None
    return {
        "statement_sha256": sha256(statement).hexdigest(),
        "sigstore_version": version("sigstore"),
        "pypi_attestations_version": version("pypi-attestations"),
    }


def require_unique_json(data: bytes) -> bytes:
    """Validate JSON key uniqueness before passing exact raw bytes to a verifier."""
    require_mapping(_json_without_duplicate_keys(data), "signed bundle")
    return data


def binds_distribution(
    media_type: str, statement: bytes, predicate: str, filename: str, digest: str
) -> bool:
    """Match verified content to the accepted in-toto media type and exact subject."""
    if media_type != "application/vnd.in-toto+json":
        return False
    data = require_mapping(_json_without_duplicate_keys(statement), "statement")
    if (
        data.get("_type") != "https://in-toto.io/Statement/v1"
        or data.get("predicateType") != predicate
    ):
        return False
    subjects = data.get("subject")
    if not isinstance(subjects, list) or not 1 <= len(subjects) <= 256:
        return False
    if predicate == PUBLISH and len(subjects) != 1:
        return False
    names: set[str] = set()
    matched = False
    for value in subjects:
        subject = require_mapping(value, "subject")
        name = subject.get("name")
        hashes = require_mapping(subject.get("digest"), "subject.digest")
        if not isinstance(name, str) or not name or name in names:
            return False
        names.add(name)
        if name == filename:
            matched = hashes.get("sha256") == digest
    return matched
