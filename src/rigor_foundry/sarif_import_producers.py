# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — declared SARIF producers and the commit an import is bound to
"""Accept SARIF only from a declared producer, bound to the exact commit it describes.

Each supported producer is one immutable declaration in code: its accepted driver names, the
field that carries its version, its supported major versions, its exact ``$schema`` URIs and
the ``uriBaseId`` names that denote the scanned root. Every value was measured from real
output of that producer, never written from memory. A file from an undeclared producer, from
RigorFoundry itself, or for another commit is refused as a whole. The identity of a declared
import is the file's own claim and is recorded as ``declared``, never as verified.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal

from .audit_primitives import canonical_digest
from .sarif_import_document import SarifDocument, SarifImportRefused

SELF_DRIVER_NAME: Final = "RigorFoundry"
_VERSION: Final = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_OBJECT_ID: Final = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


@dataclass(frozen=True)
class ImportProducer:
    """One declared SARIF producer, as its real output identifies itself."""

    producer_id: str
    driver_names: frozenset[str]
    version_field: Literal["semanticVersion", "version"]
    supported_majors: frozenset[int]
    supported_zero_minors: frozenset[int]
    schema_uris: frozenset[str]
    root_base_ids: frozenset[str]

    def __post_init__(self) -> None:
        """Require measured minors exactly when major version zero is supported."""
        if (0 in self.supported_majors) != bool(self.supported_zero_minors):
            raise ValueError("a major-zero producer declares its measured minors, and only it")

    def to_dict(self) -> dict[str, object]:
        """Serialise the declaration in a stable order."""
        return {
            "producer_id": self.producer_id,
            "driver_names": sorted(self.driver_names),
            "version_field": self.version_field,
            "supported_majors": sorted(self.supported_majors),
            "supported_zero_minors": sorted(self.supported_zero_minors),
            "schema_uris": sorted(self.schema_uris),
            "root_base_ids": sorted(self.root_base_ids),
        }

    @property
    def declaration_digest(self) -> str:
        """Return the digest that an import report records for this declaration."""
        return canonical_digest(self.to_dict())


PRODUCERS: Final[Mapping[str, ImportProducer]] = MappingProxyType(
    {
        # Measured from CodeQL 2.26.0 and 2.27.2 code-scanning analyses of this repository.
        "codeql": ImportProducer(
            producer_id="codeql",
            driver_names=frozenset({"CodeQL"}),
            version_field="semanticVersion",
            supported_majors=frozenset({2}),
            supported_zero_minors=frozenset(),
            schema_uris=frozenset(
                {
                    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
                }
            ),
            root_base_ids=frozenset(),
        ),
        # Measured from ``semgrep scan --sarif`` of Semgrep 1.186.0.
        "semgrep": ImportProducer(
            producer_id="semgrep",
            driver_names=frozenset({"Semgrep OSS"}),
            version_field="semanticVersion",
            supported_majors=frozenset({1}),
            supported_zero_minors=frozenset(),
            schema_uris=frozenset(
                {
                    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
                }
            ),
            root_base_ids=frozenset({"%SRCROOT%"}),
        ),
        # Measured from ``trivy fs --format sarif`` of Trivy 0.76.2.
        "trivy": ImportProducer(
            producer_id="trivy",
            driver_names=frozenset({"Trivy"}),
            version_field="version",
            supported_majors=frozenset({0}),
            # Under major zero any minor may change the format, so only the measured 0.76.
            supported_zero_minors=frozenset({76}),
            schema_uris=frozenset(
                {
                    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
                }
            ),
            root_base_ids=frozenset({"ROOTPATH"}),
        ),
    }
)


@dataclass(frozen=True)
class ProducerIdentity:
    """The declared producer of one file and the driver identity every run claims."""

    producer: ImportProducer
    driver_name: str
    driver_version: str


def identify_producer(document: SarifDocument, producer_id: str) -> ProducerIdentity:
    """Return the declared producer of a whole file, or refuse the file.

    Parameters
    ----------
    document : SarifDocument
        A strictly parsed SARIF 2.1.0 document.
    producer_id : str
        The producer the operator declares for the file.

    Returns
    -------
    ProducerIdentity
        The declaration and the one driver name and version that every run claims.

    Raises
    ------
    SarifImportRefused
        With ``unknown-producer``, ``no-runs``, ``self-import``, ``unsupported-schema``,
        ``driver-not-declared``, ``missing-version``, ``unsupported-version`` (anything but
        exactly ``MAJOR.MINOR.PATCH`` without leading zeros), ``unsupported-major``,
        ``unsupported-minor`` (a major-zero minor that was not measured) or
        ``mixed-producer-runs``.
    """
    producer = PRODUCERS.get(producer_id)
    if producer is None:
        raise SarifImportRefused("unknown-producer", "the producer has no declaration")
    if not document.runs:
        raise SarifImportRefused("no-runs", "a file without runs claims no producer")
    # RigorFoundry's own output is refused as such, whichever producer is declared for it.
    if any(run["tool"]["driver"]["name"] == SELF_DRIVER_NAME for run in document.runs):
        raise SarifImportRefused("self-import", "RigorFoundry's own SARIF is not imported")
    if document.document.get("$schema") not in producer.schema_uris:
        raise SarifImportRefused("unsupported-schema", "the $schema URI is not declared")
    identities = {_driver_identity(producer, run) for run in document.runs}
    if len(identities) != 1:
        raise SarifImportRefused("mixed-producer-runs", "the runs claim different drivers")
    ((name, version),) = identities
    return ProducerIdentity(producer, name, version)


def _driver_identity(producer: ImportProducer, run: dict[str, Any]) -> tuple[str, str]:
    """Return one run's driver name and version after checking them against the declaration."""
    driver = run["tool"]["driver"]
    name = driver["name"]
    if name not in producer.driver_names:
        raise SarifImportRefused("driver-not-declared", "the driver is not this producer")
    version = driver.get(producer.version_field)
    if not isinstance(version, str):
        raise SarifImportRefused("missing-version", "the driver does not state its version")
    match = _VERSION.fullmatch(version)
    if match is None:
        raise SarifImportRefused("unsupported-version", "the driver version is not a release")
    major, minor = int(match.group(1)), int(match.group(2))
    if major not in producer.supported_majors:
        raise SarifImportRefused("unsupported-major", "the driver's major version is not declared")
    if major == 0 and minor not in producer.supported_zero_minors:
        raise SarifImportRefused(
            "unsupported-minor", "this major-zero minor version is not declared"
        )
    return name, version


def bind_head(document: SarifDocument, inventory_head: str, operator_head: str | None) -> str:
    """Return the commit a file is imported against, refusing any other commit.

    Parameters
    ----------
    document : SarifDocument
        A strictly parsed SARIF 2.1.0 document.
    inventory_head : str
        ``HEAD`` of the verified inventory that locations resolve against.
    operator_head : str | None
        The commit the operator names, required when any run states no ``revisionId``.

    Returns
    -------
    str
        The inventory head, which every stated revision and the operator's head equal.

    Raises
    ------
    SarifImportRefused
        With ``malformed-version-control``, ``revision-mismatch``, ``head-mismatch`` or
        ``head-required``.
    """
    for run in document.runs:
        revisions = _run_revisions(run)
        if revisions - {inventory_head}:
            raise SarifImportRefused("revision-mismatch", "the file describes another commit")
        # Each run is bound by its own revision, or else by the head the operator names.
        if not revisions and operator_head is None:
            raise SarifImportRefused("head-required", "a run states no revision; name the head")
    if operator_head is not None and operator_head != inventory_head:
        raise SarifImportRefused("head-mismatch", "the named head is not the inventory's head")
    return inventory_head


def _run_revisions(run: dict[str, Any]) -> set[str]:
    """Return the commit object ids that one run's version-control provenance states."""
    provenance = run.get("versionControlProvenance", [])
    if not isinstance(provenance, list) or not all(
        isinstance(entry, dict) for entry in provenance
    ):
        raise SarifImportRefused("malformed-version-control", "provenance must be objects")
    revisions: set[str] = set()
    for entry in provenance:
        if "revisionId" not in entry:
            continue
        revision = entry["revisionId"]
        if not isinstance(revision, str) or _OBJECT_ID.fullmatch(revision) is None:
            raise SarifImportRefused("malformed-version-control", "a revision is not an oid")
        revisions.add(revision)
    return revisions
