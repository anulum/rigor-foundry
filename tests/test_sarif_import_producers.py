# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — declared SARIF producer and commit binding tests on real output
"""Verify the producer declarations and the commit binding on real CodeQL, Semgrep and Trivy SARIF."""

from __future__ import annotations

import copy
import dataclasses
import gzip
import json
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from rigor_foundry.sarif_import_document import (
    SarifDocument,
    SarifImportRefused,
    parse_sarif_document,
)
from rigor_foundry.sarif_import_producers import (
    PRODUCERS,
    SELF_DRIVER_NAME,
    ImportProducer,
    bind_head,
    identify_producer,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/sarif_import"
CODEQL = FIXTURES / "codeql-2.26.0-actions-analysis-1496041210.sarif.gz"
CODEQL_LATER = FIXTURES / "codeql-2.27.2-actions-analysis-2237134604.sarif.gz"
SEMGREP = FIXTURES / "semgrep-1.186.0-producer-repository.sarif"
TRIVY = FIXTURES / "trivy-0.76.2-producer-repository.sarif"
OWN = ROOT / "tests/fixtures/sarif/canonical-states.sarif"
CODEQL_REVISION = "a55894202bcbf357b7857629c5485a7c75102088"
OTHER_HEAD = "b" * 40


def _payload(path: Path) -> bytes:
    """Return the exact producer bytes of one fixture."""
    raw = path.read_bytes()
    return gzip.decompress(raw) if path.suffix == ".gz" else raw


def _document(path: Path) -> SarifDocument:
    """Return one real fixture, strictly parsed."""
    return parse_sarif_document(_payload(path))


def _variant(path: Path, change: Callable[[dict[str, Any]], None]) -> SarifDocument:
    """Return a strictly parsed copy of one real fixture with one change applied."""
    document: dict[str, Any] = json.loads(_payload(path))
    change(document)
    return parse_sarif_document(json.dumps(document).encode())


def _refusal(action: Callable[[], object]) -> str:
    """Return the reason with which an identity check refuses the whole file."""
    with pytest.raises(SarifImportRefused) as refused:
        action()
    return refused.value.reason


@pytest.mark.parametrize(
    ("path", "producer_id", "name", "version"),
    [
        (CODEQL, "codeql", "CodeQL", "2.26.0"),
        (CODEQL_LATER, "codeql", "CodeQL", "2.27.2"),
        (SEMGREP, "semgrep", "Semgrep OSS", "1.186.0"),
        (TRIVY, "trivy", "Trivy", "0.76.2"),
    ],
)
def test_each_real_file_is_identified_as_its_declared_producer(
    path: Path, producer_id: str, name: str, version: str
) -> None:
    """Every measured file carries the driver name, version and schema of its declaration.

    Parameters
    ----------
    path : Path
        The real producer output.
    producer_id : str
        Its declared producer.
    name : str
        The measured driver name.
    version : str
        The measured driver version.
    """
    identity = identify_producer(_document(path), producer_id)
    assert (identity.producer, identity.driver_name, identity.driver_version) == (
        PRODUCERS[producer_id],
        name,
        version,
    )
    for other in set(PRODUCERS) - {producer_id}:
        assert _refusal(partial(identify_producer, _document(path), other)) in {
            "unsupported-schema",
            "driver-not-declared",
        }


DECLARATION_DIGESTS = {
    "codeql": "c822dd62c943962254528d85f53f01bd4d5b0f759c94a634e6c4dbc9087d5d87",
    "semgrep": "704ff8c157d0a8f9bf710249654db4779ccb65ad4e268f48f5e7a438bfda053d",
    "trivy": "40f563e5e55d620a4cd0a49461b6b4afb77061ca73829972ffcdfc2af658cd4f",
}


def test_every_declaration_digest_covers_every_field_and_is_pinned() -> None:
    """Each serialised declaration names every field, and any change of one is a visible diff."""
    fields = {field.name for field in dataclasses.fields(ImportProducer)}
    for producer_id, producer in PRODUCERS.items():
        assert set(producer.to_dict()) == fields
        assert producer.declaration_digest == DECLARATION_DIGESTS[producer_id]
    assert PRODUCERS["trivy"].to_dict()["supported_zero_minors"] == [76]
    assert PRODUCERS["semgrep"].to_dict()["root_base_ids"] == ["%SRCROOT%"]
    assert PRODUCERS["trivy"].to_dict()["root_base_ids"] == ["ROOTPATH"]
    assert PRODUCERS["codeql"].to_dict()["root_base_ids"] == []


def test_rigor_foundrys_own_export_is_refused_as_a_self_import() -> None:
    """The exported fixture's driver is RigorFoundry, refused whichever producer is named."""
    own = _document(OWN)
    assert own.runs[0]["tool"]["driver"]["name"] == SELF_DRIVER_NAME
    for producer_id in PRODUCERS:
        assert _refusal(partial(identify_producer, own, producer_id)) == "self-import"


def test_a_later_rigor_foundry_run_is_refused_as_a_self_import() -> None:
    """A Semgrep file whose second run is RigorFoundry's own is refused as a self-import."""
    (own_run,) = json.loads(OWN.read_text(encoding="utf-8"))["runs"]

    def append_own(document: dict[str, Any]) -> None:
        document["runs"].append(own_run)

    mixed = _variant(SEMGREP, append_own)
    assert mixed.runs[0]["tool"]["driver"]["name"] == "Semgrep OSS"
    assert _refusal(lambda: identify_producer(mixed, "semgrep")) == "self-import"


def test_a_file_without_runs_claims_no_producer() -> None:
    """Zero runs is refused as such, never as mixed runs."""
    schema = next(iter(PRODUCERS["codeql"].schema_uris))
    empty = parse_sarif_document(
        json.dumps({"version": "2.1.0", "$schema": schema, "runs": []}).encode()
    )
    assert _refusal(lambda: identify_producer(empty, "codeql")) == "no-runs"


@pytest.mark.parametrize(
    ("majors", "minors"), [(frozenset({0}), frozenset()), (frozenset({1}), frozenset({3}))]
)
def test_minors_are_declared_exactly_for_a_major_zero_producer(
    majors: frozenset[int], minors: frozenset[int]
) -> None:
    """A major-zero declaration without measured minors, or minors without major zero, is refused.

    Parameters
    ----------
    majors : frozenset[int]
        The declared majors.
    minors : frozenset[int]
        The declared major-zero minors.
    """
    with pytest.raises(ValueError, match="major-zero producer declares its measured minors"):
        ImportProducer("t", frozenset({"T"}), "version", majors, minors, frozenset(), frozenset())


def _driver(**changes: Any) -> Callable[[dict[str, Any]], None]:
    """Return a change that sets or removes driver fields of the first run."""

    def change(document: dict[str, Any]) -> None:
        driver = document["runs"][0]["tool"]["driver"]
        for key, value in changes.items():
            if value is None:
                driver.pop(key)
            else:
                driver[key] = value

    return change


def _second_run(version: str) -> Callable[[dict[str, Any]], None]:
    """Return a change that adds a second run claiming another driver version."""

    def change(document: dict[str, Any]) -> None:
        run = copy.deepcopy(document["runs"][0])
        run["tool"]["driver"]["semanticVersion"] = version
        document["runs"].append(run)

    return change


def _schema(uri: str | None) -> Callable[[dict[str, Any]], None]:
    """Return a change that replaces or removes the document's ``$schema``."""

    def change(document: dict[str, Any]) -> None:
        if uri is None:
            del document["$schema"]
        else:
            document["$schema"] = uri

    return change


IDENTITY_REFUSALS: tuple[tuple[Path, str, Callable[[dict[str, Any]], None], str], ...] = (
    (TRIVY, "trivy", _driver(name="Trivy Enterprise"), "driver-not-declared"),
    (SEMGREP, "semgrep", _driver(name="Semgrep Pro"), "driver-not-declared"),
    (SEMGREP, "semgrep", _driver(semanticVersion="2.0.0"), "unsupported-major"),
    (TRIVY, "trivy", _driver(version="1.0.0"), "unsupported-major"),
    (TRIVY, "trivy", _driver(version="0.77.0"), "unsupported-minor"),
    (TRIVY, "trivy", _driver(version="0.75.9"), "unsupported-minor"),
    (CODEQL, "codeql", _driver(semanticVersion="3.0.0"), "unsupported-major"),
    (SEMGREP, "semgrep", _driver(semanticVersion=None), "missing-version"),
    (TRIVY, "trivy", _driver(version=None, semanticVersion="0.76.2"), "missing-version"),
    (SEMGREP, "semgrep", _driver(semanticVersion="latest"), "unsupported-version"),
    (SEMGREP, "semgrep", _driver(semanticVersion="v1.186.0"), "unsupported-version"),
    (SEMGREP, "semgrep", _driver(semanticVersion="01.186.0"), "unsupported-version"),
    (SEMGREP, "semgrep", _driver(semanticVersion="1.186"), "unsupported-version"),
    (SEMGREP, "semgrep", _driver(semanticVersion="1.02.3"), "unsupported-version"),
    (SEMGREP, "semgrep", _driver(semanticVersion="1.186.03"), "unsupported-version"),
    (SEMGREP, "semgrep", _driver(semanticVersion="1.186.0-rc1"), "unsupported-version"),
    (SEMGREP, "semgrep", _driver(semanticVersion="1.186.0+build"), "unsupported-version"),
    (SEMGREP, "semgrep", _driver(semanticVersion="1.186.0-"), "unsupported-version"),
    (SEMGREP, "semgrep", _second_run("1.185.0"), "mixed-producer-runs"),
    (SEMGREP, "semgrep", _schema(None), "unsupported-schema"),
    (
        SEMGREP,
        "semgrep",
        _schema("https://json.schemastore.org/sarif-2.1.0.json"),
        "unsupported-schema",
    ),
)


@pytest.mark.parametrize(("path", "producer_id", "change", "reason"), IDENTITY_REFUSALS)
def test_a_file_outside_its_declaration_is_refused_whole(
    path: Path, producer_id: str, change: Callable[[dict[str, Any]], None], reason: str
) -> None:
    """Another driver name, major, a missing or unparsable version, mixed runs or another schema.

    Parameters
    ----------
    path : Path
        The real producer output the variant starts from.
    producer_id : str
        Its declared producer.
    change : Callable[[dict[str, Any]], None]
        One change of the file's identity.
    reason : str
        The refusal reason.
    """
    document = _variant(path, change)
    assert _refusal(lambda: identify_producer(document, producer_id)) == reason


def test_an_unknown_producer_is_refused() -> None:
    """A producer without a declaration in code is refused."""
    assert _refusal(lambda: identify_producer(_document(SEMGREP), "bandit")) == "unknown-producer"


def test_a_stated_revision_binds_the_import_to_that_commit() -> None:
    """CodeQL's real ``revisionId`` must equal the inventory head, with or without a named head."""
    codeql = _document(CODEQL)
    assert codeql.runs[0]["versionControlProvenance"][0]["revisionId"] == CODEQL_REVISION
    assert bind_head(codeql, CODEQL_REVISION, None) == CODEQL_REVISION
    assert bind_head(codeql, CODEQL_REVISION, CODEQL_REVISION) == CODEQL_REVISION
    assert _refusal(lambda: bind_head(codeql, OTHER_HEAD, None)) == "revision-mismatch"
    assert _refusal(lambda: bind_head(codeql, OTHER_HEAD, OTHER_HEAD)) == "revision-mismatch"
    assert _refusal(lambda: bind_head(codeql, CODEQL_REVISION, OTHER_HEAD)) == "head-mismatch"


def test_every_run_is_bound_by_its_own_revision_or_by_the_named_head() -> None:
    """A second run without a revision needs the named head even when the first states one."""

    def second_run_without_revision(document: dict[str, Any]) -> None:
        run = copy.deepcopy(document["runs"][0])
        del run["versionControlProvenance"]
        document["runs"].append(run)

    two_runs = _variant(CODEQL, second_run_without_revision)
    assert _refusal(lambda: bind_head(two_runs, CODEQL_REVISION, None)) == "head-required"
    assert bind_head(two_runs, CODEQL_REVISION, CODEQL_REVISION) == CODEQL_REVISION


@pytest.mark.parametrize("path", [SEMGREP, TRIVY])
def test_without_a_stated_revision_the_operator_must_name_the_inventory_head(path: Path) -> None:
    """Semgrep and Trivy state no revision, so the head is required and must be the inventory's.

    Parameters
    ----------
    path : Path
        Real producer output without ``versionControlProvenance``.
    """
    document = _document(path)
    assert "versionControlProvenance" not in document.runs[0]
    assert bind_head(document, OTHER_HEAD, OTHER_HEAD) == OTHER_HEAD
    assert _refusal(lambda: bind_head(document, OTHER_HEAD, None)) == "head-required"
    assert _refusal(lambda: bind_head(document, OTHER_HEAD, "c" * 40)) == "head-mismatch"


@pytest.mark.parametrize(
    ("provenance", "reason"),
    [
        ({"revisionId": CODEQL_REVISION}, "malformed-version-control"),
        (["main"], "malformed-version-control"),
        ([{"revisionId": "main"}], "malformed-version-control"),
        ([{"revisionId": CODEQL_REVISION.upper()}], "malformed-version-control"),
        ([{"revisionId": None}], "malformed-version-control"),
        ([{"repositoryUri": "https://github.com/anulum/rigor-foundry"}], "head-required"),
    ],
)
def test_malformed_version_control_is_refused(provenance: object, reason: str) -> None:
    """A non-array, a non-object entry or a revision that is not an object id is refused.

    Parameters
    ----------
    provenance : object
        The run's ``versionControlProvenance``.
    reason : str
        The refusal reason without a named head.
    """

    def change(document: dict[str, Any]) -> None:
        document["runs"][0]["versionControlProvenance"] = provenance

    document = _variant(CODEQL, change)
    assert _refusal(lambda: bind_head(document, CODEQL_REVISION, None)) == reason
