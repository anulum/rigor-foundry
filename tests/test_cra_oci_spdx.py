# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — OCI SPDX inventory acceptance tests
"""Exercise explicit OCI SPDX import, content binding and offline record replay."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_cra_component_evidence_cli import NOW, repository
from test_cra_inventory import spdx

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.cli import main
from rigor_foundry.cra_component_evidence_store import CraComponentEvidenceStore
from rigor_foundry.cra_inventory import ComponentInventory
from rigor_foundry.cra_oci_inventory import OCI_SBOM_FORMAT
from rigor_foundry.cra_sbom import parse_sbom_source

ROOT_ID = "SPDXRef-DocumentRoot-Directory-sbom"
IMAGE_DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
CPE = "cpe:2.3:a:Example:Launcher:1.0:*:*:*:*:*:*:*"
SECOND_CPE = r"cpe:2.3:a:Example:Other\:Launcher:1.0:*:*:*:*:*:*:*"

Package = dict[str, object]


def reference(kind: str, locator: str, *, category: str) -> dict[str, str]:
    """Create a declared external reference."""
    return {"referenceCategory": category, "referenceType": kind, "referenceLocator": locator}


def package(
    identifier: str,
    *,
    refs: tuple[dict[str, str], ...] = (),
    name: str = "launcher",
) -> Package:
    """Create a versioned package, with explicit SPDX instance identity."""
    return {
        "SPDXID": identifier,
        "name": name,
        "versionInfo": "1.0",
        "externalRefs": list(refs),
    }


def relation(source: str, kind: str, target: str) -> dict[str, str]:
    """Return one directed SPDX relationship."""
    return {"spdxElementId": source, "relationshipType": kind, "relatedSpdxElement": target}


def root_package() -> Package:
    """Build the versionless synthetic FILE directory marker."""
    return {"SPDXID": ROOT_ID, "name": "sbom", "primaryPackagePurpose": "FILE"}


def predicate(
    *,
    packages: list[Package] | None = None,
    relationships: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    """Construct a bounded SPDX document with direct and transitive packages."""
    if packages is None:
        packages = [
            root_package(),
            package("SPDXRef-A", refs=(reference("cpe23Type", CPE, category="SECURITY"),)),
            package("SPDXRef-B", refs=(reference("cpe23Type", SECOND_CPE, category="SECURITY"),)),
            package(
                "SPDXRef-C",
                refs=(reference("purl", "pkg:pypi/launcher@1.0", category="PACKAGE-MANAGER"),),
            ),
            package("SPDXRef-D", name="nested"),
        ]
    if relationships is None:
        relationships = [
            relation("SPDXRef-DOCUMENT", "DESCRIBES", ROOT_ID),
            relation(ROOT_ID, "CONTAINS", "SPDXRef-A"),
            relation(ROOT_ID, "CONTAINS", "SPDXRef-B"),
            relation(ROOT_ID, "CONTAINS", "SPDXRef-C"),
            relation("SPDXRef-A", "CONTAINS", "SPDXRef-D"),
        ]
    data = cast(dict[str, object], json.loads(spdx()))
    del data["documentDescribes"]
    return data | {"packages": packages, "relationships": relationships}


def statement(**changes: object) -> bytes:
    """Encode one explicit in-toto statement with the declared OCI manifest."""
    data = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://spdx.dev/Document",
        "subject": [{"name": "pkg:docker/example", "digest": {"sha256": IMAGE_DIGEST}}],
        "predicate": predicate(),
    }
    return json.dumps(data | changes).encode()


def with_package(candidate: Package) -> bytes:
    """Encode a statement that directly contains the selected package."""
    data = predicate(
        packages=[root_package(), candidate],
        relationships=[
            relation("SPDXRef-DOCUMENT", "DESCRIBES", ROOT_ID),
            relation(ROOT_ID, "CONTAINS", "SPDXRef-A"),
        ],
    )
    return statement(predicate=data)


def import_args(repo: Path, source: Path, **changes: str | None) -> list[str]:
    """Return real CLI arguments with file and selected image identities."""
    options: dict[str, str | None] = {
        "root": str(repo),
        "product-key": "PRODUCT-1",
        "file": str(source),
        "format": OCI_SBOM_FORMAT,
        "source-tool": "buildkit@0.31.2",
        "source-evidence": "image-review:7",
        "coverage": "top-level-only",
        "captured-at": NOW,
        "statement-sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "image-manifest-sha256": IMAGE_DIGEST,
    }
    return [
        "sbom-import",
        *[
            value
            for key, option in (options | changes).items()
            if option is not None
            for value in (f"--{key}", option)
        ],
    ]


def test_explicit_oci_profile_round_trips_selected_packages_and_verbatim_cpes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Import original bytes and read exact CPE evidence through real CLI and Git."""
    repo = repository(tmp_path)
    source = tmp_path / "statement.json"
    payload = statement()
    source.write_bytes(payload)
    args = import_args(repo.root, source)
    assert main(args) == 0
    assert main(args) == 0
    store = CraComponentEvidenceStore.open(repo.root)
    record = store.current_inventory("PRODUCT-1")
    assert record.sbom_format == OCI_SBOM_FORMAT
    assert record.covers_top_level_only is True
    assert record.sbom_sha256 == hashlib.sha256(payload).hexdigest()
    assert (
        store.base.storage_root / "sboms" / f"{record.sbom_sha256}.json"
    ).read_bytes() == payload
    assert [(c.name, c.version, c.purl) for c in record.top_level_components] == [
        ("launcher", "1.0", None),
        ("launcher", "1.0", "pkg:pypi/launcher@1.0"),
    ]
    image = record.to_dict()["oci_image"]
    assert image == {
        "manifest_sha256": IMAGE_DIGEST,
        "projection": "direct-root-contains",
        "retained_cpe23": [
            {"name": "launcher", "version": "1.0", "locators": sorted((CPE, SECOND_CPE))}
        ],
    }
    status = [
        "sbom-status",
        "--root",
        str(repo.root),
        "--product-key",
        "PRODUCT-1",
        "--observed-at",
        NOW,
    ]
    capsys.readouterr()
    assert main(status) == 0
    assert json.loads(capsys.readouterr().out)["inventory"]["oci_image"] == image

    assert record.oci_image is not None
    with pytest.raises(ValueError, match="OCI image binding is required"):
        ComponentInventory.build(
            product_key=record.product_key,
            sbom_format=record.sbom_format,
            sbom_sha256=record.sbom_sha256,
            source_tool=record.source_tool,
            captured_at=record.captured_at,
            top_level_components=record.top_level_components,
            covers_top_level_only=record.covers_top_level_only,
            tree_binding=record.tree_binding,
        )
    forged_image = replace(record.oci_image, manifest_sha256=OTHER_DIGEST)
    forged = record.to_dict() | {"oci_image": forged_image.to_dict()}
    del forged["inventory_digest"]
    digest = canonical_digest(forged)
    forged["inventory_digest"] = digest
    forged_record = ComponentInventory.from_dict(forged)
    with pytest.raises(ValueError, match="SBOM OCI image binding does not match"):
        store.append_inventory(forged_record, payload.decode())
    directory = store.base.storage_root / "inventories" / "PRODUCT-1"
    original = directory / f"{record.inventory_digest}.json"
    forged_path = directory / f"{digest}.json"
    original.rename(forged_path)
    forged_path.write_text(forged_record.to_json(), encoding="utf-8", newline="\n")
    with pytest.raises(ValueError, match="stored SBOM OCI image binding does not match"):
        store.current_inventory("PRODUCT-1")


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"statement-sha256": None}, "--statement-sha256"),
        ({"statement-sha256": OTHER_DIGEST}, "statement SHA-256 does not match"),
        ({"image-manifest-sha256": None}, "--image-manifest-sha256"),
        ({"image-manifest-sha256": OTHER_DIGEST}, "does not match the expected manifest"),
        ({"coverage": "declared-complete"}, "must declare top-level-only"),
        ({"format": "spdx-2.3"}, "OCI SHA-256 arguments require"),
        (
            {"format": "spdx-2.3", "statement-sha256": None, "image-manifest-sha256": None},
            "must declare spdxVersion SPDX-2.3",
        ),
    ],
)
def test_oci_cli_wrong_profile_digests_or_scope_leave_no_record(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    changes: dict[str, str | None],
    message: str,
) -> None:
    """Reject unsafe assumptions before an inventory or SBOM is written."""
    repo = repository(tmp_path)
    source = tmp_path / "statement.json"
    source.write_bytes(statement())
    assert main(import_args(repo.root, source, **changes)) == 2
    assert message in capsys.readouterr().err
    store = CraComponentEvidenceStore.open(repo.root)
    assert store.inventories("PRODUCT-1") == ()
    assert not list((store.base.storage_root / "sboms").glob("*.json"))


@pytest.mark.parametrize(
    ("package_index", "external_refs", "message"),
    [
        (
            1,
            [reference("purl", "pkg:generic/ns%2Fother/widget@1", category="PACKAGE-MANAGER")],
            "invalid package URL",
        ),
        (
            1,
            [reference("purl", "pkg:generic/widget@1#src%2flib", category="PACKAGE-MANAGER")],
            "invalid package URL",
        ),
        (
            1,
            [reference("purl", "pkg:gene+ric/widget@1", category="PACKAGE-MANAGER")],
            "invalid package URL",
        ),
        (0, "not an array", "externalRefs must be an array"),
        (
            0,
            [reference("purl", "pkg:pypi/root@", category="PACKAGE-MANAGER")],
            "invalid package URL",
        ),
        (0, [reference("cpe23Type", "not-a-cpe", category="SECURITY")], "CPE 2.3"),
        (
            1,
            [reference("purl", "pkg:generic/one+two@1", category="PACKAGE-MANAGER")],
            "invalid package URL",
        ),
        (
            1,
            [reference("purl", "pkg:generic/widget@1+vendor", category="PACKAGE-MANAGER")],
            "invalid package URL",
        ),
        (
            1,
            [reference("purl", "pkg:generic/a+b/widget@1", category="PACKAGE-MANAGER")],
            "invalid package URL",
        ),
        (
            1,
            [reference("purl", "pkg:generic/widget@1#src/a+b", category="PACKAGE-MANAGER")],
            "invalid package URL",
        ),
        (
            1,
            [reference("purl", "pkg:generic/widget@1?arch=a+b", category="PACKAGE-MANAGER")],
            "invalid package URL",
        ),
        (
            1,
            [reference("LocationRef-catalogue", "index-1", category="UNKNOWN")],
            "unsupported SPDX referenceCategory",
        ),
        (
            0,
            [reference("LocationRef-catalogue", "index 1", category="OTHER")],
            "referenceLocator must not contain whitespace",
        ),
        (
            0,
            [reference("LocationRef-catalogue", "index-1", category="OTHER") | {"comment": 1}],
            "comment must be a string",
        ),
        (
            1,
            [reference("LocationRef-catalogue", "index-1", category="OTHER") | {"extra": "x"}],
            "unknown external reference field",
        ),
    ],
)
def test_oci_cli_refuses_invalid_purl_segments_and_synthetic_root_refs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    package_index: int,
    external_refs: object,
    message: str,
) -> None:
    """Reject malformed package and structural-root references before any write."""
    repo = repository(tmp_path)
    document = predicate()
    packages = cast(list[Package], document["packages"])
    packages[package_index]["externalRefs"] = external_refs
    source = tmp_path / "statement.json"
    source.write_bytes(statement(predicate=document))
    assert main(import_args(repo.root, source)) == 2
    assert message in capsys.readouterr().err
    store = CraComponentEvidenceStore.open(repo.root)
    assert store.inventories("PRODUCT-1") == ()
    assert not list((store.base.storage_root / "sboms").glob("*.json"))


def test_oci_cli_retains_encoded_plus_and_preserves_generic_reference_compatibility(
    tmp_path: Path,
) -> None:
    """Store a percent-encoded literal and preserve ordinary SPDX parsing."""
    repo = repository(tmp_path)
    locator = "pkg:generic/a%2Bb/widget%2Bextra@1%2Bvendor?arch=a%2Bb#src/a%2Bb"
    candidate = package(
        "SPDXRef-A",
        refs=(reference("purl", locator, category="PACKAGE-MANAGER") | {"comment": "original"},),
    )
    source = tmp_path / "statement.json"
    source.write_bytes(with_package(candidate))
    assert main(import_args(repo.root, source)) == 0
    store = CraComponentEvidenceStore.open(repo.root)
    record = store.current_inventory("PRODUCT-1")
    assert record.top_level_components[0].purl == locator
    ordinary = cast(dict[str, object], json.loads(spdx()))
    (package_row,) = cast(list[Package], ordinary["packages"])
    refs = cast(list[dict[str, str]], package_row["externalRefs"])
    refs.append(reference("LocationRef-catalogue", "index 1", category="LEGACY"))
    components, binding = parse_sbom_source(json.dumps(ordinary).encode(), "spdx-2.3")
    assert components[0].purl == "pkg:pypi/alpha@1.0" and binding is None


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"_type": "https://in-toto.io/Statement/v0.1"}, "Statement v1"),
        ({"predicateType": "https://slsa.dev/provenance/v1"}, "SPDX document predicate"),
        ({"subject": None}, "exactly one image subject"),
        ({"subject": []}, "exactly one image subject"),
        ({"subject": [{}, {}]}, "exactly one image subject"),
        ({"subject": [{"name": "image", "digest": {"sha256": "no"}}]}, "lowercase SHA-256"),
        ({"predicate": predicate() | {"spdxVersion": "SPDX-2.2"}}, "spdxVersion SPDX-2.3"),
        ({"predicate": predicate(packages=[package("SPDXRef-A")])}, "exactly one synthetic root"),
        (
            {
                "predicate": predicate(
                    packages=[
                        root_package(),
                        root_package() | {"SPDXID": "SPDXRef-DocumentRoot-Directory-second"},
                    ]
                )
            },
            "exactly one synthetic root",
        ),
        (
            {"predicate": predicate(packages=[root_package() | {"versionInfo": "1"}])},
            "versionless FILE",
        ),
        (
            {
                "predicate": predicate(
                    relationships=[relation("SPDXRef-DOCUMENT", "DESCRIBES", ROOT_ID)]
                )
            },
            "directly contain unique",
        ),
        (
            {
                "predicate": predicate(
                    relationships=[
                        relation("SPDXRef-DOCUMENT", "DESCRIBES", ROOT_ID),
                        relation(ROOT_ID, "CONTAINS", "SPDXRef-A"),
                        relation(ROOT_ID, "CONTAINS", "SPDXRef-A"),
                    ]
                )
            },
            "directly contain unique",
        ),
        (
            {
                "predicate": predicate(
                    relationships=[
                        relation("SPDXRef-DOCUMENT", "DESCRIBES", ROOT_ID),
                        relation(ROOT_ID, "CONTAINS", "SPDXRef-NotDeclared"),
                    ]
                )
            },
            "directly contain unique",
        ),
    ],
)
def test_oci_statement_rejects_ambiguous_or_unbound_input(
    changes: dict[str, object], message: str
) -> None:
    """Check the image subject, predicate format and declared package graph."""
    with pytest.raises(ValueError, match=message):
        parse_sbom_source(statement(**changes), OCI_SBOM_FORMAT)


@pytest.mark.parametrize(
    "locator",
    [
        "https://example.invalid/pkg",
        "pkg:noslash",
        "pkg:UPPER/name",
        "pkg:pypi//name",
        "pkg:npm/name@",
        "pkg:npm/name%ZZ",
        "pkg:npm/name%FF",
        "pkg:npm/%00",
        "pkg:npm/name#../lib",
        "pkg:npm/name#%2E%2E/lib",
        "pkg:npm/name#lib//file",
        "pkg:npm/name?missing",
        "pkg:npm/name?1bad=value",
        "pkg:npm/name?arch=a&arch=b",
        "pkg:npm/name?arch=",
    ],
)
def test_oci_profile_refuses_malformed_supplied_purls(locator: str) -> None:
    """Refuse invalid PURL syntax while accepting genuinely absent PURLs."""
    candidate = package(
        "SPDXRef-A", refs=(reference("purl", locator, category="PACKAGE-MANAGER"),)
    )
    with pytest.raises(ValueError, match="invalid package URL"):
        parse_sbom_source(with_package(candidate), OCI_SBOM_FORMAT)


@pytest.mark.parametrize(
    "locator",
    [
        "pkg:npm/%40scope/widget@1.0?arch=x64&distro=ubuntu#lib/bin",
        "pkg:generic/widget%2Fextension@release%2F1",
    ],
)
def test_oci_profile_preserves_a_complete_purl_spelling(locator: str) -> None:
    """Version, qualifiers and a subpath must retain their original spelling."""
    candidate = package(
        "SPDXRef-A", refs=(reference("purl", locator, category="PACKAGE-MANAGER"),)
    )
    components, binding = parse_sbom_source(with_package(candidate), OCI_SBOM_FORMAT)
    assert components[0].purl == locator
    assert binding is not None
    assert binding.retained_cpe23 == ()


@pytest.mark.parametrize(
    ("candidate", "message"),
    [
        (package("SPDXRef-A") | {"versionInfo": None}, "versionInfo"),
        (
            package("SPDXRef-A", refs=(reference("purl", "pkg:pypi/widget", category="OTHER"),)),
            "PACKAGE-MANAGER",
        ),
        (
            package("SPDXRef-A", refs=(reference("cpe23Type", CPE, category="OTHER"),)),
            "SECURITY",
        ),
        (
            package("SPDXRef-A", refs=(reference("cpe23Type", "bad", category="SECURITY"),)),
            "CPE 2.3",
        ),
    ],
)
def test_oci_profile_refuses_missing_versions_and_malformed_references(
    candidate: Package, message: str
) -> None:
    """The importer refuses incomplete packages and malformed typed references."""
    with pytest.raises(ValueError, match=message):
        parse_sbom_source(with_package(candidate), OCI_SBOM_FORMAT)


@pytest.mark.parametrize(
    ("image_change", "message"),
    [
        ({"projection": "transitive"}, "must declare direct-root-contains"),
        ({"retained_cpe23": {}}, "must be an array"),
        (
            {"retained_cpe23": [{"name": "launcher", "version": "1.0", "locators": []}]},
            "non-empty array",
        ),
        (
            {"retained_cpe23": [{"name": "launcher", "version": "1.0", "locators": [CPE, CPE]}]},
            "locators must be unique and sorted",
        ),
        (
            {
                "retained_cpe23": [
                    {"name": "launcher", "version": "1.0", "locators": [CPE]},
                    {"name": "launcher", "version": "1.0", "locators": [SECOND_CPE]},
                ]
            },
            "component identities must be unique and sorted",
        ),
        (
            {"retained_cpe23": [{"name": "unrecorded", "version": "1.0", "locators": [CPE]}]},
            "must identify a projected null-PURL component",
        ),
    ],
)
def test_oci_record_reader_rejects_noncanonical_projection_metadata(
    tmp_path: Path, image_change: dict[str, object], message: str
) -> None:
    """Reject rewritten image bindings even after recomputing an evidence digest."""
    repo = repository(tmp_path)
    source = tmp_path / "statement.json"
    source.write_bytes(statement())
    assert main(import_args(repo.root, source)) == 0
    store = CraComponentEvidenceStore.open(repo.root)
    record = store.current_inventory("PRODUCT-1")
    assert record.oci_image is not None
    rewritten = record.to_dict() | {"oci_image": record.oci_image.to_dict() | image_change}
    del rewritten["inventory_digest"]
    rewritten["inventory_digest"] = canonical_digest(rewritten)
    with pytest.raises(ValueError, match=message):
        ComponentInventory.from_dict(rewritten)
