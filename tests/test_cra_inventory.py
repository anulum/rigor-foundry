# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA component-inventory tests
"""Exercise imported SBOM parsing, identities, bounds, and Git drift evidence."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.cra_inventory import (
    ComponentInventory,
    InventoryComponent,
    InventoryDriftEvidence,
    RepositoryBinding,
    SourceToolEvidence,
)
from rigor_foundry.cra_sbom import MAX_SBOM_BYTES, parse_sbom, read_import_file
from rigor_foundry.git_inventory import load_git_inventory


def cyclonedx(version: str = "1.5") -> bytes:
    """Return a valid bounded CycloneDX fixture with deliberately unsorted components."""
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": version,
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "zeta",
                    "version": "2.0",
                    "purl": "pkg:pypi/zeta@2.0",
                },
                {"type": "application", "name": "alpha", "version": "1.0"},
            ],
        },
        sort_keys=True,
    ).encode()


def spdx() -> bytes:
    """Return a valid bounded SPDX 2.3 JSON fixture."""
    return json.dumps(
        {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "fixture",
            "documentNamespace": "https://example.invalid/spdx/fixture",
            "documentDescribes": ["SPDXRef-Package-alpha"],
            "creationInfo": {
                "created": "2026-07-20T00:00:00Z",
                "creators": ["Tool: fixture-1.0"],
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-alpha",
                    "name": "alpha",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/alpha@1.0",
                        }
                    ],
                }
            ],
        },
        sort_keys=True,
    ).encode()


@pytest.mark.parametrize(
    ("sbom_format", "payload", "expected"),
    [
        ("cyclonedx-1.5", cyclonedx("1.5"), ("zeta", "alpha")),
        ("cyclonedx-1.6", cyclonedx("1.6"), ("zeta", "alpha")),
        ("spdx-2.3", spdx(), ("alpha",)),
    ],
)
def test_supported_sbom_profiles_extract_only_explicit_components(
    sbom_format: str,
    payload: bytes,
    expected: tuple[str, ...],
) -> None:
    """Every promised format validates its consumed schema and preserves source order."""
    components = parse_sbom(payload, sbom_format)  # type: ignore[arg-type]
    assert tuple(item.name for item in components) == expected


@pytest.mark.parametrize(
    ("payload", "sbom_format", "message"),
    [
        (b'{"bomFormat":"CycloneDX",', "cyclonedx-1.5", "not complete"),
        (
            b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}',
            "cyclonedx-1.5",
            "duplicate",
        ),
        (cyclonedx("1.5"), "cyclonedx-1.6", "specVersion 1.6"),
        (spdx().replace(b'"SPDX-2.3"', b'"SPDX-2.2"'), "spdx-2.3", "SPDX-2.3"),
    ],
)
def test_sbom_profiles_fail_closed_on_ambiguous_or_wrong_schema(
    payload: bytes,
    sbom_format: str,
    message: str,
) -> None:
    """Truncation, duplicate keys, and mismatched versions cannot produce inventory."""
    with pytest.raises(ValueError, match=message):
        parse_sbom(payload, sbom_format)  # type: ignore[arg-type]


def test_inventory_is_sorted_content_addressed_and_detects_git_drift(tmp_path: Path) -> None:
    """The public records bind sorted components and exact clean or dirty Git content."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("tracked.txt", "first\n")
    repository.commit()
    payload = cyclonedx()
    components = parse_sbom(payload, "cyclonedx-1.5")
    clean_binding = RepositoryBinding.from_inventory(load_git_inventory(repository.root))
    inventory = ComponentInventory.build(
        product_key="PRODUCT-1",
        sbom_format="cyclonedx-1.5",
        sbom_sha256=hashlib.sha256(payload).hexdigest(),
        source_tool=SourceToolEvidence.build(
            name="generator", version="1.2.3", evidence_ref="build-log:7"
        ),
        captured_at="2026-07-20T10:00:00Z",
        top_level_components=components,
        covers_top_level_only=True,
        tree_binding=clean_binding,
    )

    assert ComponentInventory.from_dict(inventory.to_dict()) == inventory
    assert tuple(item.name for item in inventory.top_level_components) == ("alpha", "zeta")
    assert not InventoryDriftEvidence.build(
        inventory,
        clean_binding,
        observed_at="2026-07-20T10:01:00Z",
    ).drifted

    repository.write_text("tracked.txt", "changed\n")
    drift = InventoryDriftEvidence.build(
        inventory,
        RepositoryBinding.from_inventory(load_git_inventory(repository.root)),
        observed_at="2026-07-20T10:02:00Z",
    )
    assert drift.drifted
    assert drift.tracked_content_changed
    assert not drift.head_changed
    assert not drift.tree_changed
    assert InventoryDriftEvidence.from_dict(drift.to_dict()) == drift

    mutated = inventory.to_dict()
    mutated["inventory_digest"] = "0" * 64
    with pytest.raises(ValueError, match="digest does not match"):
        ComponentInventory.from_dict(mutated)
    contradictory = drift.to_dict()
    contradictory["drifted"] = False
    with pytest.raises(ValueError, match="contradicts"):
        InventoryDriftEvidence.from_dict(contradictory)


def test_component_and_binding_validation_rejects_ambiguity() -> None:
    """Duplicate components, invalid purls, and object-format mismatches fail closed."""
    component = InventoryComponent.build(name="alpha", version="1", purl=None)
    with pytest.raises(ValueError, match="package-url"):
        InventoryComponent.build(name="alpha", version="1", purl="https://invalid")
    binding = RepositoryBinding(
        head="1" * 40,
        tree_oid="2" * 40,
        tracked_content_sha256="3" * 64,
        object_format="sha1",
    )
    with pytest.raises(ValueError, match="unique"):
        ComponentInventory.build(
            product_key="PRODUCT-1",
            sbom_format="cyclonedx-1.5",
            sbom_sha256="4" * 64,
            source_tool=SourceToolEvidence.build(
                name="tool", version="1", evidence_ref="evidence"
            ),
            captured_at="2026-07-20T10:00:00Z",
            top_level_components=(component, component),
            covers_top_level_only=True,
            tree_binding=binding,
        )
    invalid_binding = {**binding.to_dict(), "object_format": "sha256"}
    with pytest.raises(ValueError, match="contradict"):
        RepositoryBinding.from_dict(invalid_binding)
    with pytest.raises(ValueError, match="unsupported"):
        RepositoryBinding.from_dict({**binding.to_dict(), "object_format": "sha512"})


def test_inventory_and_drift_schema_guards_reject_invalid_envelopes() -> None:
    """Version, array, Boolean, empty-set, format, and drift digests are fail-closed."""
    component = InventoryComponent.build(name="alpha", version="1", purl=None)
    binding = RepositoryBinding(
        head="1" * 40,
        tree_oid="2" * 40,
        tracked_content_sha256="3" * 64,
        object_format="sha1",
    )
    arguments = {
        "product_key": "PRODUCT-1",
        "sbom_format": "cyclonedx-1.5",
        "sbom_sha256": "4" * 64,
        "source_tool": SourceToolEvidence.build(name="tool", version="1", evidence_ref="evidence"),
        "captured_at": "2026-07-20T10:00:00Z",
        "top_level_components": (component,),
        "covers_top_level_only": True,
        "tree_binding": binding,
    }
    with pytest.raises(ValueError, match="unsupported"):
        ComponentInventory.build(**{**arguments, "sbom_format": "unknown"})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="boolean"):
        ComponentInventory.build(**{**arguments, "covers_top_level_only": 1})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="at least one"):
        ComponentInventory.build(**{**arguments, "top_level_components": ()})  # type: ignore[arg-type]

    inventory = ComponentInventory.build(**arguments)  # type: ignore[arg-type]
    wrong_version = {**inventory.to_dict(), "schema_version": "2.0"}
    with pytest.raises(ValueError, match="schema_version"):
        ComponentInventory.from_dict(wrong_version)
    wrong_array = {**inventory.to_dict(), "top_level_components": {}}
    with pytest.raises(ValueError, match="must be an array"):
        ComponentInventory.from_dict(wrong_array)

    drift = InventoryDriftEvidence.build(
        inventory,
        binding,
        observed_at="2026-07-20T10:01:00Z",
    )
    with pytest.raises(ValueError, match="schema_version"):
        InventoryDriftEvidence.from_dict({**drift.to_dict(), "schema_version": "2.0"})
    with pytest.raises(ValueError, match="digest does not match"):
        InventoryDriftEvidence.from_dict({**drift.to_dict(), "drift_digest": "0" * 64})


def test_stable_import_reader_rejects_oversize_symlink_and_multiple_links(
    tmp_path: Path,
) -> None:
    """The real file boundary rejects inputs that cannot be captured exactly once."""
    regular = tmp_path / "regular.json"
    regular.write_bytes(b"{}")
    payload, digest = read_import_file(regular, maximum_bytes=2, label="fixture")
    assert payload == b"{}"
    assert digest == hashlib.sha256(payload).hexdigest()

    oversize = tmp_path / "oversize.json"
    oversize.write_bytes(b"123")
    with pytest.raises(ValueError, match="exceeds"):
        read_import_file(oversize, maximum_bytes=2, label="fixture")

    link = tmp_path / "link.json"
    link.symlink_to(regular)
    with pytest.raises(RuntimeError, match=r"not one regular file|cannot access"):
        read_import_file(link, maximum_bytes=MAX_SBOM_BYTES, label="fixture")

    hardlink = tmp_path / "hardlink.json"
    os.link(regular, hardlink)
    with pytest.raises(RuntimeError, match="multiple hard links"):
        read_import_file(regular, maximum_bytes=MAX_SBOM_BYTES, label="fixture")


def test_inventory_parser_rejects_unsorted_imported_record() -> None:
    """Imported records cannot use ordering to create a second identity."""
    alpha = InventoryComponent.build(name="alpha", version="1", purl=None)
    zeta = InventoryComponent.build(name="zeta", version="1", purl=None)
    binding = RepositoryBinding(
        head="1" * 40,
        tree_oid="2" * 40,
        tracked_content_sha256="3" * 64,
        object_format="sha1",
    )
    inventory = ComponentInventory.build(
        product_key="PRODUCT-1",
        sbom_format="cyclonedx-1.5",
        sbom_sha256="4" * 64,
        source_tool=SourceToolEvidence.build(name="tool", version="1", evidence_ref="evidence"),
        captured_at="2026-07-20T10:00:00Z",
        top_level_components=(zeta, alpha),
        covers_top_level_only=True,
        tree_binding=binding,
    )
    changed = inventory.to_dict()
    changed["top_level_components"] = list(reversed(changed["top_level_components"]))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="canonical sort order"):
        ComponentInventory.from_dict(changed)
    assert replace(inventory, inventory_digest="0" * 64) != inventory
