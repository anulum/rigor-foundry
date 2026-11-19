# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — SPDX component evidence framing
"""Validate the SPDX fields consumed by the offline inventory profiles."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import cast

from .cra_inventory import InventoryComponent
from .models import require_mapping, require_string

_REFERENCE_CATEGORIES = frozenset({"OTHER", "PERSISTENT-ID", "SECURITY", "PACKAGE-MANAGER"})
_REFERENCE_FIELDS = frozenset(
    {"referenceCategory", "referenceType", "referenceLocator", "comment"}
)


def spdx_references(
    package: dict[str, object], field: str, *, strict: bool = False
) -> Iterator[tuple[str, str, str]]:
    """Yield the nonempty category, type and locator for each declared reference."""
    raw_refs = package.get("externalRefs", [])
    if not isinstance(raw_refs, list):
        raise ValueError(f"{field}.externalRefs must be an array")
    for index, raw in enumerate(cast(list[object], raw_refs)):
        ref_field = f"{field}.externalRefs[{index}]"
        ref = require_mapping(raw, ref_field)
        category = require_string(ref.get("referenceCategory"), f"{ref_field}.referenceCategory")
        kind = require_string(ref.get("referenceType"), f"{ref_field}.referenceType")
        locator = require_string(ref.get("referenceLocator"), f"{ref_field}.referenceLocator")
        if strict:
            if ref.keys() - _REFERENCE_FIELDS:
                raise ValueError(f"{ref_field} contains an unknown external reference field")
            if "comment" in ref and not isinstance(ref["comment"], str):
                raise ValueError(f"{ref_field}.comment must be a string")
            if category not in _REFERENCE_CATEGORIES:
                raise ValueError(f"{ref_field} has an unsupported SPDX referenceCategory")
            if any(character.isspace() for character in locator):
                raise ValueError(f"{ref_field}.referenceLocator must not contain whitespace")
        yield category, kind, locator


def spdx_purl(references: tuple[tuple[str, str, str], ...], field: str) -> str | None:
    """Extract at most one Package URL from SPDX 2.3 external references."""
    purls: list[str] = []
    for index, (category, reference_type, locator) in enumerate(references):
        if reference_type == "purl":
            if category != "PACKAGE-MANAGER":
                raise ValueError(
                    f"{field}.externalRefs[{index}] purl must use PACKAGE-MANAGER category"
                )
            purls.append(locator)
    if len(purls) > 1:
        raise ValueError(f"{field} contains multiple purl external references")
    return purls[0] if purls else None


def _spdx_id_array(value: object, field: str) -> tuple[str, ...]:
    """Return one non-empty unique SPDX identifier array."""
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty array")
    identifiers = tuple(
        require_string(item, f"{field}[{index}]") for index, item in enumerate(value)
    )
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{field} identifiers must be unique")
    return identifiers


def spdx_described_ids(
    data: dict[str, object], relationships: tuple[tuple[str, str, str], ...]
) -> tuple[str, ...]:
    """Resolve exact document-level package identities without flattening dependencies."""
    declared = (
        ()
        if data.get("documentDescribes") is None
        else _spdx_id_array(data.get("documentDescribes"), "documentDescribes")
    )
    related: list[str] = []
    for source, relation, target in relationships:
        if source == "SPDXRef-DOCUMENT" and relation == "DESCRIBES":
            related.append(target)
        elif target == "SPDXRef-DOCUMENT" and relation == "DESCRIBED_BY":
            related.append(source)
    if len(related) != len(set(related)):
        raise ValueError("document DESCRIBES relationships must be unique")
    relation_ids = tuple(related)
    if declared and relation_ids and frozenset(declared) != frozenset(relation_ids):
        raise ValueError("documentDescribes and DESCRIBES relationships disagree")
    result = declared or relation_ids
    if not result:
        raise ValueError("SPDX SBOM must identify top-level packages with documentDescribes")
    return result


def spdx_relationships(data: dict[str, object]) -> Iterator[tuple[str, str, str]]:
    """Yield well-formed SPDX relationships in document order."""
    raw_relationships = data.get("relationships", [])
    if not isinstance(raw_relationships, list):
        raise ValueError("relationships must be an array")
    for index, raw in enumerate(cast(list[object], raw_relationships)):
        field = f"relationships[{index}]"
        relationship = require_mapping(raw, field)
        source = require_string(relationship.get("spdxElementId"), f"{field}.spdxElementId")
        relation = require_string(
            relationship.get("relationshipType"), f"{field}.relationshipType"
        )
        target = require_string(
            relationship.get("relatedSpdxElement"), f"{field}.relatedSpdxElement"
        )
        yield source, relation, target


def spdx_document(document: object) -> dict[str, object]:
    """Validate the consumed SPDX 2.3 envelope and creation fields."""
    data = require_mapping(document, "SPDX SBOM")
    if data.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("SPDX SBOM must declare spdxVersion SPDX-2.3")
    if data.get("dataLicense") != "CC0-1.0" or data.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError("SPDX SBOM must declare CC0-1.0 and SPDXRef-DOCUMENT")
    require_string(data.get("name"), "SPDX document.name")
    require_string(data.get("documentNamespace"), "SPDX document.documentNamespace")
    creation = require_mapping(data.get("creationInfo"), "SPDX document.creationInfo")
    require_string(creation.get("created"), "SPDX document.creationInfo.created")
    creators = creation.get("creators")
    if (
        not isinstance(creators, list)
        or not creators
        or not all(isinstance(item, str) and item.strip() for item in creators)
    ):
        raise ValueError("SPDX document.creationInfo.creators must contain strings")
    return data


def spdx_packages(
    raw_packages: list[object],
) -> Iterator[tuple[str, str, dict[str, object]]]:
    """Yield uniquely identified SPDX packages in their source order."""
    identifiers: set[str] = set()
    for index, raw in enumerate(raw_packages):
        field = f"packages[{index}]"
        item = require_mapping(raw, field)
        spdx_id = require_string(item.get("SPDXID"), f"{field}.SPDXID")
        if not spdx_id.startswith("SPDXRef-") or spdx_id in identifiers:
            raise ValueError(f"{field}.SPDXID must be a unique SPDXRef identifier")
        identifiers.add(spdx_id)
        yield spdx_id, field, item


def spdx_components(
    document: object,
    component_array: Callable[[object, str], list[object]],
) -> tuple[InventoryComponent, ...]:
    """Validate generic SPDX packages and return exactly the document's described roots."""
    data = spdx_document(document)
    components: dict[str, InventoryComponent] = {}
    for spdx_id, field, item in spdx_packages(component_array(data.get("packages"), "packages")):
        components[spdx_id] = InventoryComponent.build(
            name=require_string(item.get("name"), f"{field}.name"),
            version=require_string(item.get("versionInfo"), f"{field}.versionInfo"),
            purl=spdx_purl(tuple(spdx_references(item, field)), field),
        )
    described_ids = spdx_described_ids(data, tuple(spdx_relationships(data)))
    if any(identifier not in components for identifier in described_ids):
        raise ValueError("SPDX top-level identity does not select an imported package")
    return tuple(components[identifier] for identifier in described_ids)
