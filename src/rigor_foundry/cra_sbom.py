# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded imported-SBOM parser
"""Read and validate the bounded CycloneDX and SPDX fields used by CRA evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import cast

from .cra_inventory import InventoryComponent, SbomFormat
from .git_inventory import open_directory_no_follow, read_stable_regular_file_at
from .models import require_mapping, require_string

MAX_SBOM_BYTES = 16 * 1024 * 1024
MAX_COMPONENTS = 100_000

_CYCLONEDX_15_TYPES = frozenset(
    {
        "application",
        "container",
        "data",
        "device",
        "device-driver",
        "file",
        "firmware",
        "framework",
        "library",
        "machine-learning-model",
        "operating-system",
        "platform",
    }
)


def _strict_json(payload: bytes, label: str) -> object:
    """Decode strict UTF-8 JSON without duplicate keys or non-finite numbers."""

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"{label} contains a non-finite number: {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not complete strict UTF-8 JSON") from exc


def read_import_file(path: Path, *, maximum_bytes: int, label: str) -> tuple[bytes, str]:
    """Read one bounded single-link regular file through no-follow descriptors."""
    absolute = Path(os.path.abspath(path))
    parent_descriptor = open_directory_no_follow(absolute.parent)
    try:
        observed = read_stable_regular_file_at(
            parent_descriptor,
            absolute.name,
            label,
            buffer_limit=maximum_bytes,
            require_single_link=True,
        )
    finally:
        os.close(parent_descriptor)
    if observed.payload is None:
        raise ValueError(f"{label} exceeds the {maximum_bytes}-byte import limit")
    return observed.payload, observed.content_digest


def _component_array(value: object, field: str) -> list[object]:
    """Return one bounded non-empty JSON component array."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    items = cast(list[object], value)
    if not items:
        raise ValueError(f"{field} must contain at least one component")
    if len(items) > MAX_COMPONENTS:
        raise ValueError(f"{field} exceeds the {MAX_COMPONENTS}-component limit")
    return items


def _cyclonedx_components(document: object, version: str) -> tuple[InventoryComponent, ...]:
    """Validate the consumed CycloneDX envelope and top-level component schema."""
    data = require_mapping(document, "CycloneDX SBOM")
    if data.get("bomFormat") != "CycloneDX" or data.get("specVersion") != version:
        raise ValueError(
            f"CycloneDX SBOM must declare bomFormat CycloneDX and specVersion {version}"
        )
    raw_version = data.get("version", 1)
    if isinstance(raw_version, bool) or not isinstance(raw_version, int) or raw_version < 1:
        raise ValueError("CycloneDX SBOM version must be an integer >= 1")
    components: list[InventoryComponent] = []
    for index, raw in enumerate(_component_array(data.get("components"), "components")):
        field = f"components[{index}]"
        item = require_mapping(raw, field)
        component_type = require_string(item.get("type"), f"{field}.type")
        supported_types = (
            _CYCLONEDX_15_TYPES | {"cryptographic-asset"}
            if version == "1.6"
            else _CYCLONEDX_15_TYPES
        )
        if component_type not in supported_types:
            raise ValueError(f"{field}.type is unsupported")
        raw_purl = item.get("purl")
        components.append(
            InventoryComponent.build(
                name=require_string(item.get("name"), f"{field}.name"),
                version=require_string(item.get("version"), f"{field}.version"),
                purl=(None if raw_purl is None else require_string(raw_purl, f"{field}.purl")),
            )
        )
    return tuple(components)


def _spdx_purl(package: dict[str, object], field: str) -> str | None:
    """Extract at most one Package URL from SPDX 2.3 external references."""
    raw_refs = package.get("externalRefs", [])
    if not isinstance(raw_refs, list):
        raise ValueError(f"{field}.externalRefs must be an array")
    purls: list[str] = []
    for index, raw in enumerate(cast(list[object], raw_refs)):
        ref_field = f"{field}.externalRefs[{index}]"
        ref = require_mapping(raw, ref_field)
        category = require_string(ref.get("referenceCategory"), f"{ref_field}.referenceCategory")
        reference_type = require_string(ref.get("referenceType"), f"{ref_field}.referenceType")
        locator = require_string(ref.get("referenceLocator"), f"{ref_field}.referenceLocator")
        if reference_type == "purl":
            if category != "PACKAGE-MANAGER":
                raise ValueError(f"{ref_field} purl must use PACKAGE-MANAGER category")
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


def _spdx_described_ids(data: dict[str, object]) -> tuple[str, ...]:
    """Resolve exact document-level package identities without flattening dependencies."""
    declared = (
        ()
        if data.get("documentDescribes") is None
        else _spdx_id_array(data.get("documentDescribes"), "documentDescribes")
    )
    raw_relationships = data.get("relationships", [])
    if not isinstance(raw_relationships, list):
        raise ValueError("relationships must be an array")
    related: list[str] = []
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


def _spdx_components(document: object) -> tuple[InventoryComponent, ...]:
    """Validate the consumed SPDX 2.3 JSON envelope and package schema."""
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
    components: dict[str, InventoryComponent] = {}
    for index, raw in enumerate(_component_array(data.get("packages"), "packages")):
        field = f"packages[{index}]"
        item = require_mapping(raw, field)
        spdx_id = require_string(item.get("SPDXID"), f"{field}.SPDXID")
        if not spdx_id.startswith("SPDXRef-") or spdx_id in components:
            raise ValueError(f"{field}.SPDXID must be a unique SPDXRef identifier")
        components[spdx_id] = InventoryComponent.build(
            name=require_string(item.get("name"), f"{field}.name"),
            version=require_string(item.get("versionInfo"), f"{field}.versionInfo"),
            purl=_spdx_purl(item, field),
        )
    described_ids = _spdx_described_ids(data)
    if any(identifier not in components for identifier in described_ids):
        raise ValueError("SPDX top-level identity does not select an imported package")
    return tuple(components[identifier] for identifier in described_ids)


def parse_sbom(payload: bytes, sbom_format: SbomFormat) -> tuple[InventoryComponent, ...]:
    """Validate one bounded supported schema profile and return its components.

    This validates the exact envelope and fields consumed by RIGOR-FOUNDRY. It
    does not certify full conformance of unconsumed optional SBOM fields.
    """
    document = _strict_json(payload, "SBOM")
    if sbom_format == "cyclonedx-1.5":
        return _cyclonedx_components(document, "1.5")
    if sbom_format == "cyclonedx-1.6":
        return _cyclonedx_components(document, "1.6")
    if sbom_format == "spdx-2.3":
        return _spdx_components(document)
    raise ValueError("sbom_format is unsupported")
