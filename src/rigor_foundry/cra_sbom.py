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
from .cra_oci_inventory import OCI_SBOM_FORMAT, OciImageBinding
from .cra_oci_spdx import oci_spdx_projection
from .cra_spdx import spdx_components
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


def parse_sbom(payload: bytes, sbom_format: SbomFormat) -> tuple[InventoryComponent, ...]:
    """Validate one bounded supported schema profile and return its components.

    This validates the exact envelope and fields consumed by RIGOR-FOUNDRY. It
    does not certify full conformance of unconsumed optional SBOM fields.
    """
    return parse_sbom_source(payload, sbom_format)[0]


def parse_sbom_source(
    payload: bytes, sbom_format: SbomFormat
) -> tuple[tuple[InventoryComponent, ...], OciImageBinding | None]:
    """Read consumed inventory identities and any declared OCI image binding."""
    document = _strict_json(payload, "SBOM")
    if sbom_format == "cyclonedx-1.5":
        return _cyclonedx_components(document, "1.5"), None
    if sbom_format == "cyclonedx-1.6":
        return _cyclonedx_components(document, "1.6"), None
    if sbom_format == "spdx-2.3":
        return spdx_components(document, _component_array), None
    if sbom_format == OCI_SBOM_FORMAT:
        return oci_spdx_projection(document, _component_array)
    raise ValueError("sbom_format is unsupported")
