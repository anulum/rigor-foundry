# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — BuildKit OCI SPDX inventory projection
"""Validate an OCI SPDX statement and project direct image package identities."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable

from .cra_inventory import InventoryComponent
from .cra_oci_inventory import OciComponentCpe23, OciImageBinding, require_cpe23
from .cra_spdx import (
    spdx_described_ids,
    spdx_document,
    spdx_packages,
    spdx_purl,
    spdx_references,
    spdx_relationships,
)
from .model_primitives import require_digest
from .models import require_mapping, require_string

_ROOT_PREFIX = "SPDXRef-DocumentRoot-Directory-"
_PURL_TYPE = re.compile(r"[a-z][a-z0-9.-]*")
_PURL_KEY = re.compile(r"[a-z][a-z0-9._-]*")
_PURL_TOKEN = re.compile(r"(?:[a-zA-Z0-9._~:-]|%[a-fA-F0-9]{2})+")
_PERCENT_BYTE = re.compile(rb"%([a-fA-F0-9]{2})")


def _purl_token(value: str) -> str | None:
    """Decode one valid UTF-8 package URL token without network imports."""
    if _PURL_TOKEN.fullmatch(value) is None:
        return None
    encoded = _PERCENT_BYTE.sub(lambda match: bytes([int(match[1], 16)]), value.encode("ascii"))
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() and not text.isspace() else None


def _purl_path_segment(value: str, *, subpath: bool = False) -> bool:
    """Validate one namespace or subpath segment after decoding."""
    part = _purl_token(value)
    if part is None or "/" in part:
        return False
    return not subpath or part not in {".", ".."}


def _valid_package_url(value: str) -> bool:
    """Check package URL syntax without inferring ecosystem-specific identity."""
    body, marker, subpath = value.removeprefix("pkg:").partition("#")
    identity, query_marker, query = body.partition("?")
    coordinates, version_marker, version = identity.partition("@")
    kind, separator, path = coordinates.partition("/")
    if not value.startswith("pkg:") or not separator or not _PURL_TYPE.fullmatch(kind):
        return False
    *namespace, name = path.split("/")
    if not _purl_token(name) or not all(_purl_path_segment(part) for part in namespace):
        return False
    if version_marker and not _purl_token(version):
        return False
    if marker and not all(_purl_path_segment(part, subpath=True) for part in subpath.split("/")):
        return False
    names: set[str] = set()
    if query_marker:
        for qualifier in query.split("&"):
            name, equals, qualifier_value = qualifier.partition("=")
            if (
                not equals
                or not _PURL_KEY.fullmatch(name)
                or name in names
                or not _purl_token(qualifier_value)
            ):
                return False
            names.add(name)
    return True


def _package_references(
    package: dict[str, object], field: str
) -> tuple[str | None, tuple[str, ...]]:
    """Validate all supplied references and return the PURL and CPE locators."""
    refs = tuple(spdx_references(package, field, strict=True))
    purl = spdx_purl(refs, field)
    if purl is not None and not _valid_package_url(purl):
        raise ValueError(f"{field} contains an invalid package URL")
    cpes: list[str] = []
    for category, reference_type, locator in refs:
        if reference_type == "cpe23Type":
            if category != "SECURITY":
                raise ValueError(f"{field} cpe23Type must use SECURITY category")
            cpes.append(require_cpe23(locator))
    return purl, tuple(cpes)


def _package_evidence(
    package: dict[str, object], field: str
) -> tuple[InventoryComponent, tuple[str, ...]]:
    """Validate a versioned package and read its original null-PURL CPE locators."""
    purl, cpes = _package_references(package, field)
    component = InventoryComponent.build(
        name=require_string(package.get("name"), f"{field}.name"),
        version=require_string(package.get("versionInfo"), f"{field}.versionInfo"),
        purl=purl,
    )
    return component, cpes if purl is None else ()


def _image_subject(statement: dict[str, object]) -> str:
    """Return the SHA-256 of the only declared OCI image subject."""
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise ValueError("OCI SPDX input must be an in-toto Statement v1")
    if statement.get("predicateType") != "https://spdx.dev/Document":
        raise ValueError("OCI SPDX statement must declare an SPDX document predicate")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise ValueError("OCI SPDX statement must have exactly one image subject")
    subject = require_mapping(subjects[0], "OCI SPDX image subject")
    require_string(subject.get("name"), "OCI SPDX image subject.name")
    digests = require_mapping(subject.get("digest"), "OCI SPDX image subject.digest")
    return require_digest(digests.get("sha256"), "OCI SPDX image subject.digest.sha256")


def oci_spdx_projection(
    document: object, component_array: Callable[[object, str], list[object]]
) -> tuple[tuple[InventoryComponent, ...], OciImageBinding]:
    """Select the declared synthetic root's direct package children."""
    statement = require_mapping(document, "OCI SPDX statement")
    manifest = _image_subject(statement)
    data = spdx_document(statement.get("predicate"))
    relationships = tuple(spdx_relationships(data))
    described = spdx_described_ids(data, relationships)
    packages: dict[str, tuple[InventoryComponent, tuple[str, ...]]] = {}
    roots: list[str] = []
    for identifier, field, package in spdx_packages(
        component_array(data.get("packages"), "packages")
    ):
        if identifier.startswith(_ROOT_PREFIX):
            if package.get("primaryPackagePurpose") != "FILE" or "versionInfo" in package:
                raise ValueError("OCI SPDX synthetic root must be a versionless FILE package")
            require_string(package.get("name"), f"{field}.name")
            _package_references(package, field)
            roots.append(identifier)
        else:
            packages[identifier] = _package_evidence(package, field)
    if len(roots) != 1 or tuple(roots) != described:
        raise ValueError("OCI SPDX document must describe exactly one synthetic root")
    children = [
        target
        for source, relation, target in relationships
        if source == roots[0] and relation == "CONTAINS"
    ]
    if (
        not children
        or len(set(children)) != len(children)
        or any(target not in packages for target in children)
    ):
        raise ValueError("OCI SPDX root must directly contain unique declared packages")
    projected: dict[InventoryComponent, set[str]] = defaultdict(set)
    for target in children:
        component, locators = packages[target]
        projected[component].update(locators)
    cpe_records = tuple(
        sorted(
            OciComponentCpe23(item.name, item.version, tuple(sorted(locators)))
            for item, locators in projected.items()
            if locators
        )
    )
    return tuple(projected), OciImageBinding(manifest, cpe_records)
