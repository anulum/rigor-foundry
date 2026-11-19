# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — OCI inventory projection evidence
"""Describe which image and null-PURL CPEs an OCI inventory projection retains."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from .audit_primitives import require_exact_fields
from .cra_protocol import JsonObject
from .model_primitives import require_digest
from .models import require_mapping, require_string

OCI_SBOM_FORMAT: Final = "spdx-2.3-oci"
OCI_PROJECTION = "direct-root-contains"
_CPE23 = re.compile(r"cpe:2\.3:[aho](?::(?:[^:\\\s]|\\[^\s])+){10}")


def require_cpe23(value: str) -> str:
    """Check the CPE 2.3 formatted binding and retain its exact spelling."""
    if _CPE23.fullmatch(value) is None:
        raise ValueError("cpe23Type reference must be a CPE 2.3 formatted binding")
    return value


@dataclass(frozen=True, order=True)
class OciComponentCpe23:
    """Bind verbatim CPE locators to one projected component with no PURL."""

    name: str
    version: str
    locators: tuple[str, ...]

    def to_dict(self) -> JsonObject:
        """Serialise one component's retained CPE locators."""
        return {"name": self.name, "version": self.version, "locators": list(self.locators)}

    @classmethod
    def from_dict(cls, value: object) -> OciComponentCpe23:
        """Read one canonical null-PURL component metadata entry."""
        data = require_mapping(value, "OCI component CPE metadata")
        require_exact_fields(data, frozenset({"name", "version", "locators"}), "OCI component CPE")
        raw = data.get("locators")
        if not isinstance(raw, list) or not raw:
            raise ValueError("OCI component CPE locators must be a non-empty array")
        locators = tuple(require_cpe23(require_string(item, "CPE locator")) for item in raw)
        if locators != tuple(sorted(set(locators))):
            raise ValueError("OCI component CPE locators must be unique and sorted")
        return cls(
            require_string(data.get("name"), "OCI component CPE name"),
            require_string(data.get("version"), "OCI component CPE version"),
            locators,
        )


@dataclass(frozen=True)
class OciImageBinding:
    """Bind the image manifest and direct-only projection metadata."""

    manifest_sha256: str
    retained_cpe23: tuple[OciComponentCpe23, ...]

    def to_dict(self) -> JsonObject:
        """Serialise the exact image identity and projection evidence."""
        return {
            "manifest_sha256": self.manifest_sha256,
            "projection": OCI_PROJECTION,
            "retained_cpe23": [entry.to_dict() for entry in self.retained_cpe23],
        }

    @classmethod
    def from_dict(cls, value: object) -> OciImageBinding:
        """Read the exact OCI projection and its canonical component metadata."""
        data = require_mapping(value, "OCI image binding")
        require_exact_fields(
            data,
            frozenset({"manifest_sha256", "projection", "retained_cpe23"}),
            "OCI image binding",
        )
        if data.get("projection") != OCI_PROJECTION:
            raise ValueError("OCI image binding must declare direct-root-contains projection")
        raw = data.get("retained_cpe23")
        if not isinstance(raw, list):
            raise ValueError("retained_cpe23 must be an array")
        entries = tuple(OciComponentCpe23.from_dict(item) for item in raw)
        identities = tuple((item.name, item.version) for item in entries)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("OCI CPE component identities must be unique and sorted")
        return cls(require_digest(data.get("manifest_sha256"), "OCI manifest_sha256"), entries)
