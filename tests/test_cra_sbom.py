# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded SBOM schema tests
"""Exercise every bounded CycloneDX and SPDX schema decision through ``parse_sbom``."""

from __future__ import annotations

import json

import pytest
from test_cra_inventory import cyclonedx, spdx

import rigor_foundry.cra_sbom as sbom_module
from rigor_foundry.cra_sbom import parse_sbom


def encoded(value: object) -> bytes:
    """Return deterministic JSON bytes for schema mutations."""
    return json.dumps(value, sort_keys=True).encode()


@pytest.mark.parametrize(
    ("document", "sbom_format", "message"),
    [
        (
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": {}},
            "cyclonedx-1.5",
            "must be an array",
        ),
        (
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []},
            "cyclonedx-1.5",
            "at least one",
        ),
        (
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 0, "components": [{}]},
            "cyclonedx-1.5",
            "integer",
        ),
        (
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": True, "components": [{}]},
            "cyclonedx-1.5",
            "integer",
        ),
        (
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"type": "unknown", "name": "a", "version": "1"}],
            },
            "cyclonedx-1.5",
            "type is unsupported",
        ),
        (
            {"spdxVersion": "SPDX-2.3", "dataLicense": "wrong", "SPDXID": "SPDXRef-DOCUMENT"},
            "spdx-2.3",
            "CC0-1.0",
        ),
        (
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "x",
                "documentNamespace": "n",
                "creationInfo": {"created": "now", "creators": []},
                "packages": [{}],
            },
            "spdx-2.3",
            "creators",
        ),
        (
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "x",
                "documentNamespace": "n",
                "creationInfo": {"created": "now", "creators": ["Tool: x"]},
                "packages": [{"SPDXID": "invalid", "name": "x", "versionInfo": "1"}],
            },
            "spdx-2.3",
            "unique SPDXRef",
        ),
    ],
)
def test_schema_profiles_reject_invalid_consumed_fields(
    document: object,
    sbom_format: str,
    message: str,
) -> None:
    """Invalid consumed fields cannot be hidden in otherwise valid JSON."""
    with pytest.raises(ValueError, match=message):
        parse_sbom(encoded(document), sbom_format)  # type: ignore[arg-type]


def test_cyclonedx_default_document_version_and_nonfinite_json() -> None:
    """The default document version is accepted while non-finite JSON is rejected."""
    document = json.loads(cyclonedx())
    document.pop("version")
    assert len(parse_sbom(encoded(document), "cyclonedx-1.5")) == 2
    with pytest.raises(ValueError, match="non-finite"):
        parse_sbom(b'{"value": NaN}', "cyclonedx-1.5")

    crypto = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [{"type": "cryptographic-asset", "name": "key", "version": "1"}],
    }
    assert parse_sbom(encoded(crypto), "cyclonedx-1.6")[0].name == "key"
    crypto["specVersion"] = "1.5"
    with pytest.raises(ValueError, match="type is unsupported"):
        parse_sbom(encoded(crypto), "cyclonedx-1.5")


def test_spdx_external_reference_rules_and_duplicate_package_ids() -> None:
    """Non-purl references are ignored, while purl ambiguity and ID reuse fail."""
    document = json.loads(spdx())
    package = document["packages"][0]
    invalid_refs = json.loads(spdx())
    invalid_refs["packages"][0]["externalRefs"] = {}
    with pytest.raises(ValueError, match="externalRefs must be an array"):
        parse_sbom(encoded(invalid_refs), "spdx-2.3")
    package["externalRefs"].insert(
        0,
        {
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": "cpe:2.3:a:example:alpha:1:*:*:*:*:*:*:*",
        },
    )
    assert parse_sbom(encoded(document), "spdx-2.3")[0].purl == "pkg:pypi/alpha@1.0"

    package["externalRefs"][1]["referenceCategory"] = "SECURITY"
    with pytest.raises(ValueError, match="PACKAGE-MANAGER"):
        parse_sbom(encoded(document), "spdx-2.3")
    package["externalRefs"][1]["referenceCategory"] = "PACKAGE-MANAGER"
    package["externalRefs"].append(dict(package["externalRefs"][1]))
    with pytest.raises(ValueError, match="multiple purl"):
        parse_sbom(encoded(document), "spdx-2.3")

    duplicate = json.loads(spdx())
    duplicate["packages"].append(dict(duplicate["packages"][0]))
    with pytest.raises(ValueError, match="unique SPDXRef"):
        parse_sbom(encoded(duplicate), "spdx-2.3")


def test_component_and_format_bounds_are_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public parser enforces its item bound and closed format vocabulary."""
    monkeypatch.setattr(sbom_module, "MAX_COMPONENTS", 1)
    with pytest.raises(ValueError, match="component limit"):
        parse_sbom(cyclonedx(), "cyclonedx-1.5")
    with pytest.raises(ValueError, match="unsupported"):
        parse_sbom(b"{}", "unknown")  # type: ignore[arg-type]


def test_spdx_package_without_external_refs_has_no_purl() -> None:
    """Absence of an optional purl remains explicit instead of fabricated."""
    document = json.loads(spdx())
    document["packages"][0].pop("externalRefs")
    assert parse_sbom(encoded(document), "spdx-2.3")[0].purl is None
