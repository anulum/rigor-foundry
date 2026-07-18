# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — adapter catalogue tests
"""Verify the risk-driven adapter catalogue never trusts third-party output."""

from __future__ import annotations

from typing import cast

import pytest

from rigor_foundry.adapter_catalogue import (
    NON_VERDICT_NOTICE,
    AdapterCatalogue,
    CatalogueEntry,
    EvidenceDomain,
    ToolStatus,
    builtin_catalogue,
)

URL = "https://github.com/example/tool"


def candidate(
    tool_id: str, domain: EvidenceDomain = "secret", risk: tuple[str, ...] = ("secret",)
) -> CatalogueEntry:
    """Return one candidate catalogue entry."""
    return CatalogueEntry.build(
        tool_id=tool_id,
        evidence_domain=domain,
        source_url=URL,
        coverage="observes something",
        exclusions="not a verdict",
        status="candidate",
        risk_profiles=risk,
    )


def test_entry_status_variants_round_trip() -> None:
    """Candidate, profiled, and superseded entries validate and round-trip."""
    cand = candidate("gitleaks-like")
    assert cand.is_selectable is True
    assert CatalogueEntry.from_dict(cand.to_dict()) == cand

    profiled = CatalogueEntry.build(
        tool_id="semgrep-like",
        evidence_domain="application-security",
        source_url=URL,
        coverage="static findings",
        exclusions="not exploitability",
        status="profiled",
        risk_profiles=("application-security",),
        profile_name="semgrep-local-json-v1",
    )
    assert profiled.profile_name == "semgrep-local-json-v1"
    assert CatalogueEntry.from_dict(profiled.to_dict()) == profiled

    superseded = CatalogueEntry.build(
        tool_id="tfsec-like",
        evidence_domain="infrastructure-as-code",
        source_url=URL,
        coverage="terraform findings",
        exclusions="deprecated",
        status="superseded",
        risk_profiles=("infrastructure-as-code",),
        superseded_by="trivy-like",
    )
    assert superseded.is_selectable is False
    assert superseded.superseded_by == "trivy-like"


def test_entry_build_rejects_inconsistent_status() -> None:
    """Domain, status, and cross-field status inconsistencies fail closed."""
    with pytest.raises(ValueError, match="evidence_domain is unsupported"):
        CatalogueEntry.build(
            tool_id="t",
            evidence_domain=cast(EvidenceDomain, "space-lasers"),
            source_url=URL,
            coverage="c",
            exclusions="e",
            status="candidate",
            risk_profiles=("r",),
        )
    with pytest.raises(ValueError, match="status is unsupported"):
        CatalogueEntry.build(
            tool_id="t",
            evidence_domain="secret",
            source_url=URL,
            coverage="c",
            exclusions="e",
            status=cast(ToolStatus, "trusted"),
            risk_profiles=("r",),
        )
    with pytest.raises(ValueError, match="https URL"):
        candidate_with(source_url="http://insecure.example")
    with pytest.raises(ValueError, match="risk_profiles"):
        CatalogueEntry.build(
            tool_id="t",
            evidence_domain="secret",
            source_url=URL,
            coverage="c",
            exclusions="e",
            status="candidate",
            risk_profiles=(),
        )


def candidate_with(
    *,
    status: str = "candidate",
    profile_name: str = "",
    superseded_by: str = "",
    source_url: str = URL,
) -> CatalogueEntry:
    """Build a secret-domain entry overriding status-related fields."""
    return CatalogueEntry.build(
        tool_id="t",
        evidence_domain="secret",
        source_url=source_url,
        coverage="c",
        exclusions="e",
        status=cast(ToolStatus, status),
        risk_profiles=("r",),
        profile_name=profile_name,
        superseded_by=superseded_by,
    )


def test_status_cross_field_rules() -> None:
    """Each status binds exactly its own extra fields."""
    with pytest.raises(ValueError, match="must not name a successor"):
        candidate_with(status="profiled", profile_name="semgrep-local-json-v1", superseded_by="x")
    with pytest.raises(ValueError, match="profile_name is unsupported"):
        candidate_with(status="profiled", profile_name="does-not-exist")
    with pytest.raises(ValueError, match="must not bind an adapter profile"):
        candidate_with(status="superseded", profile_name="semgrep-local-json-v1")
    with pytest.raises(ValueError, match="superseded_by"):
        candidate_with(status="superseded")
    with pytest.raises(ValueError, match="must not bind a profile or successor"):
        candidate_with(profile_name="semgrep-local-json-v1")


def test_entry_from_dict_rejects_tampering() -> None:
    """Schema, array shape, and digest tampering fail closed."""
    good = candidate("t").to_dict()
    bad_schema = dict(good)
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="entry schema version"):
        CatalogueEntry.from_dict(bad_schema)
    bad_risk = dict(good)
    bad_risk["risk_profiles"] = "not-a-list"
    with pytest.raises(ValueError, match="risk_profiles must be an array"):
        CatalogueEntry.from_dict(bad_risk)
    bad_digest = dict(good)
    bad_digest["entry_digest"] = "0" * 64
    with pytest.raises(ValueError, match="entry digest"):
        CatalogueEntry.from_dict(bad_digest)


def test_catalogue_selection_is_risk_driven_and_skips_superseded() -> None:
    """Selection matches risk and domain and never returns a superseded tool."""
    catalogue = builtin_catalogue()
    assert catalogue.non_verdict_notice == NON_VERDICT_NOTICE
    assert [e.tool_id for e in catalogue.select("supply-chain")] == [
        "grype",
        "osv-scanner",
        "trivy",
    ]
    assert [e.tool_id for e in catalogue.select("infrastructure-as-code")] == ["checkov"]
    assert [e.tool_id for e in catalogue.select("secret", "secret")] == ["gitleaks"]
    assert [e.tool_id for e in catalogue.select("supply-chain", "container")] == ["grype", "trivy"]
    assert {e.tool_id for e in catalogue.for_domain("container")} == {"trivy", "grype"}
    assert catalogue.select("no-such-risk") == ()
    assert AdapterCatalogue.from_dict(catalogue.to_dict()) == catalogue


def test_catalogue_build_rejects_invalid_sets() -> None:
    """Empty, duplicate, and dangling-successor catalogues fail closed."""
    with pytest.raises(ValueError, match="entries must not be empty"):
        AdapterCatalogue.build(catalogue_version="1.0.0", entries=())
    with pytest.raises(ValueError, match="unique"):
        AdapterCatalogue.build(
            catalogue_version="1.0.0",
            entries=(candidate("dup"), candidate("dup")),
        )
    dangling = CatalogueEntry.build(
        tool_id="old",
        evidence_domain="infrastructure-as-code",
        source_url=URL,
        coverage="c",
        exclusions="e",
        status="superseded",
        risk_profiles=("infrastructure-as-code",),
        superseded_by="uncatalogued",
    )
    with pytest.raises(ValueError, match="uncatalogued successor"):
        AdapterCatalogue.build(catalogue_version="1.0.0", entries=(dangling,))


def test_catalogue_from_dict_rejects_tampering() -> None:
    """Schema, notice, array shape, and digest tampering fail closed."""
    good = builtin_catalogue().to_dict()
    bad_schema = dict(good)
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="catalogue schema version"):
        AdapterCatalogue.from_dict(bad_schema)
    bad_notice = dict(good)
    bad_notice["non_verdict_notice"] = "trust everything"
    with pytest.raises(ValueError, match="non-verdict notice"):
        AdapterCatalogue.from_dict(bad_notice)
    bad_entries = dict(good)
    bad_entries["entries"] = "not-a-list"
    with pytest.raises(ValueError, match="entries must be an array"):
        AdapterCatalogue.from_dict(bad_entries)
    bad_digest = dict(good)
    bad_digest["catalogue_digest"] = "0" * 64
    with pytest.raises(ValueError, match="catalogue digest"):
        AdapterCatalogue.from_dict(bad_digest)
