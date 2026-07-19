# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — versioned adapter catalogue
"""Catalogue candidate evidence adapters by domain without trusting their output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .adapter_profiles import profile_by_name
from .model_primitives import require_identifier, require_semantic_version, validate_unique_strings
from .models import canonical_digest, require_mapping, require_string

ADAPTER_CATALOGUE_SCHEMA_VERSION = "1.0"

EvidenceDomain = Literal[
    "application-security",
    "dependency-vulnerability",
    "container",
    "infrastructure-as-code",
    "secret",
]
ToolStatus = Literal["candidate", "profiled", "superseded"]

_EVIDENCE_DOMAINS: frozenset[str] = frozenset(
    {
        "application-security",
        "dependency-vulnerability",
        "container",
        "infrastructure-as-code",
        "secret",
    }
)
_TOOL_STATUSES: frozenset[str] = frozenset({"candidate", "profiled", "superseded"})

NON_VERDICT_NOTICE = (
    "A catalogued adapter's output is signed, digest-bound evidence interpreted "
    "through an adapter profile. It is never an automatically trusted RigorFoundry "
    "verdict; selection is risk and profile driven, and promotion requires review."
)


def _require_https_url(value: object, field: str) -> str:
    """Return one non-empty ``https`` source-of-record URL."""
    text = require_string(value, field)
    if not text.startswith("https://"):
        raise ValueError(f"{field} must be an https URL")
    return text


@dataclass(frozen=True)
class CatalogueEntry:
    """One candidate evidence adapter with its domain, scope, and selection risk.

    Parameters
    ----------
    tool_id:
        Stable adapter tool identifier.
    evidence_domain:
        The evidence domain the tool covers.
    source_url:
        ``https`` source of record for the tool.
    coverage:
        Neutral description of what the tool observes.
    exclusions:
        What the tool does not establish; its output is never a trusted verdict.
    status:
        ``candidate``, ``profiled`` (bound to a built-in adapter profile), or
        ``superseded``.
    risk_profiles:
        Risk labels that select this tool.
    profile_name:
        Built-in adapter-profile name (``profiled`` only).
    superseded_by:
        Successor tool identifier (``superseded`` only).

    """

    tool_id: str
    evidence_domain: EvidenceDomain
    source_url: str
    coverage: str
    exclusions: str
    status: ToolStatus
    risk_profiles: tuple[str, ...]
    profile_name: str
    superseded_by: str
    entry_digest: str

    @classmethod
    def build(
        cls,
        *,
        tool_id: str,
        evidence_domain: EvidenceDomain,
        source_url: str,
        coverage: str,
        exclusions: str,
        status: ToolStatus,
        risk_profiles: tuple[str, ...],
        profile_name: str = "",
        superseded_by: str = "",
    ) -> CatalogueEntry:
        """Build one validated catalogue entry with a consistent status."""
        if evidence_domain not in _EVIDENCE_DOMAINS:
            raise ValueError("entry.evidence_domain is unsupported")
        if status not in _TOOL_STATUSES:
            raise ValueError("entry.status is unsupported")
        profile, successor = _resolve_status(status, profile_name, superseded_by)
        body: dict[str, object] = {
            "schema_version": ADAPTER_CATALOGUE_SCHEMA_VERSION,
            "tool_id": require_identifier(tool_id, "entry.tool_id"),
            "evidence_domain": evidence_domain,
            "source_url": _require_https_url(source_url, "entry.source_url"),
            "coverage": require_string(coverage, "entry.coverage"),
            "exclusions": require_string(exclusions, "entry.exclusions"),
            "status": status,
            "risk_profiles": list(
                validate_unique_strings(risk_profiles, "entry.risk_profiles", minimum=1)
            ),
            "profile_name": profile,
            "superseded_by": successor,
        }
        return cls(
            tool_id=cast(str, body["tool_id"]),
            evidence_domain=evidence_domain,
            source_url=cast(str, body["source_url"]),
            coverage=cast(str, body["coverage"]),
            exclusions=cast(str, body["exclusions"]),
            status=status,
            risk_profiles=tuple(cast(list[str], body["risk_profiles"])),
            profile_name=profile,
            superseded_by=successor,
            entry_digest=canonical_digest(body),
        )

    @property
    def is_selectable(self) -> bool:
        """Return whether the tool is eligible for selection (not superseded)."""
        return self.status != "superseded"

    def to_dict(self) -> dict[str, object]:
        """Serialise one catalogue entry."""
        return {
            "schema_version": ADAPTER_CATALOGUE_SCHEMA_VERSION,
            "tool_id": self.tool_id,
            "evidence_domain": self.evidence_domain,
            "source_url": self.source_url,
            "coverage": self.coverage,
            "exclusions": self.exclusions,
            "status": self.status,
            "risk_profiles": list(self.risk_profiles),
            "profile_name": self.profile_name,
            "superseded_by": self.superseded_by,
            "entry_digest": self.entry_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> CatalogueEntry:
        """Parse and integrity-check one catalogue entry."""
        data = require_mapping(value, "entry")
        if data.get("schema_version") != ADAPTER_CATALOGUE_SCHEMA_VERSION:
            raise ValueError("unsupported catalogue entry schema version")
        raw_risk = data.get("risk_profiles")
        if not isinstance(raw_risk, list):
            raise ValueError("entry.risk_profiles must be an array")
        entry = cls.build(
            tool_id=require_string(data.get("tool_id"), "entry.tool_id"),
            evidence_domain=cast(
                EvidenceDomain,
                require_string(data.get("evidence_domain"), "entry.evidence_domain"),
            ),
            source_url=require_string(data.get("source_url"), "entry.source_url"),
            coverage=require_string(data.get("coverage"), "entry.coverage"),
            exclusions=require_string(data.get("exclusions"), "entry.exclusions"),
            status=cast(ToolStatus, require_string(data.get("status"), "entry.status")),
            risk_profiles=tuple(
                require_string(item, "entry.risk_profiles[]")
                for item in cast(list[object], raw_risk)
            ),
            profile_name=require_string(
                data.get("profile_name", ""), "entry.profile_name", allow_empty=True
            ),
            superseded_by=require_string(
                data.get("superseded_by", ""), "entry.superseded_by", allow_empty=True
            ),
        )
        if data.get("entry_digest") != entry.entry_digest:
            raise ValueError("catalogue entry digest does not match its content")
        return entry


def _resolve_status(status: ToolStatus, profile_name: str, superseded_by: str) -> tuple[str, str]:
    """Validate and normalise the fields tied to a tool status."""
    if status == "profiled":
        if superseded_by:
            raise ValueError("profiled entry must not name a successor")
        profile = profile_by_name(profile_name, "entry.profile_name").name
        return profile, ""
    if status == "superseded":
        if profile_name:
            raise ValueError("superseded entry must not bind an adapter profile")
        return "", require_identifier(superseded_by, "entry.superseded_by")
    if profile_name or superseded_by:
        raise ValueError("candidate entry must not bind a profile or successor")
    return "", ""


@dataclass(frozen=True)
class AdapterCatalogue:
    """A versioned catalogue of candidate evidence adapters across domains.

    Parameters
    ----------
    catalogue_version:
        Semantic version of the catalogue content.
    entries:
        Catalogue entries with unique tool identifiers.

    """

    catalogue_version: str
    entries: tuple[CatalogueEntry, ...]
    non_verdict_notice: str
    catalogue_digest: str

    @classmethod
    def build(
        cls,
        *,
        catalogue_version: str,
        entries: tuple[CatalogueEntry, ...],
    ) -> AdapterCatalogue:
        """Build one validated catalogue with cross-checked successor references."""
        if not entries:
            raise ValueError("catalogue.entries must not be empty")
        tool_ids = tuple(entry.tool_id for entry in entries)
        validate_unique_strings(tool_ids, "catalogue.tool_ids", minimum=1)
        present = set(tool_ids)
        for entry in entries:
            if entry.superseded_by and entry.superseded_by not in present:
                raise ValueError(
                    f"entry {entry.tool_id} names an uncatalogued successor: {entry.superseded_by}"
                )
        body: dict[str, object] = {
            "schema_version": ADAPTER_CATALOGUE_SCHEMA_VERSION,
            "catalogue_version": require_semantic_version(
                catalogue_version, "catalogue.catalogue_version"
            ),
            "entries": [entry.to_dict() for entry in entries],
            "non_verdict_notice": NON_VERDICT_NOTICE,
        }
        return cls(
            catalogue_version=cast(str, body["catalogue_version"]),
            entries=entries,
            non_verdict_notice=NON_VERDICT_NOTICE,
            catalogue_digest=canonical_digest(body),
        )

    def for_domain(self, evidence_domain: str) -> tuple[CatalogueEntry, ...]:
        """Return every entry covering one evidence domain."""
        return tuple(entry for entry in self.entries if entry.evidence_domain == evidence_domain)

    def select(
        self,
        risk_profile: str,
        evidence_domain: str | None = None,
    ) -> tuple[CatalogueEntry, ...]:
        """Return selectable entries for a risk profile, optionally by domain.

        Selection is risk and profile driven and never returns a superseded tool.
        """
        chosen = [
            entry
            for entry in self.entries
            if entry.is_selectable
            and risk_profile in entry.risk_profiles
            and (evidence_domain is None or entry.evidence_domain == evidence_domain)
        ]
        return tuple(sorted(chosen, key=lambda entry: entry.tool_id))

    def to_dict(self) -> dict[str, object]:
        """Serialise the catalogue."""
        return {
            "schema_version": ADAPTER_CATALOGUE_SCHEMA_VERSION,
            "catalogue_version": self.catalogue_version,
            "entries": [entry.to_dict() for entry in self.entries],
            "non_verdict_notice": self.non_verdict_notice,
            "catalogue_digest": self.catalogue_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> AdapterCatalogue:
        """Parse and integrity-check the catalogue."""
        data = require_mapping(value, "catalogue")
        if data.get("schema_version") != ADAPTER_CATALOGUE_SCHEMA_VERSION:
            raise ValueError("unsupported catalogue schema version")
        if data.get("non_verdict_notice") != NON_VERDICT_NOTICE:
            raise ValueError("catalogue must carry the exact non-verdict notice")
        raw = data.get("entries")
        if not isinstance(raw, list):
            raise ValueError("catalogue.entries must be an array")
        catalogue = cls.build(
            catalogue_version=require_string(
                data.get("catalogue_version"), "catalogue.catalogue_version"
            ),
            entries=tuple(CatalogueEntry.from_dict(item) for item in cast(list[object], raw)),
        )
        if data.get("catalogue_digest") != catalogue.catalogue_digest:
            raise ValueError("catalogue digest does not match its content")
        return catalogue


def _entry(
    tool_id: str,
    evidence_domain: EvidenceDomain,
    source_url: str,
    coverage: str,
    exclusions: str,
    status: ToolStatus,
    risk_profiles: tuple[str, ...],
    *,
    profile_name: str = "",
    superseded_by: str = "",
) -> CatalogueEntry:
    """Build one built-in catalogue entry."""
    return CatalogueEntry.build(
        tool_id=tool_id,
        evidence_domain=evidence_domain,
        source_url=source_url,
        coverage=coverage,
        exclusions=exclusions,
        status=status,
        risk_profiles=risk_profiles,
        profile_name=profile_name,
        superseded_by=superseded_by,
    )


_BUILTIN_CATALOGUE = AdapterCatalogue.build(
    catalogue_version="1.0.0",
    entries=(
        _entry(
            "semgrep",
            "application-security",
            "https://github.com/semgrep/semgrep",
            "Static application-security pattern findings over source code.",
            "Does not prove exploitability; findings are candidate evidence only.",
            "profiled",
            ("application-security",),
            profile_name="semgrep-local-json-v1",
        ),
        _entry(
            "trivy",
            "container",
            "https://github.com/aquasecurity/trivy",
            "Offline misconfiguration and secret scanning over a repository target.",
            "Not represented as CVE, SBOM, licence, or supply-chain coverage here.",
            "profiled",
            ("container", "supply-chain"),
            profile_name="trivy-repository-json-v1",
        ),
        _entry(
            "osv-scanner",
            "dependency-vulnerability",
            "https://github.com/google/osv-scanner",
            "Offline lockfile vulnerabilities matched against an exact local OSV snapshot.",
            "Requires a tracked database manifest; reports matches, not reachability or exploitability.",
            "profiled",
            ("supply-chain", "release-gate"),
            profile_name="osv-lockfile-offline-json-v1",
        ),
        _entry(
            "grype",
            "container",
            "https://github.com/anchore/grype",
            "Known vulnerabilities in container images and filesystems.",
            "Reports catalogue matches, not confirmed runtime exposure.",
            "candidate",
            ("container", "supply-chain"),
        ),
        _entry(
            "checkov",
            "infrastructure-as-code",
            "https://github.com/bridgecrewio/checkov",
            "Infrastructure-as-code misconfiguration policy findings.",
            "Findings are policy signals, not a deployed-state attestation.",
            "candidate",
            ("infrastructure-as-code", "release-gate"),
        ),
        _entry(
            "tfsec",
            "infrastructure-as-code",
            "https://github.com/aquasecurity/tfsec",
            "Terraform static-analysis security findings (now part of Trivy).",
            "Superseded and no longer actively developed; prefer the successor.",
            "superseded",
            ("infrastructure-as-code",),
            superseded_by="trivy",
        ),
        _entry(
            "gitleaks",
            "secret",
            "https://github.com/gitleaks/gitleaks",
            "Detection of hard-coded secrets in a git repository.",
            "Pattern detection may miss or over-report; not a leak-impact verdict.",
            "candidate",
            ("secret", "release-gate"),
        ),
    ),
)


def builtin_catalogue() -> AdapterCatalogue:
    """Return the built-in versioned adapter catalogue."""
    return _BUILTIN_CATALOGUE
