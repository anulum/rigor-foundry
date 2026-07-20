# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit CRA applicability policy
"""Define the optional, fail-closed CRA audit-policy extension."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal, cast

from .audit_primitives import _mapping, _string, canonical_digest, require_exact_fields
from .model_primitives import require_identifier

CRA_POLICY_SCHEMA_VERSION = "1.0"
CraApplicability = Literal["required", "not-applicable"]

_FIELDS = frozenset(
    {
        "schema_version",
        "applicability",
        "rationale",
        "product_key",
        "disclosure_policy_path",
        "state_evidence_id",
        "cra_policy_digest",
    }
)


def _tracked_path(value: object, field: str) -> str:
    """Return one normalised repository-relative tracked path."""
    text = _string(value, field)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or path.as_posix() != text
        or text in {"", "."}
        or "//" in text
    ):
        raise ValueError(f"{field} must be a normalised repository-relative path")
    return text


@dataclass(frozen=True)
class CraPolicy:
    """Explicitly scope CRA signals to one declared product and evidence root."""

    applicability: CraApplicability
    rationale: str
    product_key: str | None
    disclosure_policy_path: str | None
    state_evidence_id: str | None
    cra_policy_digest: str

    @classmethod
    def build(
        cls,
        *,
        applicability: CraApplicability,
        rationale: str,
        product_key: str | None,
        disclosure_policy_path: str | None,
        state_evidence_id: str | None,
    ) -> CraPolicy:
        """Build one applicability decision without making a legal verdict."""
        if applicability not in {"required", "not-applicable"}:
            raise ValueError("cra.applicability is unsupported")
        rationale = _string(rationale, "cra.rationale")
        if applicability == "required":
            product_key = require_identifier(product_key, "cra.product_key")
            disclosure_policy_path = _tracked_path(
                disclosure_policy_path,
                "cra.disclosure_policy_path",
            )
            state_evidence_id = require_identifier(
                state_evidence_id,
                "cra.state_evidence_id",
            )
        elif any(
            value is not None for value in (product_key, disclosure_policy_path, state_evidence_id)
        ):
            raise ValueError("not-applicable CRA policy must not declare product evidence")
        body: dict[str, object] = {
            "schema_version": CRA_POLICY_SCHEMA_VERSION,
            "applicability": applicability,
            "rationale": rationale,
            "product_key": product_key,
            "disclosure_policy_path": disclosure_policy_path,
            "state_evidence_id": state_evidence_id,
        }
        return cls(
            applicability=applicability,
            rationale=rationale,
            product_key=product_key,
            disclosure_policy_path=disclosure_policy_path,
            state_evidence_id=state_evidence_id,
            cra_policy_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete CRA applicability decision."""
        return {
            "schema_version": CRA_POLICY_SCHEMA_VERSION,
            "applicability": self.applicability,
            "rationale": self.rationale,
            "product_key": self.product_key,
            "disclosure_policy_path": self.disclosure_policy_path,
            "state_evidence_id": self.state_evidence_id,
            "cra_policy_digest": self.cra_policy_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> CraPolicy:
        """Parse and integrity-check one CRA policy block."""
        data = _mapping(value, "cra")
        require_exact_fields(data, _FIELDS, "cra")
        if data.get("schema_version") != CRA_POLICY_SCHEMA_VERSION:
            raise ValueError("cra.schema_version is unsupported")
        applicability = _string(data.get("applicability"), "cra.applicability")
        expected = cls.build(
            applicability=cast(CraApplicability, applicability),
            rationale=_string(data.get("rationale"), "cra.rationale"),
            product_key=cast(str | None, data.get("product_key")),
            disclosure_policy_path=cast(str | None, data.get("disclosure_policy_path")),
            state_evidence_id=cast(str | None, data.get("state_evidence_id")),
        )
        if data.get("cra_policy_digest") != expected.cra_policy_digest:
            raise ValueError("CRA policy digest does not match its content")
        return expected
