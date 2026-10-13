# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — sealed v2 effect extractor registry
"""Admit only the exact reviewed built-in extractors from the protected tree."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .effect_journal_records_v2 import canonical_journal_json_v2
from .models import canonical_digest
from .project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json

EXTRACTOR_REGISTRY_SCHEMA_V2: Final = "rigor.extractor-registry.v2"
_EMPTY_BODY: Final = {"schema": EXTRACTOR_REGISTRY_SCHEMA_V2, "extractors": []}
_FIRST_ATOMIC_BODY: Final = {
    "schema": EXTRACTOR_REGISTRY_SCHEMA_V2,
    "extractors": [
        {
            "id": "builtin.extract.content-byte-count.v2",
            "output": "byte_count",
            "module": "rigor_foundry.tier0_builtin.extract_content_byte_count",
            "entrypoint": "extract",
            "forms": [],
        },
        {
            "id": "builtin.extract.fixed-variant-replace-or-create.v2",
            "output": "operation_variant",
            "module": "rigor_foundry.tier0_builtin.extract_fixed_variant",
            "entrypoint": "extract",
            "forms": [],
        },
        {
            "id": "builtin.extract.path-target.v2",
            "output": "target_ref",
            "module": "rigor_foundry.tier0_builtin.extract_path_target",
            "entrypoint": "extract",
            "forms": ["path"],
        },
    ],
}


@dataclass(frozen=True)
class ExtractorRegistryV2:
    """Closed extractor identities awaiting protected code and selection pins.

    Attributes
    ----------
    body_bytes : bytes
        Canonical exact registry body for bootstrap or the fixed first candidate.
    registry_digest : str
        Canonical digest of the complete registry body.

    Notes
    -----
    Module names are metadata. Parsing does not load code or establish installed code custody.
    """

    body_bytes: bytes
    registry_digest: str

    @classmethod
    def empty(cls) -> ExtractorRegistryV2:
        """Build the effect-free bootstrap extractor metadata.

        Returns
        -------
        ExtractorRegistryV2
            Canonical registry with no extractors.
        """
        return cls.from_bytes(canonical_journal_json_v2(_EMPTY_BODY))

    @classmethod
    def first_atomic_candidate(cls) -> ExtractorRegistryV2:
        """Build the three fixed first-operation extractor identities.

        Returns
        -------
        ExtractorRegistryV2
            Canonical count, variant and path extractor metadata.

        Notes
        -----
        The protected consumer must separately pin installed code and owner selection.
        """
        return cls.from_bytes(canonical_journal_json_v2(_FIRST_ATOMIC_BODY))

    @classmethod
    def from_bytes(cls, payload: bytes) -> ExtractorRegistryV2:
        """Reject aliases and extractor identities outside the closed catalogue.

        Parameters
        ----------
        payload : bytes
            Exact canonical bootstrap or first-candidate registry bytes.

        Returns
        -------
        ExtractorRegistryV2
            Recomputed digest and exact validated bytes.

        Raises
        ------
        ValueError
            Input is non-bytes, invalid JSON, noncanonical or contains any other extractor metadata.
        """
        if not isinstance(payload, bytes):
            raise ValueError("extractor registry must be bytes")
        try:
            body = project_registry_strict_json(payload)
            if canonical_journal_json_v2(body) != payload:
                raise ValueError("extractor registry bytes are not canonical")
        except ProjectRegistryInvalid as exc:
            raise ValueError("extractor registry is not strict JSON") from exc
        if body not in (_EMPTY_BODY, _FIRST_ATOMIC_BODY):
            raise ValueError("extractor registry contains an unreviewed extractor")
        return cls(payload, canonical_digest(body))
