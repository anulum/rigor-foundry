# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed effect target table
"""Bind v2 effect classes to the exact target kinds and selector forms."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, cast

from .effect_journal_records_v2 import canonical_journal_json_v2
from .effect_vocabulary_v2 import EffectVocabularyV2
from .models import canonical_digest
from .project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json

EFFECT_TARGET_TABLE_SCHEMA_V2: Final = "rigor.effect-target-table.v2"
EFFECT_TARGET_TABLE_DIGEST_V2: Final = (
    "4340dcb96fabda56535afcba2ec0b9b8160e8e0c98a9cbdde6b2aecf1d3d2c76"
)
_ROWS: Final[tuple[tuple[str, str, tuple[str, ...]], ...]] = (
    ("cloud-resource", "cloud-resource", ("endpoint", "remote")),
    ("compute-job", "compute-host", ("endpoint",)),
    ("coordination-message", "service-endpoint", ("endpoint",)),
    ("exchange-record-create", "filesystem-path", ("path",)),
    ("external-send", "send-channel", ("endpoint", "remote")),
    ("git-commit", "repository", ("path",)),
    ("git-push-or-publication", "remote-location", ("remote",)),
    ("git-push-or-publication", "repository", ("remote",)),
    ("local-file-write", "filesystem-path", ("path",)),
    ("package-or-model-upload", "service-endpoint", ("endpoint",)),
    ("provider-call-with-spend", "service-endpoint", ("endpoint",)),
    ("read", "filesystem-path", ("path",)),
    ("repo-visibility-change", "repository", ("remote",)),
    ("shared-storage-write", "filesystem-path", ("path",)),
    ("shared-storage-write", "remote-location", ("remote",)),
)


def _body() -> dict[str, object]:
    """Construct the reviewed, closed 15-row body."""
    return {
        "schema": EFFECT_TARGET_TABLE_SCHEMA_V2,
        "vocabulary_digest": EffectVocabularyV2.build().vocabulary_digest,
        "rows": [
            {"effect_class": effect_class, "target_kind": target_kind, "forms": list(forms)}
            for effect_class, target_kind, forms in _ROWS
        ],
    }


@dataclass(frozen=True)
class EffectTargetTableV2:
    """One immutable effect-to-target mapping.

    Attributes
    ----------
    body_bytes : bytes
        Canonical JSON for the fixed fifteen rows and vocabulary reference.
    table_digest : str
        Reviewed content digest; selection custody remains host-owned.
    """

    body_bytes: bytes
    table_digest: str

    @classmethod
    def build(cls) -> EffectTargetTableV2:
        """Construct the fixed v2 target mapping.

        Returns
        -------
        EffectTargetTableV2
            Canonical bytes and the verified fixed digest.

        Raises
        ------
        ValueError
            Compiled rows differ from the fixed version digest.
        """
        return cls.from_bytes(canonical_journal_json_v2(_body()))

    @classmethod
    def from_bytes(cls, payload: bytes) -> EffectTargetTableV2:
        """Parse the exact canonical v2 target mapping.

        Parameters
        ----------
        payload : bytes
            Canonical UTF-8 JSON containing the fixed mapping.

        Returns
        -------
        EffectTargetTableV2
            Immutable bytes and their verified content digest.

        Raises
        ------
        ValueError
            Encoding, rows, vocabulary reference or fixed digest differs.
        """
        if not isinstance(payload, bytes):
            raise ValueError("effect target table must be bytes")
        try:
            parsed = project_registry_strict_json(payload)
            if canonical_journal_json_v2(parsed) != payload:
                raise ValueError("effect target table bytes are not canonical")
        except ProjectRegistryInvalid as exc:
            raise ValueError("effect target table is not strict JSON") from exc
        if parsed != _body():
            raise ValueError("effect target table v2 content differs")
        body = cast(dict[str, object], parsed)
        digest = canonical_digest(body)
        if digest != EFFECT_TARGET_TABLE_DIGEST_V2:
            raise ValueError("effect target table v2 reviewed digest differs")
        return cls(payload, digest)

    def allows(self, effect_class: str, target_kind: str, form: str) -> bool:
        """Check whether a target triple belongs to the mapping.

        Parameters
        ----------
        effect_class : str
            Exact effect class.
        target_kind : str
            Exact target kind.
        form : str
            Concrete selector form, such as path or remote.

        Returns
        -------
        bool
            Whether the fixed table contains the triple.
        """
        return any(
            effect_class == row_class and target_kind == row_kind and form in forms
            for row_class, row_kind, forms in _ROWS
        )

    def triples_for_class(self, effect_class: str) -> tuple[tuple[str, str], ...]:
        """List the target kinds and forms for an effect class.

        Parameters
        ----------
        effect_class : str
            Exact class spelling.

        Returns
        -------
        tuple[tuple[str, str], ...]
            Target-kind/form pairs in fixed row order, or an empty tuple.
        """
        return tuple(
            (target_kind, form)
            for row_class, target_kind, forms in _ROWS
            if effect_class == row_class
            for form in forms
        )
