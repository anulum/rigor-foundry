# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed v2 effect-class vocabulary
"""Parse the exact thirteen-class effect vocabulary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, cast

from .effect_journal_records_v2 import canonical_journal_json_v2
from .models import canonical_digest
from .project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json

EFFECT_CLASSES_V2: Final = (
    "cloud-resource",
    "compute-job",
    "coordination-message",
    "exchange-record-create",
    "external-send",
    "git-commit",
    "git-push-or-publication",
    "local-file-write",
    "package-or-model-upload",
    "provider-call-with-spend",
    "read",
    "repo-visibility-change",
    "shared-storage-write",
)
EFFECT_VOCABULARY_SCHEMA_V2: Final = "rigor.effect-class-vocabulary.v2"
EFFECT_VOCABULARY_DIGEST_V2: Final = (
    "1f116c17442687a3cb00e6b574c8306da57ff2fc902039ea2890bb396de0d563"
)


@dataclass(frozen=True)
class EffectVocabularyV2:
    """One immutable effect vocabulary.

    Attributes
    ----------
    body_bytes : bytes
        Canonical JSON encoding of the fixed class list.
    vocabulary_digest : str
        Reviewed content digest; this object conveys no execution authority.
    """

    body_bytes: bytes
    vocabulary_digest: str

    @classmethod
    def build(cls) -> EffectVocabularyV2:
        """Construct the fixed v2 class list.

        Returns
        -------
        EffectVocabularyV2
            Canonical bytes with the independently fixed digest.

        Raises
        ------
        ValueError
            Compiled classes differ from the fixed version digest.
        """
        return cls.from_bytes(
            canonical_journal_json_v2(
                {"schema": EFFECT_VOCABULARY_SCHEMA_V2, "classes": list(EFFECT_CLASSES_V2)}
            )
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> EffectVocabularyV2:
        """Parse only the exact canonical v2 class list.

        Parameters
        ----------
        payload : bytes
            Canonical UTF-8 JSON vocabulary body.

        Returns
        -------
        EffectVocabularyV2
            Immutable bytes and their verified content digest.

        Raises
        ------
        ValueError
            Encoding, schema, class ordering or version digest differs.
        """
        if not isinstance(payload, bytes):
            raise ValueError("effect vocabulary must be bytes")
        try:
            parsed = project_registry_strict_json(payload)
            if canonical_journal_json_v2(parsed) != payload:
                raise ValueError("effect vocabulary bytes are not canonical")
        except ProjectRegistryInvalid as exc:
            raise ValueError("effect vocabulary is not strict JSON") from exc
        if not isinstance(parsed, dict) or set(parsed) != {"schema", "classes"}:
            raise ValueError("effect vocabulary fields differ")
        body = cast(dict[str, object], parsed)
        if body["schema"] != EFFECT_VOCABULARY_SCHEMA_V2 or body["classes"] != list(
            EFFECT_CLASSES_V2
        ):
            raise ValueError("effect vocabulary v2 content differs")
        digest = canonical_digest(body)
        if digest != EFFECT_VOCABULARY_DIGEST_V2:
            raise ValueError("effect vocabulary v2 reviewed digest differs")
        return cls(payload, digest)

    def contains(self, effect_class: str) -> bool:
        """Check exact class membership.

        Parameters
        ----------
        effect_class : str
            Class spelling to inspect.

        Returns
        -------
        bool
            Whether the spelling occurs in the fixed class list.
        """
        return effect_class in EFFECT_CLASSES_V2
