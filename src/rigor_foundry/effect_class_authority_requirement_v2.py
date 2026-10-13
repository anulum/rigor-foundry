# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — v2 effect-class authority requirement
"""Parse explicit effect-class authority requirement records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, cast

from .effect_journal_records_v2 import canonical_journal_json_v2
from .effect_vocabulary_v2 import EFFECT_CLASSES_V2
from .models import canonical_digest
from .project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json

AUTHORITY_REQUIREMENT_SCHEMA_V2: Final = "rigor.effect-class-authority-requirement.v2"
DEFAULT_ENFORCED_REQUIRED_V2: Final = (
    "cloud-resource",
    "external-send",
    "git-push-or-publication",
    "package-or-model-upload",
    "provider-call-with-spend",
    "repo-visibility-change",
    "shared-storage-write",
)


@dataclass(frozen=True)
class EffectClassAuthorityRequirementV2:
    """Canonical list, with confirmation and selection verified separately.

    Attributes
    ----------
    body_bytes : bytes
        Exact closed canonical JSON requirement record.
    requirement_digest : str
        Canonical content digest.
    enforced_required : tuple[str, ...]
        Sorted effect classes that this proposed list marks as enforced-required.
    """

    body_bytes: bytes
    requirement_digest: str
    enforced_required: tuple[str, ...]

    @classmethod
    def build_default(cls) -> EffectClassAuthorityRequirementV2:
        """Construct the proposed default without implying owner consent.

        Returns
        -------
        EffectClassAuthorityRequirementV2
            Canonical proposal only; no operative policy is selected.
        """
        return cls.from_bytes(
            canonical_journal_json_v2(
                {
                    "schema": AUTHORITY_REQUIREMENT_SCHEMA_V2,
                    "enforced_required": list(DEFAULT_ENFORCED_REQUIRED_V2),
                }
            )
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> EffectClassAuthorityRequirementV2:
        """Parse a closed canonical requirement list.

        Parameters
        ----------
        payload : bytes
            Canonical UTF-8 JSON containing a sorted subset of known effect classes.

        Returns
        -------
        EffectClassAuthorityRequirementV2
            Immutable bytes, digest and declared classes.

        Raises
        ------
        ValueError
            Fields, schema, encoding, order or class membership differs.
        """
        if not isinstance(payload, bytes):
            raise ValueError("authority requirement must be bytes")
        try:
            parsed = project_registry_strict_json(payload)
            if canonical_journal_json_v2(parsed) != payload:
                raise ValueError("authority requirement bytes are not canonical")
        except ProjectRegistryInvalid as exc:
            raise ValueError("authority requirement is not strict JSON") from exc
        if not isinstance(parsed, dict) or set(parsed) != {"schema", "enforced_required"}:
            raise ValueError("authority requirement fields differ")
        body = cast(dict[str, object], parsed)
        items = body["enforced_required"]
        if body["schema"] != AUTHORITY_REQUIREMENT_SCHEMA_V2 or not isinstance(items, list):
            raise ValueError("authority requirement v2 content differs")
        if any(type(item) is not str or item not in EFFECT_CLASSES_V2 for item in items):
            raise ValueError("authority requirement has an unknown effect class")
        classes = cast(list[str], items)
        if classes != sorted(set(classes), key=lambda value: value.encode("utf-8")):
            raise ValueError("authority requirement classes must be sorted and unique")
        return cls(payload, canonical_digest(body), tuple(classes))

    def requires_enforced(self, effect_class: str) -> bool:
        """Check declared membership without evaluating an action or scope.

        Parameters
        ----------
        effect_class : str
            Exact known v2 effect class.

        Returns
        -------
        bool
            Whether the list includes this class.

        Raises
        ------
        ValueError
            The effect class is unknown.
        """
        if effect_class not in EFFECT_CLASSES_V2:
            raise ValueError("unknown effect class")
        return effect_class in self.enforced_required
