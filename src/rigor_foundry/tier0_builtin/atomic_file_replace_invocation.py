# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — atomic file replacement invocation
"""Parse the exact, bounded invocation for the first built-in operation."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Final, cast

from ..effect_journal_records_v2 import canonical_journal_json_v2, parse_effect_target_ref_v2
from ..project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json

ATOMIC_FILE_REPLACE_OPERATION_ID: Final = "local-file-write.atomic-replace"
ATOMIC_FILE_REPLACE_VARIANT: Final = "replace-or-create"
MAX_REPLACEMENT_CONTENT_BYTES: Final = 16 * 1024 * 1024
_MAX_BASE64_LENGTH: Final = 4 * ((MAX_REPLACEMENT_CONTENT_BYTES + 2) // 3)
MAX_ATOMIC_PATH_BYTES: Final = 4095
MAX_ATOMIC_INVOCATION_BYTES: Final = _MAX_BASE64_LENGTH + 4 * (MAX_ATOMIC_PATH_BYTES + 1) + 1024
_FIELDS: Final = frozenset({"operation_id", "path", "content_b64", "declared"})
_DECLARED_FIELDS: Final = frozenset({"target_ref", "byte_count", "operation_variant"})


@dataclass(frozen=True)
class AtomicFileReplaceInvocationV2:
    """Canonical request bytes and caller declarations awaiting extraction.

    Attributes
    ----------
    payload : bytes
        Exact canonical JSON received by the parser.
    path : str
        Canonical absolute requested path, at most 4095 UTF-8 bytes.
    content : bytes
        Actual decoded replacement content, at most 16 MiB.
    declared_target_ref : dict[str, str]
        Unchecked caller declaration; it may differ from the requested path.
    declared_byte_count : int
        Unchecked caller count within the operation's content bound.
    declared_operation_variant : str
        Nonempty caller declaration awaiting the fixed extractor comparison.

    Notes
    -----
    A parsed request provides neither path admission nor permission to write.
    Direct construction bypasses parsing; consumers parse the payload again.
    """

    payload: bytes
    path: str
    content: bytes
    declared_target_ref: dict[str, str]
    declared_byte_count: int
    declared_operation_variant: str

    @classmethod
    def from_bytes(cls, payload: bytes) -> AtomicFileReplaceInvocationV2:
        """Reject aliases, oversized content and malformed declared fields.

        Parameters
        ----------
        payload : bytes
            Exact closed JSON wire for local-file-write.atomic-replace.
            Declaration agreement is checked by the composed extractor.

        Returns
        -------
        AtomicFileReplaceInvocationV2
            Validated wire, decoded bytes and unchecked declarations.

        Raises
        ------
        ValueError
            For non-bytes input, invalid or noncanonical JSON, wrong fields
            or operation, invalid paths, noncanonical base64, or exceeded
            payload, content or path bounds.
        """
        if type(payload) is not bytes:
            raise ValueError("atomic replacement invocation must be bytes")
        if len(payload) > MAX_ATOMIC_INVOCATION_BYTES:
            raise ValueError("atomic replacement invocation exceeds its byte bound")
        try:
            parsed = project_registry_strict_json(payload)
        except ProjectRegistryInvalid as exc:
            raise ValueError("atomic replacement invocation is not strict JSON") from exc
        if not isinstance(parsed, dict) or set(parsed) != _FIELDS:
            raise ValueError("atomic replacement invocation fields differ")
        body = cast(dict[str, object], parsed)
        canonical_journal_json_v2({**body, "content_b64": ""})
        if (
            json.dumps(
                body, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            != payload
        ):
            raise ValueError("atomic replacement invocation is not canonical JSON")
        if body["operation_id"] != ATOMIC_FILE_REPLACE_OPERATION_ID:
            raise ValueError("atomic replacement operation id differs")
        path = body["path"]
        if not isinstance(path, str):
            raise ValueError("atomic replacement path must be text")
        parse_effect_target_ref_v2({"form": "path", "value": path})
        if len(path.encode("utf-8")) > MAX_ATOMIC_PATH_BYTES:
            raise ValueError("atomic replacement path exceeds PATH_MAX")
        encoded = body["content_b64"]
        if not isinstance(encoded, str) or not encoded.isascii():
            raise ValueError("atomic replacement content must be standard base64")
        if len(encoded) > _MAX_BASE64_LENGTH:
            raise ValueError("atomic replacement content exceeds 16 MiB")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("atomic replacement content is not standard base64") from exc
        if len(content) > MAX_REPLACEMENT_CONTENT_BYTES:
            raise ValueError("atomic replacement content exceeds 16 MiB")
        if base64.b64encode(content).decode("ascii") != encoded:
            raise ValueError("atomic replacement content is not canonical bounded base64")
        declared = body["declared"]
        if not isinstance(declared, dict) or set(declared) != _DECLARED_FIELDS:
            raise ValueError("atomic replacement declared fields differ")
        declaration = cast(dict[str, object], declared)
        form, value = parse_effect_target_ref_v2(declaration["target_ref"])
        if form != "path":
            raise ValueError("atomic replacement declared target must be a path")
        if len(value.encode("utf-8")) > MAX_ATOMIC_PATH_BYTES:
            raise ValueError("atomic replacement declared path exceeds PATH_MAX")
        count = declaration["byte_count"]
        if type(count) is not int or not 0 <= count <= MAX_REPLACEMENT_CONTENT_BYTES:
            raise ValueError("atomic replacement declared byte count differs")
        variant = declaration["operation_variant"]
        if not isinstance(variant, str) or not variant:
            raise ValueError("atomic replacement declared variant must be text")
        return cls(payload, path, content, {"form": form, "value": value}, count, variant)
