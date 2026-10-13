# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected owner-confirmation record wire
"""Parse the closed owner-confirmation record without claiming native proof."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Final, cast
from uuid import UUID

from .audit_primitives import require_integer
from .discovery_source_schema import parse_json
from .effect_class_authority_requirement_v2 import EffectClassAuthorityRequirementV2
from .effect_journal_records_v2 import canonical_journal_json_v2
from .model_primitives import require_digest, require_utc_timestamp
from .models import canonical_digest, require_mapping
from .project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json
from .semantic_ratification_source import verify_full_text_ratification_source

OWNER_CONFIRMATION_SCHEMA_V2: Final = "rigor.owner-confirmation.v2"
_BODY_FIELDS: Final = frozenset(
    {
        "schema",
        "subject_kind",
        "subject_digest",
        "question_sha256",
        "reply_sha256",
        "capture_manifest_digest",
        "transcript",
        "captured_at",
    }
)
_TRANSCRIPT_FIELDS: Final = frozenset(
    {"path", "question_line", "reply_line", "reply_uuid", "reply_line_sha256"}
)


@dataclass(frozen=True)
class OwnerConfirmationRecordV2:
    """Canonical confirmation record awaiting retained transcript verification.

    Attributes
    ----------
    body_bytes : bytes
        Exact canonical record.
    record_digest, subject_digest : str
        Record identity and declared requirement identity.
    question_sha256, reply_sha256, capture_manifest_digest : str
        Retained capture identities.
    transcript_path : Path
        Absolute retained native JSONL source path.
    question_line, reply_line : int
        One-based native question and later reply selectors.
    reply_uuid, reply_line_sha256 : str
        Exact native reply identity and line-byte digest.
    captured_at : str
        Declared UTC capture time; this is not an authenticated clock.
    """

    body_bytes: bytes
    record_digest: str
    subject_digest: str
    question_sha256: str
    reply_sha256: str
    capture_manifest_digest: str
    transcript_path: Path
    question_line: int
    reply_line: int
    reply_uuid: str
    reply_line_sha256: str
    captured_at: str

    @classmethod
    def from_bytes(cls, payload: bytes) -> OwnerConfirmationRecordV2:
        """Parse the closed confirmation record without granting authority.

        Parameters
        ----------
        payload : bytes
            Canonical UTF-8 JSON with exact subject and transcript selectors.

        Returns
        -------
        OwnerConfirmationRecordV2
            Immutable bytes and validated selector fields.

        Raises
        ------
        ValueError
            Encoding, fields, digests, UUID, chronology or selectors are malformed.
        """
        if not isinstance(payload, bytes):
            raise ValueError("owner confirmation must be bytes")
        try:
            parsed = project_registry_strict_json(payload)
            if canonical_journal_json_v2(parsed) != payload:
                raise ValueError("owner confirmation bytes are not canonical")
        except ProjectRegistryInvalid as exc:
            raise ValueError("owner confirmation is not strict JSON") from exc
        if not isinstance(parsed, dict) or set(parsed) != _BODY_FIELDS:
            raise ValueError("owner confirmation fields differ")
        body = cast(dict[str, object], parsed)
        if (
            body["schema"] != OWNER_CONFIRMATION_SCHEMA_V2
            or body["subject_kind"] != "effect-class-authority-requirement"
        ):
            raise ValueError("owner confirmation subject differs")
        transcript = body["transcript"]
        if not isinstance(transcript, dict) or set(transcript) != _TRANSCRIPT_FIELDS:
            raise ValueError("owner confirmation transcript fields differ")
        selected = cast(dict[str, object], transcript)
        path = selected["path"]
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise ValueError("owner confirmation transcript path must be absolute")
        question_line = require_integer(
            selected["question_line"], "owner confirmation question line", minimum=2
        )
        reply_line = require_integer(
            selected["reply_line"], "owner confirmation reply line", minimum=3
        )
        if not 1 <= reply_line - question_line - 1 <= 16:
            raise ValueError(
                "owner confirmation reply is not later within its bounded lineage gap"
            )
        reply_uuid = selected["reply_uuid"]
        if not isinstance(reply_uuid, str):
            raise ValueError("owner confirmation reply UUID must be text")
        try:
            if str(UUID(reply_uuid)) != reply_uuid:
                raise ValueError("owner confirmation reply UUID is not canonical")
        except ValueError as exc:
            raise ValueError("owner confirmation reply UUID is invalid") from exc
        return cls(
            payload,
            canonical_digest(body),
            require_digest(body["subject_digest"], "owner confirmation subject digest"),
            require_digest(body["question_sha256"], "owner confirmation question digest"),
            require_digest(body["reply_sha256"], "owner confirmation reply digest"),
            require_digest(body["capture_manifest_digest"], "owner confirmation manifest digest"),
            Path(path),
            question_line,
            reply_line,
            reply_uuid,
            require_digest(selected["reply_line_sha256"], "owner confirmation native line"),
            require_utc_timestamp(body["captured_at"], "owner confirmation captured_at"),
        )


def verify_owner_confirmation_v2(
    *,
    record: OwnerConfirmationRecordV2,
    requirement: EffectClassAuthorityRequirementV2,
    manifest_bytes: bytes,
    question_capture: bytes,
    reply_capture: bytes,
    expected_authority_requirement_digest: str,
    expected_owner_confirmation_digest: str,
) -> dict[str, object]:
    """Recheck retained native owner approval as an integrity dependency only.

    Parameters
    ----------
    record : OwnerConfirmationRecordV2
        Selected exact canonical confirmation record.
    requirement : EffectClassAuthorityRequirementV2
        Selected exact requirement list to which the decision must refer.
    manifest_bytes, question_capture, reply_capture : bytes
        Retained native capture manifest and complete LF-terminated messages.
    expected_authority_requirement_digest, expected_owner_confirmation_digest : str
        Independently selected identities of the requirement and record.

    Returns
    -------
    dict[str, object]
        Deterministic integrity proof with ``guard_admissible`` false.

    Raises
    ------
    PermissionError
        Selection, native capture identity, chronology or exact decision differs.
    ValueError
        A selected record, capture or native event is malformed or changed.
    OSError
        The native transcript cannot be opened safely.

    Notes
    -----
    The protected host must select every input and re-run this at final recheck.
    Caller-selected bytes and pins cannot grant operational admission. The source
    format is a constrained Claude JSONL subset requiring human origin and main
    chain markers. It does not authenticate a caller-supplied transcript.
    """
    if (
        OwnerConfirmationRecordV2.from_bytes(record.body_bytes) != record
        or record.record_digest != expected_owner_confirmation_digest
        or EffectClassAuthorityRequirementV2.from_bytes(requirement.body_bytes) != requirement
        or requirement.requirement_digest != expected_authority_requirement_digest
        or record.subject_digest != requirement.requirement_digest
    ):
        raise PermissionError("owner confirmation differs from selected records")
    if not all(
        isinstance(value, bytes) for value in (manifest_bytes, question_capture, reply_capture)
    ):
        raise PermissionError("owner confirmation retained captures are missing")
    if sha256(manifest_bytes).hexdigest() != record.capture_manifest_digest:
        raise PermissionError("owner confirmation manifest differs")
    integrity = verify_full_text_ratification_source(
        manifest_bytes=manifest_bytes,
        question_capture=question_capture,
        reply_capture=reply_capture,
        transcript_path=record.transcript_path,
        expected_manifest_sha256=record.capture_manifest_digest,
        expected_question_sha256=record.question_sha256,
        expected_reply_sha256=record.reply_sha256,
    )
    manifest = require_mapping(parse_json(manifest_bytes), "owner confirmation manifest")
    captures = require_mapping(manifest["captures"], "owner confirmation captures")
    question = require_mapping(captures["CEO_QUESTION_FULL_TEXT.txt"], "owner question")
    reply = require_mapping(captures["OWNER_REPLY.txt"], "owner reply")
    if (
        question["jsonl_line"] != record.question_line
        or reply["jsonl_line"] != record.reply_line
        or reply["uuid"] != record.reply_uuid
        or reply["native_line_sha256"] != record.reply_line_sha256
        or question["text_sha256"] != sha256(question_capture).hexdigest()
        or reply["text_sha256"] != sha256(reply_capture).hexdigest()
    ):
        raise PermissionError("owner confirmation differs from native capture manifest")
    if datetime.fromisoformat(cast(str, reply["timestamp"])) <= datetime.fromisoformat(
        cast(str, question["timestamp"])
    ):
        raise PermissionError("owner confirmation reply is not later")
    decision = f"SCHVAĽUJEM effect-class-authority-requirement {requirement.requirement_digest}"
    expected_list = "".join(f"{item}\n" for item in requirement.enforced_required)
    lines = [part + "\n" for part in question_capture.decode("utf-8").split("\n")[:-1]]
    reply_text = reply_capture.decode("utf-8")
    decision_lines = [
        line for line in lines if line.startswith("SCHVAĽUJEM effect-class-authority-requirement ")
    ]
    start = "--- enforced_required ---\n"
    end = "--- end ---\n"
    if (
        decision_lines != [f"{decision}\n"]
        or lines.count(start) != 1
        or lines.count(end) != 1
        or lines.index(end) <= lines.index(start)
        or "".join(lines[lines.index(start) + 1 : lines.index(end)]) != expected_list
    ):
        raise PermissionError("owner confirmation question differs from selected list")
    if unicodedata.normalize("NFC", reply_text).strip(" \t\n\r").encode(
        "utf-8"
    ) != decision.encode("utf-8"):
        raise PermissionError("owner confirmation reply is not the exact decision")
    proof: dict[str, object] = {
        "schema": "rigor.owner-confirmation-proof.v2",
        "assertion_class": "native-owner-confirmation-dependency-only",
        "guard_admissible": False,
        "authority_requirement_digest": requirement.requirement_digest,
        "owner_confirmation_digest": record.record_digest,
        "source_proof_digest": integrity["proof_digest"],
    }
    return {**proof, "proof_digest": canonical_digest(proof)}
