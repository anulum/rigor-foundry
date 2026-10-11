# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected effect-journal record wire
"""Validate canonical effect-journal frames before protected state replay."""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from hashlib import sha256
from typing import Final, cast
from uuid import UUID

from .effect_target_grammar_v2 import TARGET_VARIANT_V2, require_remote_target_v2
from .model_primitives import require_utc_timestamp
from .project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json
from .trust import ED25519_SIGNATURE_HEX_LENGTH, require_lower_hex

JOURNAL_MAGIC_V2: Final = b"RIGOR-EFFECT-JOURNAL-V2.1\n"
JOURNAL_GENESIS_V2: Final = sha256(JOURNAL_MAGIC_V2).digest()
_DOMAIN: Final = "rigor.effect-journal.v2.1"
_LENGTH: Final = struct.Struct(">I")
_MAX_PAYLOAD: Final = 65536
_SAFE_INTEGER: Final = 2**53 - 1
_KEY: Final = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_DIGEST: Final = re.compile(r"[0-9a-f]{64}\Z")
_VARIANT: Final = TARGET_VARIANT_V2
_REGISTRY_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SEAT_ID: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z"
)
_EFFECT_CLASSES: Final = frozenset(
    {
        "read",
        "local-file-write",
        "git-commit",
        "git-push-or-publication",
        "package-or-model-upload",
        "provider-call-with-spend",
        "external-send",
        "compute-job",
        "shared-storage-write",
        "cloud-resource",
        "repo-visibility-change",
        "coordination-message",
        "exchange-record-create",
    }
)
_STATUS_KINDS: Final = frozenset(
    {"terminated", "overrun", "unkillable", "adopted-after-restart", "ended-unknown"}
)
_CLOSURE_KINDS: Final = frozenset(
    {"operation-complete", "operation-rolled-back", "operation-reconciled", "operation-partial"}
)
_RELEASE_KINDS: Final = frozenset({"target-reconciled"})
_BODY_FIELDS: Final = {
    "operation-intent": frozenset(
        {
            "permit_id",
            "permit_digest",
            "ledger_head",
            "effect_target_digest",
            "decision_digest",
            "grant_snapshot_digest",
            "adapter_operations_digest",
            "operation_key",
            "cgroup_id",
            "atomicity",
            "parts",
        }
    ),
    "effect-intent": frozenset({"permit_id", "part_index", "pre_state_digest"}),
    "effect-complete": frozenset({"permit_id", "part_index", "post_state_digest"}),
    "effect-failed": frozenset({"permit_id", "part_index", "post_state_digest", "failure_code"}),
    "operation-complete": frozenset({"permit_id", "parts_result_digest"}),
    "operation-rolled-back": frozenset({"permit_id", "rollback_evidence_digest"}),
    "operation-reconciled": frozenset(
        {"permit_id", "reconciliation_evidence_digest", "operator_identity", "state_digest"}
    ),
    "operation-partial": frozenset(
        {"permit_id", "parts_applied", "blocked_targets", "evidence_digest"}
    ),
    "target-reconciled": frozenset(
        {
            "permit_id",
            "target_ref",
            "outcome",
            "state_digest",
            "reconciliation_evidence_digest",
            "operator_identity",
            "operator_policy_digest",
            "operator_signature",
        }
    ),
    "trust-policy-activated": frozenset(
        {"policy_digest", "previous_policy_digest", "activation_evidence_digest", "root_signature"}
    ),
    "key-revoked": frozenset(
        {"key_fingerprint", "compromised_since_seq", "evidence_digest", "root_signature"}
    ),
    "cleared-orphan-leaf": frozenset({"cgroup_id", "operator_identity", "status_evidence_digest"}),
    "removed-empty-leaf": frozenset({"cgroup_id", "operator_identity", "status_evidence_digest"}),
    "journal-tail-recovery": frozenset(
        {"recovery_intent_digest", "removed_digest", "removed_length", "operator_identity"}
    ),
}
_BODY_FIELDS.update(
    {
        kind: frozenset({"permit_id", "cgroup_id", "status_evidence_digest"})
        for kind in _STATUS_KINDS
    }
)
_OUTER_FIELDS: Final = frozenset({"body", "domain", "host_time", "kind", "previous_head", "seq"})
_PART_FIELDS: Final = frozenset(
    {"index", "effect_class", "target_ref", "route_digest", "operation_variant"}
)


def _canonical_value(value: object) -> None:
    """Require the restricted PCS-CANON-1 value and key domain."""
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -_SAFE_INTEGER <= value <= _SAFE_INTEGER:
            raise ValueError("journal integer exceeds PCS-CANON-1 range")
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value) or any(
            ord(char) < 0x20 and char not in "\t\n\r" for char in value
        ):
            raise ValueError("journal string exceeds PCS-CANON-1 range")
        return
    if isinstance(value, list):
        for item in cast(list[object], value):
            _canonical_value(item)
        return
    if isinstance(value, dict):
        for key, item in cast(dict[object, object], value).items():
            if not isinstance(key, str) or _KEY.fullmatch(key) is None:
                raise ValueError("journal object key exceeds PCS-CANON-1 range")
            _canonical_value(item)
        return
    raise ValueError("journal contains a value outside PCS-CANON-1")


def canonical_journal_json_v2(value: object) -> bytes:
    """Encode one PCS-CANON-1 value as exact canonical UTF-8 bytes.

    Parameters
    ----------
    value
        Restricted JSON value with lowercase identifier keys and safe integers.

    Returns
    -------
    bytes
        Sorted, compact JSON without alternate numeric or Unicode spellings.

    Raises
    ------
    ValueError
        If a value falls outside the canonical profile or exceeds supported nesting.
    """
    try:
        _canonical_value(value)
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except RecursionError as exc:
        raise ValueError("journal nesting exceeds supported depth") from exc


def _object(value: object, fields: frozenset[str], label: str) -> dict[str, object]:
    """Require one closed object with the named fields."""
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields differ")
    return cast(dict[str, object], value)


def _string(value: object, label: str) -> str:
    """Require one nonempty string after canonical JSON validation."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _digest(value: object, label: str) -> str:
    """Require a lowercase SHA-256 digest."""
    text = _string(value, label)
    if _DIGEST.fullmatch(text) is None:
        raise ValueError(f"{label} must be a lowercase digest")
    return text


def _uuid(value: object, label: str) -> str:
    """Require a canonical non-reserved UUID."""
    text = _string(value, label)
    try:
        parsed = UUID(text)
    except ValueError as exc:
        raise ValueError(f"{label} must be a UUID") from exc
    if str(parsed) != text or parsed.int in (0, (1 << 128) - 1):
        raise ValueError(f"{label} must be a canonical non-reserved UUID")
    return text


def _positive_decimal(value: object, label: str) -> str:
    """Require a positive decimal inode string without leading zeros."""
    text = _string(value, label)
    if not text.isascii() or not text.isdecimal() or text[0] == "0":
        raise ValueError(f"{label} must be a positive decimal string")
    return text


def parse_effect_target_ref_v2(value: object) -> tuple[str, str]:
    """Validate a closed extracted target and preserve its exact identity.

    Parameters
    ----------
    value
        Mapping with exactly ``form`` and ``value`` for a supported target.

    Returns
    -------
    tuple[str, str]
        Validated form and value without normalisation or aliases.

    Raises
    ------
    ValueError
        If fields, target syntax or target form are invalid.
    """
    target = _object(value, frozenset({"form", "value"}), "target_ref")
    form = _string(target["form"], "target_ref.form")
    name = _string(target["value"], "target_ref.value")
    if form == "path":
        if (
            not name.startswith("/")
            or (name != "/" and name.endswith("/"))
            or any(part in ("", ".", "..") for part in name[1:].split("/") if name != "/")
            or any(ord(char) < 0x20 for char in name)
        ):
            raise ValueError("target_ref path is not canonical absolute POSIX")
    elif form == "remote":
        require_remote_target_v2(name)
    elif form == "endpoint":
        service, separator, resource = name.partition(":")
        if (
            separator != ":"
            or _VARIANT.fullmatch(service) is None
            or _VARIANT.fullmatch(resource) is None
        ):
            raise ValueError("target_ref endpoint is malformed")
    elif form == "project":
        if _REGISTRY_ID.fullmatch(name) is None:
            raise ValueError("target_ref project id is malformed")
    elif form == "record":
        _uuid(name, "target_ref record")
    else:
        raise ValueError("target_ref form is unknown")
    return form, name


def _body(kind: str, value: object) -> dict[str, object]:
    """Validate the closed kind-specific body shape and primitive fields."""
    fields = _BODY_FIELDS.get(kind)
    if fields is None:
        raise ValueError("journal record kind is unknown")
    body = _object(value, fields, f"{kind} body")
    for field in fields & frozenset(
        {
            "permit_digest",
            "ledger_head",
            "effect_target_digest",
            "decision_digest",
            "grant_snapshot_digest",
            "adapter_operations_digest",
            "route_digest",
            "parts_result_digest",
            "rollback_evidence_digest",
            "reconciliation_evidence_digest",
            "state_digest",
            "status_evidence_digest",
            "recovery_intent_digest",
            "removed_digest",
            "evidence_digest",
            "policy_digest",
            "activation_evidence_digest",
            "key_fingerprint",
            "operator_policy_digest",
        }
    ):
        _digest(body[field], field)
    if "permit_id" in body:
        _uuid(body["permit_id"], "permit_id")
    if "cgroup_id" in body:
        _positive_decimal(body["cgroup_id"], "cgroup_id")
    if "operator_identity" in body:
        _string(body["operator_identity"], "operator_identity")
    if kind == "target-reconciled":
        if _SEAT_ID.fullmatch(cast(str, body["operator_identity"])) is None:
            raise ValueError("target reconciliation operator identity must be a K7 seat")
        parse_effect_target_ref_v2(body["target_ref"])
        if body["outcome"] not in ("pre-state-restored", "post-state-accepted"):
            raise ValueError("target reconciliation outcome is unknown")
        require_lower_hex(
            body["operator_signature"],
            "target reconciliation operator signature",
            length=ED25519_SIGNATURE_HEX_LENGTH,
        )
    if kind in ("trust-policy-activated", "key-revoked"):
        require_lower_hex(
            body["root_signature"],
            "trust record root signature",
            length=ED25519_SIGNATURE_HEX_LENGTH,
        )
    if kind == "trust-policy-activated" and body["previous_policy_digest"] is not None:
        _digest(body["previous_policy_digest"], "previous_policy_digest")
    if (
        kind == "key-revoked"
        and body["compromised_since_seq"] is not None
        and (type(body["compromised_since_seq"]) is not int or body["compromised_since_seq"] < 1)
    ):
        raise ValueError("compromised_since_seq must be a positive journal position")
    if "part_index" in body and (type(body["part_index"]) is not int or body["part_index"] < 0):
        raise ValueError("part_index must be nonnegative")
    for field in ("pre_state_digest", "post_state_digest"):
        if field in body and body[field] is not None:
            _digest(body[field], field)
    if "failure_code" in body:
        _string(body["failure_code"], "failure_code")
    if "removed_length" in body and (
        type(body["removed_length"]) is not int or body["removed_length"] <= 0
    ):
        raise ValueError("removed_length must be positive")
    if kind == "operation-intent":
        if _REGISTRY_ID.fullmatch(_string(body["operation_key"], "operation_key")) is None:
            raise ValueError("operation_key is malformed")
        if body["atomicity"] not in (
            "atomic",
            "all-or-nothing-journalled",
            "partial-allowed",
        ):
            raise ValueError("operation atomicity is unknown")
        parts = body["parts"]
        if not isinstance(parts, list) or not parts:
            raise ValueError("operation parts must be nonempty")
        for index, item in enumerate(parts):
            part = _object(item, _PART_FIELDS, "operation part")
            if type(part["index"]) is not int or part["index"] != index:
                raise ValueError("operation part indexes differ")
            if _string(part["effect_class"], "effect_class") not in _EFFECT_CLASSES:
                raise ValueError("operation effect class is unknown")
            parse_effect_target_ref_v2(part["target_ref"])
            _digest(part["route_digest"], "route_digest")
            if _VARIANT.fullmatch(_string(part["operation_variant"], "operation_variant")) is None:
                raise ValueError("operation variant is malformed")
    if kind == "operation-partial":
        applied = body["parts_applied"]
        if (
            not isinstance(applied, list)
            or any(type(index) is not int or index < 0 for index in applied)
            or applied != sorted(set(applied))
        ):
            raise ValueError("operation partial parts_applied must be ascending and unique")
        blocked = body["blocked_targets"]
        if not isinstance(blocked, list):
            raise ValueError("operation partial blocked_targets must be an array")
        keys = [parse_effect_target_ref_v2(item) for item in blocked]
        if keys != sorted(set(keys), key=lambda item: (item[0].encode(), item[1].encode())):
            raise ValueError("operation partial blocked_targets must be byte-sorted and unique")
    return body


@dataclass(frozen=True)
class EffectJournalRecordV2:
    """Carry one parsed frame without granting writer or effect authority.

    Parameters
    ----------
    seq
        Positive integer position in the retained chain.
    kind
        Closed event kind.
    body
        Validated kind-specific fields.
    host_time
        Canonical UTC timestamp supplied by the record writer.
    previous_head
        Hex digest of the preceding chain head.
    record_head
        Hex digest joining the preceding head and this frame payload.
    record_digest
        SHA-256 of the complete frame.
    frame
        Original bounded length-prefixed canonical JSON and chain head.

    Notes
    -----
    A direct instance is data. Consumers reparse original frame bytes and
    independently establish custody, signatures and transaction authority.
    """

    seq: int
    kind: str
    body: dict[str, object]
    host_time: str
    previous_head: str
    record_head: str
    record_digest: str
    frame: bytes


def parse_effect_journal_frame_v2(
    frame: bytes, *, previous_head: bytes, expected_seq: int
) -> EffectJournalRecordV2:
    """Check one complete frame against its expected chain position.

    Parameters
    ----------
    frame
        Original length-prefixed canonical JSON followed by its chain head.
    previous_head
        Independently retained 32-byte preceding chain head.
    expected_seq
        Positive integer position expected by the scanning caller.

    Returns
    -------
    EffectJournalRecordV2
        Structurally valid original data, without writer authentication.

    Raises
    ------
    ValueError, PermissionError
        If framing, position, schema, canonical bytes or chain identity differ.
    """
    if len(previous_head) != 32 or type(expected_seq) is not int or expected_seq < 1:
        raise ValueError("journal scan position differs")
    if len(frame) < 37:
        raise PermissionError("journal frame is incomplete")
    length = _LENGTH.unpack(frame[:4])[0]
    if not 1 <= length <= _MAX_PAYLOAD or len(frame) != 4 + length + 32:
        raise PermissionError("journal frame length differs")
    payload = frame[4 : 4 + length]
    try:
        decoded = project_registry_strict_json(payload)
        canonical = canonical_journal_json_v2(decoded)
    except (ProjectRegistryInvalid, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise PermissionError("journal frame JSON is invalid") from exc
    if canonical != payload:
        raise PermissionError("journal frame JSON is not canonical")
    data = _object(decoded, _OUTER_FIELDS, "journal record")
    if data["domain"] != _DOMAIN or type(data["seq"]) is not int or data["seq"] != expected_seq:
        raise PermissionError("journal domain or sequence differs")
    if data["previous_head"] != previous_head.hex():
        raise PermissionError("journal previous head differs")
    host_time = _string(data["host_time"], "host_time")
    if host_time != require_utc_timestamp(host_time, "journal.host_time"):
        raise PermissionError("journal host time is not canonical UTC")
    kind = _string(data["kind"], "kind")
    body = _body(kind, data["body"])
    if kind == "key-revoked":
        compromise = body["compromised_since_seq"]
        if compromise is not None and cast(int, compromise) > expected_seq:
            raise ValueError("compromised_since_seq exceeds its record position")
    head = sha256(previous_head + frame[: 4 + length]).digest()
    if frame[-32:] != head:
        raise PermissionError("journal record head differs")
    return EffectJournalRecordV2(
        seq=expected_seq,
        kind=kind,
        body=body,
        host_time=host_time,
        previous_head=previous_head.hex(),
        record_head=head.hex(),
        record_digest=sha256(frame).hexdigest(),
        frame=frame,
    )


def build_effect_journal_frame_v2(
    *,
    kind: str,
    body: dict[str, object],
    host_time: str,
    previous_head: bytes,
    seq: int,
) -> EffectJournalRecordV2:
    """Build and reparse a bounded frame without appending to a journal.

    Parameters
    ----------
    kind
        Closed event kind.
    body
        Complete kind-specific fields supplied by the calling owner.
    host_time
        Canonical UTC timestamp supplied by the calling owner.
    previous_head
        Independently retained 32-byte preceding chain head.
    seq
        Positive integer position for the new frame.

    Returns
    -------
    EffectJournalRecordV2
        Exact validated frame data, without a custody or permission grant.

    Raises
    ------
    ValueError, PermissionError
        If the payload is oversized or fails the public frame parser.
    """
    data = {
        "body": body,
        "domain": _DOMAIN,
        "host_time": host_time,
        "kind": kind,
        "previous_head": previous_head.hex(),
        "seq": seq,
    }
    payload = canonical_journal_json_v2(data)
    if not 1 <= len(payload) <= _MAX_PAYLOAD:
        raise ValueError("journal canonical payload exceeds frame bound")
    length = _LENGTH.pack(len(payload))
    frame = length + payload + sha256(previous_head + length + payload).digest()
    return parse_effect_journal_frame_v2(frame, previous_head=previous_head, expected_seq=seq)
