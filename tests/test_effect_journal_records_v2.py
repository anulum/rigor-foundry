# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected effect-journal record-wire tests
"""Exercise canonical, chained journal frames through their public wire API."""

from __future__ import annotations

import json
import struct
from copy import deepcopy
from hashlib import sha256
from typing import Any

import pytest

from rigor_foundry.effect_journal_records_v2 import (
    JOURNAL_GENESIS_V2,
    build_effect_journal_frame_v2,
    canonical_journal_json_v2,
    parse_effect_journal_frame_v2,
)

_PERMIT_ID = "123e4567-e89b-12d3-a456-426614174000"
_DIGEST = "a" * 64
_HOST_TIME = "2026-09-23T03:00:00Z"


def _intent(target_ref: dict[str, str] | None = None) -> dict[str, Any]:
    """Return one registry-derived operation intent for public frame tests."""
    return {
        "permit_id": _PERMIT_ID,
        "permit_digest": _DIGEST,
        "ledger_head": _DIGEST,
        "effect_target_digest": _DIGEST,
        "decision_digest": _DIGEST,
        "grant_snapshot_digest": _DIGEST,
        "adapter_operations_digest": _DIGEST,
        "operation_key": "write-artifact",
        "cgroup_id": "42",
        "atomicity": "atomic",
        "parts": [
            {
                "index": 0,
                "effect_class": "local-file-write",
                "target_ref": target_ref or {"form": "path", "value": "/srv/rigor/output"},
                "route_digest": _DIGEST,
                "operation_variant": "default",
            }
        ],
    }


def test_chained_frames_bind_operation_and_part_intent() -> None:
    """A second real frame must name the first exact record head and sequence."""
    first = build_effect_journal_frame_v2(
        kind="operation-intent",
        body=_intent(),
        host_time=_HOST_TIME,
        previous_head=JOURNAL_GENESIS_V2,
        seq=1,
    )
    second = build_effect_journal_frame_v2(
        kind="effect-intent",
        body={"permit_id": _PERMIT_ID, "part_index": 0, "pre_state_digest": None},
        host_time=_HOST_TIME,
        previous_head=bytes.fromhex(first.record_head),
        seq=2,
    )
    assert first.record_digest == sha256(first.frame).hexdigest()
    assert second.previous_head == first.record_head
    assert (
        parse_effect_journal_frame_v2(
            second.frame, previous_head=bytes.fromhex(first.record_head), expected_seq=2
        )
        == second
    )
    with pytest.raises(PermissionError, match="previous head"):
        parse_effect_journal_frame_v2(
            second.frame, previous_head=JOURNAL_GENESIS_V2, expected_seq=2
        )


@pytest.mark.parametrize(
    "target_ref",
    [
        {"form": "path", "value": "relative"},
        {"form": "path", "value": "/srv/../secret"},
        {"form": "remote", "value": "https://user:secret@example.test/object"},
        {"form": "remote", "value": "https://user%40example.test/object"},
        {"form": "remote", "value": "https://example.test/object#fragment"},
        {"form": "endpoint", "value": "service:Bad Resource"},
        {"form": "record", "value": "00000000-0000-0000-0000-000000000000"},
        {"form": "unknown", "value": "anything"},
    ],
)
def test_unsafe_or_unknown_targets_refuse_before_frame_creation(
    target_ref: dict[str, str],
) -> None:
    """The public builder refuses malformed targets before a frame can be appended."""
    with pytest.raises(ValueError):
        build_effect_journal_frame_v2(
            kind="operation-intent",
            body=_intent(target_ref),
            host_time=_HOST_TIME,
            previous_head=JOURNAL_GENESIS_V2,
            seq=1,
        )


def test_noncanonical_payload_refuses_even_with_recomputed_head() -> None:
    """Whitespace cannot become a second valid byte representation of one record."""
    valid = build_effect_journal_frame_v2(
        kind="effect-intent",
        body={"permit_id": _PERMIT_ID, "part_index": 0, "pre_state_digest": None},
        host_time=_HOST_TIME,
        previous_head=JOURNAL_GENESIS_V2,
        seq=1,
    )
    size = struct.unpack(">I", valid.frame[:4])[0]
    data = json.loads(valid.frame[4 : 4 + size])
    payload = json.dumps(data, sort_keys=True, indent=1).encode()
    prefix = struct.pack(">I", len(payload)) + payload
    forged = prefix + sha256(JOURNAL_GENESIS_V2 + prefix).digest()
    with pytest.raises(PermissionError, match="not canonical"):
        parse_effect_journal_frame_v2(forged, previous_head=JOURNAL_GENESIS_V2, expected_seq=1)


def test_stored_record_head_and_canonical_time_refuse() -> None:
    """A changed head or alternate UTC spelling cannot verify as the selected frame."""
    valid = build_effect_journal_frame_v2(
        kind="effect-intent",
        body={"permit_id": _PERMIT_ID, "part_index": 0, "pre_state_digest": None},
        host_time=_HOST_TIME,
        previous_head=JOURNAL_GENESIS_V2,
        seq=1,
    )
    altered = valid.frame[:-1] + bytes([valid.frame[-1] ^ 1])
    with pytest.raises(PermissionError, match="record head"):
        parse_effect_journal_frame_v2(altered, previous_head=JOURNAL_GENESIS_V2, expected_seq=1)
    with pytest.raises(PermissionError, match="canonical UTC"):
        build_effect_journal_frame_v2(
            kind="effect-intent",
            body={"permit_id": _PERMIT_ID, "part_index": 0, "pre_state_digest": None},
            host_time="2026-09-23T03:00:00+00:00",
            previous_head=JOURNAL_GENESIS_V2,
            seq=1,
        )


@pytest.mark.parametrize(
    ("kind", "body"),
    [
        (
            "effect-complete",
            {"permit_id": _PERMIT_ID, "part_index": 0, "post_state_digest": _DIGEST},
        ),
        (
            "effect-failed",
            {
                "permit_id": _PERMIT_ID,
                "part_index": 0,
                "post_state_digest": None,
                "failure_code": "adapter-error",
            },
        ),
        ("operation-complete", {"permit_id": _PERMIT_ID, "parts_result_digest": _DIGEST}),
        (
            "operation-rolled-back",
            {"permit_id": _PERMIT_ID, "rollback_evidence_digest": _DIGEST},
        ),
        (
            "operation-reconciled",
            {
                "permit_id": _PERMIT_ID,
                "reconciliation_evidence_digest": _DIGEST,
                "operator_identity": "operator-1",
                "state_digest": _DIGEST,
            },
        ),
        (
            "operation-partial",
            {
                "permit_id": _PERMIT_ID,
                "parts_applied": [0],
                "blocked_targets": [{"form": "path", "value": "/srv/rigor/output"}],
                "evidence_digest": _DIGEST,
            },
        ),
        (
            "target-reconciled",
            {
                "permit_id": _PERMIT_ID,
                "target_ref": {"form": "path", "value": "/srv/rigor/output"},
                "outcome": "pre-state-restored",
                "state_digest": _DIGEST,
                "reconciliation_evidence_digest": _DIGEST,
                "operator_identity": "RIGOR-FOUNDRY/operator-1",
                "operator_policy_digest": _DIGEST,
                "operator_signature": "a" * 128,
            },
        ),
        (
            "trust-policy-activated",
            {
                "policy_digest": _DIGEST,
                "previous_policy_digest": None,
                "activation_evidence_digest": _DIGEST,
                "root_signature": "a" * 128,
            },
        ),
        (
            "key-revoked",
            {
                "key_fingerprint": _DIGEST,
                "compromised_since_seq": 1,
                "evidence_digest": _DIGEST,
                "root_signature": "a" * 128,
            },
        ),
        (
            "terminated",
            {"permit_id": _PERMIT_ID, "cgroup_id": "42", "status_evidence_digest": _DIGEST},
        ),
        (
            "overrun",
            {"permit_id": _PERMIT_ID, "cgroup_id": "42", "status_evidence_digest": _DIGEST},
        ),
        (
            "unkillable",
            {"permit_id": _PERMIT_ID, "cgroup_id": "42", "status_evidence_digest": _DIGEST},
        ),
        (
            "adopted-after-restart",
            {"permit_id": _PERMIT_ID, "cgroup_id": "42", "status_evidence_digest": _DIGEST},
        ),
        (
            "ended-unknown",
            {"permit_id": _PERMIT_ID, "cgroup_id": "42", "status_evidence_digest": _DIGEST},
        ),
        (
            "cleared-orphan-leaf",
            {
                "cgroup_id": "42",
                "operator_identity": "operator-1",
                "status_evidence_digest": _DIGEST,
            },
        ),
        (
            "removed-empty-leaf",
            {
                "cgroup_id": "42",
                "operator_identity": "supervisor",
                "status_evidence_digest": _DIGEST,
            },
        ),
        (
            "journal-tail-recovery",
            {
                "recovery_intent_digest": _DIGEST,
                "removed_digest": _DIGEST,
                "removed_length": 5,
                "operator_identity": "operator-1",
            },
        ),
    ],
)
def test_closed_event_kinds_have_verifiable_frames(kind: str, body: dict[str, object]) -> None:
    """Every defined event can be encoded and read without schema aliases."""
    record = build_effect_journal_frame_v2(
        kind=kind, body=body, host_time=_HOST_TIME, previous_head=JOURNAL_GENESIS_V2, seq=1
    )
    assert record.kind == kind
    assert record.body == body
    assert record.record_digest == sha256(record.frame).hexdigest()


@pytest.mark.parametrize(
    "target_ref",
    [
        {"form": "path", "value": "/"},
        {"form": "remote", "value": "https://example.test/path?public=1"},
        {"form": "endpoint", "value": "service:resource"},
        {"form": "project", "value": "RIGOR-FOUNDRY"},
        {"form": "record", "value": _PERMIT_ID},
    ],
)
def test_closed_target_forms_remain_exact_bytes(target_ref: dict[str, str]) -> None:
    """Accepted target forms retain their exact extractor string in the frame."""
    record = build_effect_journal_frame_v2(
        kind="operation-intent",
        body=_intent(target_ref),
        host_time=_HOST_TIME,
        previous_head=JOURNAL_GENESIS_V2,
        seq=1,
    )
    assert record.body["parts"] == _intent(target_ref)["parts"]


@pytest.mark.parametrize(
    "value",
    [
        2**53,
        -(2**53),
        1.5,
        {"Upper": 1},
        {"bad-key": 1},
        {1: "numeric key"},
        "\ud800",
        "bad\x01control",
    ],
)
def test_pcs_canon_rejects_out_of_profile_values(value: object) -> None:
    """The journal cannot encode numbers, keys or Unicode outside PCS-CANON-1."""
    with pytest.raises(ValueError):
        canonical_journal_json_v2(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("permit_id", "not-a-uuid"),
        ("permit_id", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
        ("permit_digest", "A" * 64),
        ("cgroup_id", "0"),
        ("cgroup_id", "042"),
        ("cgroup_id", "٤٢"),
        ("operation_key", "bad key"),
        ("atomicity", "best-effort"),
        ("parts", []),
        ("parts", None),
    ],
)
def test_invalid_operation_fields_refuse_before_append(field: str, value: object) -> None:
    """A malformed signed or registry-derived field cannot become an operation intent."""
    body = _intent()
    body[field] = value
    with pytest.raises(ValueError):
        build_effect_journal_frame_v2(
            kind="operation-intent",
            body=body,
            host_time=_HOST_TIME,
            previous_head=JOURNAL_GENESIS_V2,
            seq=1,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("index", 1),
        ("index", True),
        ("effect_class", "other"),
        ("effect_class", {}),
        ("route_digest", "not-a-digest"),
        ("operation_variant", ""),
        ("operation_variant", "Bad_Variant"),
        ("target_ref", {"form": "path", "value": "/valid", "extra": "x"}),
    ],
)
def test_invalid_part_fields_refuse_before_append(field: str, value: object) -> None:
    """A part cannot change index, class, route, variant or target shape."""
    body = deepcopy(_intent())
    parts = body["parts"]
    assert isinstance(parts, list)
    parts[0][field] = value
    with pytest.raises(ValueError):
        build_effect_journal_frame_v2(
            kind="operation-intent",
            body=body,
            host_time=_HOST_TIME,
            previous_head=JOURNAL_GENESIS_V2,
            seq=1,
        )


@pytest.mark.parametrize(
    ("target_ref", "expected"),
    [
        ({"form": "path", "value": "/srv/"}, "path"),
        ({"form": "path", "value": "/srv//file"}, "path"),
        ({"form": "path", "value": "/srv/."}, "path"),
        ({"form": "path", "value": "/srv/\nfile"}, "path"),
        ({"form": "remote", "value": "http:example.test"}, "remote"),
        ({"form": "remote", "value": "https://"}, "remote"),
        ({"form": "remote", "value": "https://user%40example.test/"}, "remote"),
        ({"form": "remote", "value": "https://example.test/#frag"}, "remote"),
        ({"form": "remote", "value": "https://example.test/a b"}, "remote"),
        ({"form": "endpoint", "value": "missingcolon"}, "endpoint"),
        ({"form": "endpoint", "value": "service:Bad"}, "endpoint"),
        ({"form": "endpoint", "value": "service:"}, "endpoint"),
        ({"form": "project", "value": "bad project"}, "project"),
        ({"form": "record", "value": "not-a-uuid"}, "UUID"),
    ],
)
def test_target_syntax_refuses_before_registry_comparison(
    target_ref: dict[str, str], expected: str
) -> None:
    """Malformed targets fail independently of the protected extractor."""
    with pytest.raises(ValueError, match=expected):
        build_effect_journal_frame_v2(
            kind="operation-intent",
            body=_intent(target_ref),
            host_time=_HOST_TIME,
            previous_head=JOURNAL_GENESIS_V2,
            seq=1,
        )


def _reframe(payload: bytes) -> bytes:
    """Build a full frame with a correct head for adversarial parser inputs."""
    prefix = struct.pack(">I", len(payload)) + payload
    return prefix + sha256(JOURNAL_GENESIS_V2 + prefix).digest()


@pytest.mark.parametrize("depth", [1, 100, 1100])
def test_bounded_nested_frame_uses_documented_refusal(depth: int) -> None:
    """Correct framing cannot let an invalid nested digest escape as recursion failure."""
    valid = build_effect_journal_frame_v2(
        kind="effect-intent",
        body={"permit_id": _PERMIT_ID, "part_index": 0, "pre_state_digest": None},
        host_time=_HOST_TIME,
        previous_head=JOURNAL_GENESIS_V2,
        seq=1,
    )
    nested = b"[" * depth + b"0" + b"]" * depth
    payload = valid.frame[4:-32].replace(
        b'"pre_state_digest":null', b'"pre_state_digest":' + nested
    )
    assert len(payload) < 65536
    with pytest.raises((ValueError, PermissionError)):
        parse_effect_journal_frame_v2(
            _reframe(payload), previous_head=JOURNAL_GENESIS_V2, expected_seq=1
        )


def test_canonical_json_refuses_excessive_nesting_as_value_error() -> None:
    """A deep caller-owned value has the same invalid-value boundary as other input."""
    value: object = 0
    for _ in range(1100):
        value = [value]
    with pytest.raises(ValueError, match="nesting"):
        canonical_journal_json_v2(value)


def test_frame_builder_refuses_excessive_nesting_as_value_error() -> None:
    """An invalid nested body cannot bypass the builder's documented rejection types."""
    value: object = 0
    for _ in range(1100):
        value = {"nested": value}
    with pytest.raises(ValueError, match="nesting"):
        build_effect_journal_frame_v2(
            kind="effect-intent",
            body={"permit_id": _PERMIT_ID, "part_index": 0, "pre_state_digest": value},
            host_time=_HOST_TIME,
            previous_head=JOURNAL_GENESIS_V2,
            seq=1,
        )


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b'{"a":1,"a":2}', "JSON is invalid"),
        (b'{"a":1.5}', "JSON is invalid"),
        (b'{"a":NaN}', "JSON is invalid"),
        (b'{"a":"\\ud800"}', "JSON is invalid"),
        (b"\xff", "JSON is invalid"),
    ],
)
def test_strict_json_refuses_ambiguous_or_invalid_bytes(payload: bytes, expected: str) -> None:
    """A recomputed head cannot legalize duplicate keys, floats or invalid UTF-8."""
    with pytest.raises(PermissionError, match=expected):
        parse_effect_journal_frame_v2(
            _reframe(payload), previous_head=JOURNAL_GENESIS_V2, expected_seq=1
        )


def test_frame_boundaries_and_closed_outer_fields_refuse() -> None:
    """A frame needs exact framing, domain, sequence, head and outer keys."""
    body = {"permit_id": _PERMIT_ID, "part_index": 0, "pre_state_digest": None}
    valid = build_effect_journal_frame_v2(
        kind="effect-intent",
        body=body,
        host_time=_HOST_TIME,
        previous_head=JOURNAL_GENESIS_V2,
        seq=1,
    )
    for frame in (b"", b"\x00" * 36):
        with pytest.raises(PermissionError, match="incomplete"):
            parse_effect_journal_frame_v2(frame, previous_head=JOURNAL_GENESIS_V2, expected_seq=1)
    for frame in (b"\x00\x00\x00\x00" + valid.frame[4:], valid.frame + b"x"):
        with pytest.raises(PermissionError, match="length"):
            parse_effect_journal_frame_v2(frame, previous_head=JOURNAL_GENESIS_V2, expected_seq=1)
    with pytest.raises(ValueError, match="scan position"):
        parse_effect_journal_frame_v2(valid.frame, previous_head=b"short", expected_seq=1)
    with pytest.raises(ValueError, match="scan position"):
        parse_effect_journal_frame_v2(
            valid.frame, previous_head=JOURNAL_GENESIS_V2, expected_seq=0
        )
    decoded = json.loads(valid.frame[4:-32])
    for field, replacement in (
        ("domain", "wrong-domain"),
        ("seq", 2),
        ("seq", True),
        ("previous_head", "b" * 64),
        ("kind", "unknown"),
    ):
        changed = dict(decoded)
        changed[field] = replacement
        with pytest.raises((PermissionError, ValueError)):
            parse_effect_journal_frame_v2(
                _reframe(canonical_journal_json_v2(changed)),
                previous_head=JOURNAL_GENESIS_V2,
                expected_seq=1,
            )
    changed = dict(decoded)
    changed["extra"] = True
    with pytest.raises(ValueError, match="fields differ"):
        parse_effect_journal_frame_v2(
            _reframe(canonical_journal_json_v2(changed)),
            previous_head=JOURNAL_GENESIS_V2,
            expected_seq=1,
        )


@pytest.mark.parametrize("part_index", [-1, True])
def test_part_index_cannot_be_negative_or_boolean(part_index: object) -> None:
    """A part transition cannot alias a boolean or an absent negative index."""
    with pytest.raises(ValueError, match="part_index"):
        build_effect_journal_frame_v2(
            kind="effect-intent",
            body={"permit_id": _PERMIT_ID, "part_index": part_index, "pre_state_digest": None},
            host_time=_HOST_TIME,
            previous_head=JOURNAL_GENESIS_V2,
            seq=1,
        )


@pytest.mark.parametrize("removed_length", [0, True])
def test_recovery_record_requires_positive_integer_length(removed_length: object) -> None:
    """A recovery audit cannot claim zero bytes or a boolean length."""
    with pytest.raises(ValueError, match="removed_length"):
        build_effect_journal_frame_v2(
            kind="journal-tail-recovery",
            body={
                "recovery_intent_digest": _DIGEST,
                "removed_digest": _DIGEST,
                "removed_length": removed_length,
                "operator_identity": "operator-1",
            },
            host_time=_HOST_TIME,
            previous_head=JOURNAL_GENESIS_V2,
            seq=1,
        )


def test_oversized_operation_frame_refuses_before_append() -> None:
    """One operation cannot force a frame larger than the fixed 64-KiB bound."""
    with pytest.raises(ValueError, match="frame bound"):
        build_effect_journal_frame_v2(
            kind="operation-intent",
            body=_intent({"form": "path", "value": "/" + "a" * 70000}),
            host_time=_HOST_TIME,
            previous_head=JOURNAL_GENESIS_V2,
            seq=1,
        )


@pytest.mark.parametrize(
    ("kind", "body", "reason"),
    [
        (
            "operation-partial",
            {
                "permit_id": _PERMIT_ID,
                "parts_applied": [1, 0],
                "blocked_targets": [],
                "evidence_digest": _DIGEST,
            },
            "parts_applied",
        ),
        (
            "operation-partial",
            {
                "permit_id": _PERMIT_ID,
                "parts_applied": [],
                "blocked_targets": [
                    {"form": "path", "value": "/z"},
                    {"form": "path", "value": "/a"},
                ],
                "evidence_digest": _DIGEST,
            },
            "blocked_targets",
        ),
        (
            "operation-partial",
            {
                "permit_id": _PERMIT_ID,
                "parts_applied": [],
                "blocked_targets": "not-an-array",
                "evidence_digest": _DIGEST,
            },
            "blocked_targets",
        ),
        (
            "target-reconciled",
            {
                "permit_id": _PERMIT_ID,
                "target_ref": {"form": "path", "value": "/x"},
                "outcome": "pre-state-restored",
                "state_digest": _DIGEST,
                "reconciliation_evidence_digest": _DIGEST,
                "operator_identity": "operator-1",
                "operator_policy_digest": _DIGEST,
                "operator_signature": "a" * 128,
            },
            "K7 seat",
        ),
        (
            "target-reconciled",
            {
                "permit_id": _PERMIT_ID,
                "target_ref": {"form": "path", "value": "/x"},
                "outcome": "unknown",
                "state_digest": _DIGEST,
                "reconciliation_evidence_digest": _DIGEST,
                "operator_identity": "RIGOR-FOUNDRY/operator-1",
                "operator_policy_digest": _DIGEST,
                "operator_signature": "a" * 128,
            },
            "outcome",
        ),
        (
            "trust-policy-activated",
            {
                "policy_digest": _DIGEST,
                "previous_policy_digest": "A" * 64,
                "activation_evidence_digest": _DIGEST,
                "root_signature": "a" * 128,
            },
            "previous_policy_digest",
        ),
        (
            "key-revoked",
            {
                "key_fingerprint": _DIGEST,
                "compromised_since_seq": 2,
                "evidence_digest": _DIGEST,
                "root_signature": "a" * 128,
            },
            "record position",
        ),
        (
            "key-revoked",
            {
                "key_fingerprint": _DIGEST,
                "compromised_since_seq": 0,
                "evidence_digest": _DIGEST,
                "root_signature": "a" * 128,
            },
            "positive journal position",
        ),
    ],
)
def test_new_journal_record_shapes_refuse_invalid_values(
    kind: str, body: dict[str, object], reason: str
) -> None:
    """New record kinds reject malformed fields before journal append."""
    with pytest.raises(ValueError, match=reason):
        build_effect_journal_frame_v2(
            kind=kind,
            body=body,
            host_time=_HOST_TIME,
            previous_head=JOURNAL_GENESIS_V2,
            seq=1,
        )
