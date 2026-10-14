# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact recovery object schema tests
"""Validate provisional recovery objects before protected storage."""

from __future__ import annotations

import base64
from copy import deepcopy
from hashlib import sha256

import pytest

from rigor_foundry.effect_journal_records_v2 import JOURNAL_MAGIC_V2
from rigor_foundry.models import canonical_digest
from rigor_foundry.permit_anchor_records_v2 import ANCHOR_MAGIC_V24
from rigor_foundry.recovery_evidence_fields_v2 import canonical_object_bytes
from rigor_foundry.recovery_evidence_schema_v2 import (
    exact_recovery_stamp_us_v2,
    validate_anchor_adoption_evidence_v2,
    validate_anchor_final_intent_v2,
    validate_journal_tail_intent_v2,
    validate_recovery_evidence_bytes_v2,
)

_DIGEST = "a" * 64
_TIME = "2026-09-23T03:00:00Z"


def _identity(path: str) -> dict[str, object]:
    """Build one exact decimal-string file identity for a test object."""
    return {
        "path": path,
        "path_digest": canonical_digest(path),
        "device": "1",
        "inode": "2",
    }


def _files() -> dict[str, object]:
    """Return the three selected identities shared by each object kind."""
    return {
        "anchor_file": _identity("/srv/rigor/anchor.bin"),
        "ledger_file": _identity("/srv/rigor/ledger.bin"),
        "journal_file": _identity("/srv/rigor/effect.journal"),
    }


def _kind1(raw: bytes = b"x") -> dict[str, object]:
    """Construct a complete root intent for one final anchor tail."""
    offset = len(ANCHOR_MAGIC_V24) + 200
    return {
        **_files(),
        "domain": "rigor.permit-anchor-final-recovery.v2.4",
        "prior_anchor_head": _DIGEST,
        "prior_anchor_record_count": 1,
        "prior_ledger_record_count": 0,
        "prior_ledger_head": _DIGEST,
        "prior_journal_head": _DIGEST,
        "tail_offset": offset,
        "tail_length": len(raw),
        "captured_file_size": offset + len(raw),
        "removed_bytes_b64": base64.b64encode(raw).decode("ascii"),
        "removed_digest": sha256(raw).hexdigest(),
        "failure_class": "partial-tail" if len(raw) < 200 else "complete-invalid-final",
        "operator_identity": "operator-1",
        "credential_proof_ref": _DIGEST,
        "recovery_code_digest": _DIGEST,
        "host_time": _TIME,
        "parent_intent_digest": None,
    }


def _kind2() -> dict[str, object]:
    """Construct one two-record complete ledger suffix adoption object."""
    return {
        **_files(),
        "domain": "rigor.permit-anchor-recovery.v2.4",
        "old_anchor_head": _DIGEST,
        "old_ledger_record_count": 0,
        "new_ledger_record_count": 2,
        "old_ledger_head": _DIGEST,
        "new_ledger_head": _DIGEST,
        "old_journal_head": _DIGEST,
        "new_journal_head": _DIGEST,
        "adopted_ledger_record_digests": [_DIGEST, "b" * 64],
        "included_journal_record_digests": [],
        "consumed_uuids_digest": _DIGEST,
        "recovery_code_digest": _DIGEST,
        "host_time": _TIME,
    }


def _journal(raw: bytes = b"\x00\x00\x00\x01") -> dict[str, object]:
    """Construct one final partial journal-frame recovery intent."""
    offset = len(JOURNAL_MAGIC_V2)
    return {
        **_files(),
        "domain": "rigor.effect-journal-tail-recovery.v2.1",
        "selected_anchor_head": _DIGEST,
        "selected_journal_head": _DIGEST,
        "last_complete_journal_head": _DIGEST,
        "old_size": offset + len(raw),
        "frame_offset": offset,
        "declared_payload_length": int.from_bytes(raw[:4], "big") if len(raw) >= 4 else None,
        "removed_length": len(raw),
        "removed_bytes_b64": base64.b64encode(raw).decode("ascii"),
        "removed_digest": sha256(raw).hexdigest(),
        "failure_class": "partial",
        "operator_identity": "operator-1",
        "credential_proof_ref": _DIGEST,
        "recovery_code_digest": _DIGEST,
        "host_time": _TIME,
        "parent_intent_digest": None,
    }


@pytest.mark.parametrize(
    ("builder", "domain"),
    [
        (_kind1, "rigor.permit-anchor-final-recovery.v2.4"),
        (_kind2, "rigor.permit-anchor-recovery.v2.4"),
        (_journal, "rigor.effect-journal-tail-recovery.v2.1"),
    ],
)
def test_exact_canonical_roundtrip(builder: object, domain: str) -> None:
    """Every closed object has one exact UTF-8 byte representation."""
    assert callable(builder)
    value = builder()
    if domain.endswith("final-recovery.v2.4"):
        data = validate_anchor_final_intent_v2(value)
    elif domain.endswith("recovery.v2.4"):
        data = validate_anchor_adoption_evidence_v2(value)
    else:
        data = validate_journal_tail_intent_v2(value)
    assert validate_recovery_evidence_bytes_v2(data) == domain
    assert data.startswith(b'{"')
    with pytest.raises(ValueError, match="canonical"):
        validate_recovery_evidence_bytes_v2(b" " + data)
    with pytest.raises(ValueError):
        validate_recovery_evidence_bytes_v2(data.replace(b'"domain"', b'"domain":"x","domain"', 1))


def test_kind1_partial_complete_and_child_fields() -> None:
    """Lengths 1, 199 and 200 bind exact bytes without changing root schema."""
    for raw in (b"x", b"x" * 199, b"x" * 200):
        value = _kind1(raw)
        assert validate_anchor_final_intent_v2(value)
        child = deepcopy(value)
        child["parent_intent_digest"] = _DIGEST
        assert validate_anchor_final_intent_v2(child)
    wrong = _kind1(b"x" * 200)
    wrong["failure_class"] = "partial-tail"
    with pytest.raises(ValueError, match="partial tail"):
        validate_anchor_final_intent_v2(wrong)
    wrong = _kind1(b"x")
    wrong["failure_class"] = "complete-invalid-final"
    with pytest.raises(ValueError, match="incomplete"):
        validate_anchor_final_intent_v2(wrong)


def test_kind1_wrong_size_offset_digest_and_base64_refuse() -> None:
    """The captured bytes cannot be relabelled by another offset or digest."""
    for field, value in (
        ("tail_offset", 0),
        ("captured_file_size", 900),
        ("removed_digest", _DIGEST),
        ("removed_bytes_b64", "eA"),
        ("failure_class", "unknown"),
        ("parent_intent_digest", "bad"),
    ):
        item = _kind1()
        item[field] = value
        with pytest.raises(ValueError):
            validate_anchor_final_intent_v2(item)


def test_kind2_suffix_arrays_and_counts_are_exact() -> None:
    """Every adopted record needs an ordered digest, including recovery records."""
    assert validate_anchor_adoption_evidence_v2(_kind2())
    for field, value in (
        ("new_ledger_record_count", 0),
        ("adopted_ledger_record_digests", [_DIGEST]),
        ("adopted_ledger_record_digests", "bad"),
        ("included_journal_record_digests", ["bad"]),
        ("consumed_uuids_digest", "bad"),
    ):
        item = _kind2()
        item[field] = value
        with pytest.raises(ValueError):
            validate_anchor_adoption_evidence_v2(item)


def test_journal_partial_and_complete_frame_boundaries() -> None:
    """Only a sole exact final frame can carry bad-head or noncanonical class."""
    assert validate_journal_tail_intent_v2(_journal(b"x"))
    complete = _journal(b"\x00\x00\x00\x01" + b"{" + bytes(32))
    complete["failure_class"] = "noncanonical"
    assert validate_journal_tail_intent_v2(complete)
    complete["failure_class"] = "bad-head"
    assert validate_journal_tail_intent_v2(complete)
    for field, value in (
        ("old_size", 0),
        ("frame_offset", 0),
        ("declared_payload_length", None),
        ("declared_payload_length", 2),
        ("failure_class", "bad-head"),
    ):
        item = _journal()
        item[field] = value
        with pytest.raises(ValueError):
            validate_journal_tail_intent_v2(item)
    item = _journal(b"x")
    item["declared_payload_length"] = 1
    with pytest.raises(ValueError, match="short length"):
        validate_journal_tail_intent_v2(item)


def test_closed_keys_file_identity_and_canonical_utc_refuse_aliases() -> None:
    """A file path, proof digest, or time spelling cannot be normalised silently."""
    for field, value in (
        ("host_time", "2026-09-23T03:00:00+00:00"),
        ("host_time", "2026-09-23T03:00:00.001Z"),
        ("host_time", "2026-09-23T03:00:00.000000Z"),
        ("credential_proof_ref", "bad"),
        ("operator_identity", "bad name"),
    ):
        item = _kind1()
        item[field] = value
        with pytest.raises(ValueError):
            validate_anchor_final_intent_v2(item)
    item = _kind1()
    item["extra"] = 1
    with pytest.raises(ValueError, match="fields differ"):
        validate_anchor_final_intent_v2(item)
    item = _kind1()
    anchor_file = item["anchor_file"]
    assert isinstance(anchor_file, dict)
    anchor_file["path"] = "relative.bin"
    with pytest.raises(ValueError, match="absolute"):
        validate_anchor_final_intent_v2(item)


def test_exact_recovery_stamp_vectors() -> None:
    """Binary stamp uses exact microseconds and rejects normalised aliases."""
    seconds = exact_recovery_stamp_us_v2("2026-09-23T03:00:00Z")
    assert exact_recovery_stamp_us_v2("2026-09-23T03:00:00.000001Z") == seconds + 1
    with pytest.raises(ValueError, match="canonical UTC"):
        exact_recovery_stamp_us_v2("2026-09-23T03:00:00.001Z")


def test_file_identity_refuses_aliases_and_unbound_identity_fields() -> None:
    """Path digest and decimal descriptor identity must survive exact replay."""
    for field, replacement in (
        ("path", "/srv/rigor/../anchor.bin"),
        ("path", "/srv//rigor/anchor.bin"),
        ("path", "/srv/rigor/anchor.bin/"),
        ("path", "/srv/rigor/other.bin"),
        ("path_digest", _DIGEST),
        ("device", "01"),
        ("device", 1),
        ("inode", "0"),
        ("inode", "-2"),
    ):
        item = _kind1()
        file_identity = item["anchor_file"]
        assert isinstance(file_identity, dict)
        file_identity[field] = replacement
        with pytest.raises(ValueError):
            validate_anchor_final_intent_v2(item)


def test_recovery_evidence_rejects_invalid_json_or_unknown_domain() -> None:
    """A digest-named artifact cannot smuggle an alternate JSON encoding."""
    data = validate_anchor_final_intent_v2(_kind1())
    for malformed in (b"[]", b"{", data + b"\n", b"{}", b'"x"'):
        with pytest.raises(ValueError):
            validate_recovery_evidence_bytes_v2(malformed)
    item = _kind1()
    item["domain"] = "unknown"
    with pytest.raises(ValueError, match="unknown"):
        validate_recovery_evidence_bytes_v2(canonical_object_bytes(item))


def test_kind2_rejects_unknown_fields_and_invalid_host_time() -> None:
    """An adoption proof is closed even when it has no operator principal."""
    item = _kind2()
    item["operator_identity"] = "operator-1"
    with pytest.raises(ValueError, match="fields differ"):
        validate_anchor_adoption_evidence_v2(item)
    item = _kind2()
    item["host_time"] = "2026-09-23T03:00:00.000000Z"
    with pytest.raises(ValueError, match="canonical UTC"):
        validate_anchor_adoption_evidence_v2(item)


def test_journal_refuses_ambiguous_or_extra_terminal_bytes() -> None:
    """Only the final damaged frame, without trailing bytes, is recoverable."""
    for raw in (b"\x00\x00\x00\x00", b"\x00\x01\x00\x01"):
        with pytest.raises(ValueError):
            validate_journal_tail_intent_v2(_journal(raw))
    complete = b"\x00\x00\x00\x01" + b"{" + bytes(32)
    item = _journal(complete)
    with pytest.raises(ValueError, match="partial frame is complete"):
        validate_journal_tail_intent_v2(item)
    item["failure_class"] = "bad-head"
    item["removed_length"] = len(complete) + 1
    with pytest.raises(ValueError):
        validate_journal_tail_intent_v2(item)
    item = _journal(complete + b"x")
    item["failure_class"] = "noncanonical"
    with pytest.raises(ValueError, match="invalid final frame length"):
        validate_journal_tail_intent_v2(item)
    item = _journal(b"\x00\x00\x00\x01")
    item["failure_class"] = "unknown"
    with pytest.raises(ValueError, match="failure class differs"):
        validate_journal_tail_intent_v2(item)


def test_exact_domain_and_capture_boundaries() -> None:
    """A structurally valid object cannot be reclassified or shifted in place."""
    for builder, validator in (
        (_kind1, validate_anchor_final_intent_v2),
        (_kind2, validate_anchor_adoption_evidence_v2),
        (_journal, validate_journal_tail_intent_v2),
    ):
        item = builder()
        item["domain"] = "wrong"
        with pytest.raises(ValueError, match="domain differs"):
            validator(item)
    item = _kind1()
    assert isinstance(item["tail_offset"], int)
    item["tail_offset"] += 1
    with pytest.raises(ValueError, match="tail offset differs"):
        validate_anchor_final_intent_v2(item)
    item = _journal()
    assert isinstance(item["old_size"], int)
    item["old_size"] += 1
    with pytest.raises(ValueError, match="captured size differs"):
        validate_journal_tail_intent_v2(item)


def test_removed_bytes_refuse_invalid_ascii_and_empty_payload() -> None:
    """The removed-byte commitment cannot encode an empty or non-ASCII tail."""
    for encoded in (3, "é", "", "@@=="):
        item = _kind1()
        item["removed_bytes_b64"] = encoded
        with pytest.raises(ValueError):
            validate_anchor_final_intent_v2(item)
