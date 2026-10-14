# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — final anchor recovery intent chain tests
"""Check immutable last-to-root commitments and torn kind-1 child prefixes."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path

import pytest

from rigor_foundry._permit_ledger_records_v2 import _INITIAL_HEAD
from rigor_foundry.effect_journal_records_v2 import JOURNAL_GENESIS_V2
from rigor_foundry.effect_journal_v2 import EffectJournalFileIdentityV2, EffectJournalSnapshotV2
from rigor_foundry.models import canonical_digest
from rigor_foundry.permit_anchor_records_v2 import (
    ANCHOR_MAGIC_V24,
    ANCHOR_RECORD_V24,
    AnchorRecordV24,
    AnchorSelectionV24,
)
from rigor_foundry.permit_consumption_ledger_v2 import LedgerFileIdentityV2, LedgerSnapshotV2
from rigor_foundry.recovery_anchor_intent_chain_v2 import (
    pending_anchor_intents_v24,
    verify_anchor_intent_chain_v24,
)
from rigor_foundry.recovery_evidence_schema_v2 import (
    exact_recovery_stamp_us_v2,
    validate_anchor_final_intent_v2,
)

_TIME = "2026-09-23T03:00:00Z"
_LATER = "2026-09-23T03:00:00.000001Z"


def _identity(path: Path) -> dict[str, object]:
    """Select the exact opened path, device and inode of one fixture file."""
    entry = path.stat()
    return {
        "path": str(path),
        "path_digest": canonical_digest(str(path)),
        "device": str(entry.st_dev),
        "inode": str(entry.st_ino),
    }


def _intent(
    files: Mapping[str, object],
    prior: AnchorSelectionV24,
    *,
    raw: bytes,
    parent: str | None,
    time: str,
) -> bytes:
    """Encode one exact root or torn-child intent at the same anchor offset."""
    offset = len(ANCHOR_MAGIC_V24) + ANCHOR_RECORD_V24.size
    return validate_anchor_final_intent_v2(
        {
            **files,
            "domain": "rigor.permit-anchor-final-recovery.v2.4",
            "prior_anchor_head": prior.anchor_head.hex(),
            "prior_anchor_record_count": 1,
            "prior_ledger_record_count": prior.ledger_record_count,
            "prior_ledger_head": prior.ledger_head.hex(),
            "prior_journal_head": prior.journal_head.hex(),
            "tail_offset": offset,
            "tail_length": len(raw),
            "captured_file_size": offset + len(raw),
            "removed_bytes_b64": base64.b64encode(raw).decode("ascii"),
            "removed_digest": sha256(raw).hexdigest(),
            "failure_class": "partial-tail" if len(raw) < 200 else "complete-invalid-final",
            "operator_identity": "operator-1",
            "credential_proof_ref": "a" * 64,
            "recovery_code_digest": "a" * 64,
            "host_time": time,
            "parent_intent_digest": parent,
        }
    )


@dataclass(frozen=True)
class _Case:
    """One selected prefix and exact evidence directory snapshot."""

    objects: dict[str, bytes]
    record: AnchorRecordV24
    prior: AnchorSelectionV24
    anchor: Path
    ledger_path: Path
    ledger: LedgerSnapshotV2
    journal_path: Path
    journal: EffectJournalSnapshotV2

    def verify(self) -> frozenset[str]:
        """Exercise the production root/child verifier with real identities."""
        return verify_anchor_intent_chain_v24(
            self.objects,
            record=self.record,
            previous=self.prior,
            prior_anchor_record_count=1,
            anchor_path=self.anchor,
            anchor_stat=self.anchor.stat(),
            ledger_path=self.ledger_path,
            ledger=self.ledger,
            journal_path=self.journal_path,
            journal=self.journal,
        )


def _case(tmp_path: Path) -> _Case:
    """Construct a one-link root commitment after a valid initial anchor."""
    anchor = tmp_path / "anchor.bin"
    ledger_path = tmp_path / "ledger.bin"
    journal_path = tmp_path / "journal.bin"
    for path in (anchor, ledger_path, journal_path):
        path.write_bytes(b"selected")
    ledger_stat = ledger_path.stat()
    journal_stat = journal_path.stat()
    ledger_identity = LedgerFileIdentityV2(
        canonical_digest(str(ledger_path)), ledger_stat.st_dev, ledger_stat.st_ino
    )
    journal_identity = EffectJournalFileIdentityV2(
        canonical_digest(str(journal_path)), journal_stat.st_dev, journal_stat.st_ino
    )
    prior = AnchorSelectionV24(
        0, _INITIAL_HEAD, ledger_identity, JOURNAL_GENESIS_V2, bytes.fromhex("b" * 64)
    )
    ledger = LedgerSnapshotV2(0, _INITIAL_HEAD.hex(), ledger_identity, ())
    journal = EffectJournalSnapshotV2(
        journal_identity, (), JOURNAL_GENESIS_V2.hex(), JOURNAL_GENESIS_V2.hex(), 0
    )
    files = {
        "anchor_file": _identity(anchor),
        "ledger_file": _identity(ledger_path),
        "journal_file": _identity(journal_path),
    }
    root = _intent(files, prior, raw=b"x", parent=None, time=_TIME)
    digest = sha256(root).hexdigest()
    record = AnchorRecordV24(
        1,
        0,
        sha256(b"x").digest(),
        ledger_identity,
        exact_recovery_stamp_us_v2(_TIME),
        1,
        JOURNAL_GENESIS_V2,
        bytes.fromhex(digest),
        prior.anchor_head,
        b"h" * 32,
        b"",
    )
    return _Case({digest: root}, record, prior, anchor, ledger_path, ledger, journal_path, journal)


def _child(case: _Case, *, captured: bytes | None = None, time: str = _LATER) -> _Case:
    """Add a child intent capturing the exact torn append of its parent kind-1."""
    root_digest, root = next(iter(case.objects.items()))
    files = {
        "anchor_file": _identity(case.anchor),
        "ledger_file": _identity(case.ledger_path),
        "journal_file": _identity(case.journal_path),
    }
    attempted = ANCHOR_RECORD_V24.pack(
        1,
        0,
        sha256(b"x").digest(),
        bytes.fromhex(case.ledger.identity.path_digest),
        case.ledger.identity.device,
        case.ledger.identity.inode,
        exact_recovery_stamp_us_v2(_TIME),
        1,
        JOURNAL_GENESIS_V2,
        bytes.fromhex(root_digest),
        case.prior.anchor_head,
    )
    raw = attempted[:99] if captured is None else captured
    child = _intent(files, case.prior, raw=raw, parent=root_digest, time=time)
    child_digest = sha256(child).hexdigest()
    record = replace(
        case.record,
        event_digest=bytes.fromhex(child_digest),
        stamp_us=exact_recovery_stamp_us_v2(time),
    )
    return replace(case, objects={root_digest: root, child_digest: child}, record=record)


def test_root_and_child_resolve_exactly(tmp_path: Path) -> None:
    """Last intent names the child while root alone commits removed bytes."""
    root = _case(tmp_path)
    assert root.verify() == frozenset(root.objects)
    child = _child(root)
    assert child.verify() == frozenset(child.objects)


def test_missing_branch_and_wrong_prefix_refuse(tmp_path: Path) -> None:
    """A complete anchor cannot resolve a missing or competing torn append."""
    root = _case(tmp_path)
    child = _child(root)
    with pytest.raises(PermissionError, match="missing"):
        replace(child, objects=root.objects).verify()
    bad = _child(root, captured=b"y")
    with pytest.raises(PermissionError, match="torn kind-1"):
        bad.verify()
    competitor = _child(root, time="2026-09-23T03:00:00.000002Z")
    objects = {**child.objects, **competitor.objects}
    with pytest.raises(PermissionError, match="branch"):
        replace(child, objects=objects).verify()


def test_root_commitment_and_descriptor_boundary_refuse(tmp_path: Path) -> None:
    """Wrong metadata, stamp, anchor head or file identity cannot be reinterpreted."""
    case = _case(tmp_path)
    with pytest.raises(PermissionError, match="commitment"):
        replace(case, record=replace(case.record, metadata=2)).verify()
    with pytest.raises(PermissionError, match="commitment"):
        replace(case, record=replace(case.record, stamp_us=case.record.stamp_us + 1)).verify()
    with pytest.raises(PermissionError, match="selected prefix"):
        replace(case, record=replace(case.record, previous_head=bytes(32))).verify()
    with pytest.raises(PermissionError, match="last intent is missing"):
        replace(case, journal_path=tmp_path / "other.journal").verify()


def test_duplicate_roots_missing_parent_and_wrong_boundary_refuse(tmp_path: Path) -> None:
    """Only one exact connected chain may claim a selected anchor offset."""
    case = _case(tmp_path)
    root_digest, root = next(iter(case.objects.items()))
    files = {
        "anchor_file": _identity(case.anchor),
        "ledger_file": _identity(case.ledger_path),
        "journal_file": _identity(case.journal_path),
    }
    second_root = _intent(files, case.prior, raw=b"z", parent=None, time=_LATER)
    with pytest.raises(PermissionError, match="roots"):
        replace(
            case, objects={**case.objects, sha256(second_root).hexdigest(): second_root}
        ).verify()
    orphan = _intent(files, case.prior, raw=b"y", parent="f" * 64, time=_LATER)
    orphan_digest = sha256(orphan).hexdigest()
    with pytest.raises(PermissionError, match="missing or ambiguous"):
        replace(
            case,
            objects={**case.objects, orphan_digest: orphan},
            record=replace(case.record, event_digest=bytes.fromhex(orphan_digest)),
        ).verify()
    changed = json.loads(root)
    assert isinstance(changed, dict)
    changed["prior_ledger_head"] = "a" * 64
    changed_bytes = validate_anchor_final_intent_v2(changed)
    with pytest.raises(PermissionError, match="selected boundary"):
        replace(
            case,
            objects={sha256(changed_bytes).hexdigest(): changed_bytes},
            record=replace(case.record, event_digest=sha256(changed_bytes).digest()),
        ).verify()
    with pytest.raises(PermissionError, match="filename"):
        replace(case, objects={"f" * 64: root}).verify()
    with pytest.raises(ValueError, match="position"):
        replace(case, record=replace(case.record, kind=0)).verify()
    assert root_digest in case.verify()


def test_unreferenced_selected_intent_remains_pending(tmp_path: Path) -> None:
    """Published root evidence alone never authorises ordinary admission."""
    case = _case(tmp_path)

    def pending(resolved: frozenset[str]) -> frozenset[str]:
        """Use the same selected descriptor triple before and after commitment."""
        return pending_anchor_intents_v24(
            case.objects,
            resolved=resolved,
            anchor_path=case.anchor,
            anchor_stat=case.anchor.stat(),
            ledger_path=case.ledger_path,
            ledger=case.ledger,
            journal_path=case.journal_path,
            journal=case.journal,
        )

    assert pending(frozenset()) == frozenset(case.objects)
    assert pending(case.verify()) == frozenset()
