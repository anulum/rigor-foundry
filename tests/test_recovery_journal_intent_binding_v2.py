# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — journal-tail intent resolution tests
"""Require an anchored matching audit frame for every selected journal intent."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path

import pytest

from rigor_foundry._permit_ledger_records_v2 import _INITIAL_HEAD
from rigor_foundry.effect_journal_records_v2 import (
    JOURNAL_GENESIS_V2,
    JOURNAL_MAGIC_V2,
    build_effect_journal_frame_v2,
)
from rigor_foundry.effect_journal_v2 import EffectJournalFileIdentityV2, EffectJournalSnapshotV2
from rigor_foundry.models import canonical_digest
from rigor_foundry.permit_consumption_ledger_v2 import LedgerFileIdentityV2, LedgerSnapshotV2
from rigor_foundry.recovery_evidence_schema_v2 import validate_journal_tail_intent_v2
from rigor_foundry.recovery_journal_intent_binding_v2 import unresolved_journal_intents_v21

_TIME = "2026-09-23T03:00:00Z"
_ANCHOR_HEAD = "b" * 64


def _identity(path: Path) -> dict[str, object]:
    """Encode one real selected test file identity."""
    entry = path.stat()
    return {
        "path": str(path),
        "path_digest": canonical_digest(str(path)),
        "device": str(entry.st_dev),
        "inode": str(entry.st_ino),
    }


@dataclass(frozen=True)
class _Case:
    """Selected file triple, immutable object directory and verified journal."""

    objects: dict[str, bytes]
    anchor: Path
    ledger_path: Path
    ledger: LedgerSnapshotV2
    journal_path: Path
    journal: EffectJournalSnapshotV2
    selected_head: str
    anchor_heads: frozenset[str]

    def pending(self) -> frozenset[str]:
        """Check all published intents against the selected journal prefix."""
        return unresolved_journal_intents_v21(
            self.objects,
            anchor_heads=self.anchor_heads,
            selected_journal_head=self.selected_head,
            anchor_path=self.anchor,
            anchor_stat=self.anchor.stat(),
            ledger_path=self.ledger_path,
            ledger=self.ledger,
            journal_path=self.journal_path,
            journal=self.journal,
        )


def _case(tmp_path: Path, *, parent: str | None = None, time: str = _TIME) -> _Case:
    """Publish a partial terminal-frame intent for an empty selected journal."""
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
    ledger = LedgerSnapshotV2(0, _INITIAL_HEAD.hex(), ledger_identity, ())
    journal = EffectJournalSnapshotV2(
        journal_identity, (), JOURNAL_GENESIS_V2.hex(), JOURNAL_GENESIS_V2.hex(), 0
    )
    raw = b"x"
    offset = len(JOURNAL_MAGIC_V2)
    data = validate_journal_tail_intent_v2(
        {
            "domain": "rigor.effect-journal-tail-recovery.v2.1",
            "anchor_file": _identity(anchor),
            "ledger_file": _identity(ledger_path),
            "journal_file": _identity(journal_path),
            "selected_anchor_head": _ANCHOR_HEAD,
            "selected_journal_head": JOURNAL_GENESIS_V2.hex(),
            "last_complete_journal_head": JOURNAL_GENESIS_V2.hex(),
            "old_size": offset + 1,
            "frame_offset": offset,
            "declared_payload_length": None,
            "removed_length": 1,
            "removed_bytes_b64": base64.b64encode(raw).decode("ascii"),
            "removed_digest": sha256(raw).hexdigest(),
            "failure_class": "partial",
            "operator_identity": "operator-1",
            "credential_proof_ref": "a" * 64,
            "recovery_code_digest": "a" * 64,
            "host_time": time,
            "parent_intent_digest": parent,
        }
    )
    return _Case(
        {sha256(data).hexdigest(): data},
        anchor,
        ledger_path,
        ledger,
        journal_path,
        journal,
        JOURNAL_GENESIS_V2.hex(),
        frozenset({_ANCHOR_HEAD}),
    )


def _audit(case: _Case, *, removed_digest: str | None = None) -> _Case:
    """Append one real parser-checked recovery frame after an intent."""
    object_digest, data = next(iter(case.objects.items()))
    value = json.loads(data)
    assert isinstance(value, dict)
    frame = build_effect_journal_frame_v2(
        kind="journal-tail-recovery",
        body={
            "recovery_intent_digest": object_digest,
            "removed_digest": removed_digest or value["removed_digest"],
            "removed_length": value["removed_length"],
            "operator_identity": value["operator_identity"],
        },
        host_time=_TIME,
        previous_head=JOURNAL_GENESIS_V2,
        seq=1,
    )
    journal = replace(case.journal, records=(frame,), head_digest=frame.record_head)
    return replace(case, journal=journal, selected_head=frame.record_head)


def _changed(case: _Case, **updates: object) -> _Case:
    """Keep a modified intent schema-valid and named by its new exact digest."""
    data = next(iter(case.objects.values()))
    value = json.loads(data)
    assert isinstance(value, dict)
    value.update(updates)
    changed = validate_journal_tail_intent_v2(value)
    return replace(case, objects={sha256(changed).hexdigest(): changed})


def test_pending_until_exact_recovery_frame_is_anchored(tmp_path: Path) -> None:
    """A complete but unanchored audit frame does not resolve the object."""
    case = _case(tmp_path)
    assert case.pending() == frozenset(case.objects)
    audited = _audit(case)
    assert replace(audited, selected_head=JOURNAL_GENESIS_V2.hex()).pending() == frozenset(
        case.objects
    )
    assert audited.pending() == frozenset()


def test_wrong_audit_or_anchor_boundary_refuses(tmp_path: Path) -> None:
    """An anchored frame must match the immutable object and its old anchor."""
    case = _case(tmp_path)
    with pytest.raises(PermissionError, match="audit frame differs"):
        _audit(case, removed_digest="c" * 64).pending()
    with pytest.raises(PermissionError, match="anchor boundary"):
        replace(case, anchor_heads=frozenset()).pending()
    with pytest.raises(PermissionError, match="selected head"):
        replace(case, selected_head="f" * 64).pending()


def test_anchored_audit_without_its_immutable_object_refuses(tmp_path: Path) -> None:
    """The selected frame-to-object relation is checked in both directions."""
    audited = _audit(_case(tmp_path))
    with pytest.raises(PermissionError, match="audit lacks selected immutable intent"):
        replace(audited, objects={}).pending()


def test_parent_and_live_fragment_conflicts_refuse(tmp_path: Path) -> None:
    """An absent parent or competing live claim cannot be skipped."""
    case = _case(tmp_path, parent="f" * 64)
    with pytest.raises(PermissionError, match="parent intent is missing"):
        case.pending()
    first = _case(tmp_path)
    second = _case(tmp_path, time="2026-09-23T03:00:00.000001Z")
    with pytest.raises(PermissionError, match="terminal fragment repeats"):
        replace(first, objects={**first.objects, **second.objects}).pending()


def test_child_remains_pending_after_parent_audit_and_branch_refuses(tmp_path: Path) -> None:
    """Each child needs its own anchored frame even when its parent resolved."""
    root = _case(tmp_path)
    parent_digest = next(iter(root.objects))
    child = _case(tmp_path, parent=parent_digest, time="2026-09-23T03:00:00.000001Z")
    audited = _audit(root)
    combined = replace(audited, objects={**root.objects, **child.objects})
    assert combined.pending() == frozenset(child.objects)
    sibling = _case(tmp_path, parent=parent_digest, time="2026-09-23T03:00:00.000002Z")
    with pytest.raises(PermissionError, match="live child branch"):
        replace(combined, objects={**combined.objects, **sibling.objects}).pending()


def test_distinct_root_and_child_fragments_may_both_remain_pending(tmp_path: Path) -> None:
    """A torn audit frame at the same offset is a new fragment, not a duplicate."""
    root = _case(tmp_path)
    parent_digest = next(iter(root.objects))
    child = _changed(
        _case(tmp_path, parent=parent_digest, time="2026-09-23T03:00:00.000001Z"),
        removed_bytes_b64=base64.b64encode(b"y").decode("ascii"),
        removed_digest=sha256(b"y").hexdigest(),
    )
    both = replace(root, objects={**root.objects, **child.objects})
    assert both.pending() == frozenset(both.objects)


def test_prefix_offset_and_duplicate_audit_refuse(tmp_path: Path) -> None:
    """An old boundary and exactly one anchored recovery frame are required."""
    case = _case(tmp_path)
    with pytest.raises(PermissionError, match="prefix boundary"):
        _changed(case, selected_journal_head="f" * 64).pending()
    with pytest.raises(PermissionError, match="frame offset"):
        _changed(
            case,
            frame_offset=len(JOURNAL_MAGIC_V2) + 1,
            old_size=len(JOURNAL_MAGIC_V2) + 2,
        ).pending()
    audited = _audit(case)
    first = audited.journal.records[0]
    second = build_effect_journal_frame_v2(
        kind="journal-tail-recovery",
        body=first.body,
        host_time=_TIME,
        previous_head=bytes.fromhex(first.record_head),
        seq=2,
    )
    repeated = replace(
        audited,
        journal=replace(audited.journal, records=(first, second), head_digest=second.record_head),
        selected_head=second.record_head,
    )
    with pytest.raises(PermissionError, match="audit frame repeats"):
        repeated.pending()


def test_other_selected_file_identity_is_inert(tmp_path: Path) -> None:
    """Retained evidence for another selected triple cannot block this one."""
    current = tmp_path / "current"
    other = tmp_path / "other"
    current.mkdir()
    other.mkdir()
    selected = _case(current)
    unrelated = _case(other)
    assert replace(
        selected, objects={**selected.objects, **unrelated.objects}
    ).pending() == frozenset(selected.objects)


@pytest.mark.parametrize("alias", ["f" * 64, "BAD", "a" * 64 + ".json"])
def test_object_digest_alias_refuses_before_intent_resolution(tmp_path: Path, alias: str) -> None:
    """A public verifier must reject a map key that does not commit its exact bytes."""
    case = _case(tmp_path)
    data = next(iter(case.objects.values()))
    assert alias != sha256(data).hexdigest()
    with pytest.raises(PermissionError, match="object filename differs"):
        replace(case, objects={alias: data}).pending()
