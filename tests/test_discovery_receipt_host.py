# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-selected discovery receipt tests
"""Exercise host-held discovery replay and exact source receipt boundaries."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from discovery_source_support import limits as source_limits
from test_semantic_transition import (
    _HOST_QUESTION,
    _HOST_REPLY,
    _HOST_SOURCE,
    _evidence,
    _snapshot_with_successors,
)

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.discovery_progress import ProgressLimits, replay_discovery_progress
from rigor_foundry.discovery_receipt_host import (
    HostDiscoveryReceiptSelection,
    HostDiscoveryReceiptState,
    HostDiscoveryReceiptVerifier,
)
from rigor_foundry.discovery_source_validation import validate_discovery_sources
from rigor_foundry.semantic_transition import SemanticTransitionProposal


def _host_verifier(state: HostDiscoveryReceiptState) -> HostDiscoveryReceiptVerifier:
    @contextmanager
    def lease() -> Iterator[HostDiscoveryReceiptState]:
        yield state

    return HostDiscoveryReceiptVerifier(lease)


def _verify_host(
    verifier: HostDiscoveryReceiptVerifier,
    proposal: SemanticTransitionProposal,
    *,
    source: bytes = _HOST_SOURCE,
    question: bytes = _HOST_QUESTION,
    reply: bytes = _HOST_REPLY,
) -> dict[str, object]:
    return verifier.verify(
        proposal,
        proposal_source=source,
        owner_question=question,
        owner_reply=reply,
    )


def _host_evidence(
    root: Path,
) -> tuple[SemanticTransitionProposal, HostDiscoveryReceiptSelection]:
    _snapshot_with_successors(root)
    budget = source_limits(root, candidates=4, spans=4)
    receipt = validate_discovery_sources(root, "manifest.json", limits=budget)
    proposal, replay, _, _, _ = _evidence(root, receipt_digest=str(receipt["receipt_digest"]))
    base = json.loads((root / "base.json").read_text(encoding="utf-8"))
    selection = HostDiscoveryReceiptSelection.build(
        lineage_root=root,
        base_name="base.json",
        transaction_names=(),
        base_sha256=canonical_digest(base),
        base_metadata_fields=(),
        progress_limits=ProgressLimits(10000, 10000, 8, 1, 1),
        replay_digest=str(replay["state_sha256"]),
        source_root=root,
        manifest_name="manifest.json",
        source_limits=budget,
        receipt_id=proposal.source_receipt_id,
        receipt_digest=proposal.source_receipt_digest,
        proposal_digest=proposal.proposal_digest,
    )
    return proposal, selection


def test_host_selected_receipt_rechecks_real_replay_and_sources(tmp_path: Path) -> None:
    """Neither the proposal nor caller chooses the replay, manifest or budgets."""
    proposal, selection = _host_evidence(tmp_path)
    state = HostDiscoveryReceiptState(selection, selection.selection_digest, frozenset())
    proof = _verify_host(_host_verifier(state), proposal)
    assert proof["schema_version"] == "host-discovery-receipt-verification.v2"
    assert proof["proposal_digest"] == proposal.proposal_digest
    assert proof["selection_digest"] == selection.selection_digest
    assert proof["proposal_source_digest"] == proposal.proposal_source_digest
    assert proof["owner_question_digest"] == proposal.owner_question_digest
    assert proof["owner_reply_digest"] == proposal.owner_reply_digest
    assert proof["promotable"] is False


@pytest.mark.parametrize(
    ("field", "altered"),
    [
        ("source", b"wrong successor\nsecond successor\nthird successor\nfourth successor\n"),
        ("question", b"wrong question\n"),
        ("reply", b"wrong approval\n"),
    ],
)
def test_host_receipt_refuses_changed_proposal_or_owner_bytes(
    tmp_path: Path, field: str, altered: bytes
) -> None:
    """Receipt integrity alone cannot admit changed transition or owner captures."""
    proposal, selection = _host_evidence(tmp_path)
    inputs = {"source": _HOST_SOURCE, "question": _HOST_QUESTION, "reply": _HOST_REPLY}
    inputs[field] = altered
    state = HostDiscoveryReceiptState(selection, selection.selection_digest, frozenset())
    with pytest.raises(ValueError, match="captured evidence differs"):
        _verify_host(_host_verifier(state), proposal, **inputs)


def test_host_receipt_refuses_bound_predecessor_even_with_rebased_pins(tmp_path: Path) -> None:
    """An integrity-valid replay with a bound predecessor is not a transition."""
    proposal, selection = _host_evidence(tmp_path)
    base = json.loads((tmp_path / "base.json").read_text(encoding="utf-8"))
    base["records"][0]["source_receipt"] = proposal.source_receipt_id
    (tmp_path / "base.json").write_text(json.dumps(base), encoding="utf-8")
    rebased = replay_discovery_progress(
        tmp_path,
        "base.json",
        (),
        base_sha256=canonical_digest(base),
        limits=selection.progress_limits,
    )
    changed_proposal = SemanticTransitionProposal.build(
        parent_replay_digest=str(rebased["state_sha256"]),
        proposal_source_digest=proposal.proposal_source_digest,
        owner_question_digest=proposal.owner_question_digest,
        owner_reply_digest=proposal.owner_reply_digest,
        source_receipt_id=proposal.source_receipt_id,
        source_receipt_digest=proposal.source_receipt_digest,
        replacements=proposal.replacements,
    )
    changed_selection = HostDiscoveryReceiptSelection.build(
        lineage_root=selection.lineage_root,
        base_name=selection.base_name,
        transaction_names=selection.transaction_names,
        base_sha256=canonical_digest(base),
        base_metadata_fields=selection.base_metadata_fields,
        progress_limits=selection.progress_limits,
        replay_digest=str(rebased["state_sha256"]),
        source_root=selection.source_root,
        manifest_name=selection.manifest_name,
        source_limits=selection.source_limits,
        receipt_id=selection.receipt_id,
        receipt_digest=selection.receipt_digest,
        proposal_digest=changed_proposal.proposal_digest,
    )
    state = HostDiscoveryReceiptState(
        changed_selection, changed_selection.selection_digest, frozenset()
    )
    with pytest.raises(ValueError, match="captured evidence differs"):
        _verify_host(_host_verifier(state), changed_proposal)


def test_host_selected_receipt_refuses_mutation_revocation_and_crossing(tmp_path: Path) -> None:
    """Change selected bytes, selection identity or host revocation and fail closed."""
    proposal, selection = _host_evidence(tmp_path)
    state = HostDiscoveryReceiptState(selection, selection.selection_digest, frozenset())
    verifier = _host_verifier(state)
    original = (tmp_path / "source0.txt").read_bytes()
    (tmp_path / "source0.txt").write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="captured evidence differs"):
        _verify_host(verifier, proposal)
    (tmp_path / "source0.txt").write_bytes(original)
    with pytest.raises(PermissionError, match="differs"):
        _verify_host(_host_verifier(replace(state, expected_selection_digest="0" * 64)), proposal)
    with pytest.raises(PermissionError, match="differs"):
        _verify_host(
            _host_verifier(
                replace(state, revoked_selection_digests=frozenset({selection.selection_digest}))
            ),
            proposal,
        )
    crossed = replace(proposal, proposal_digest="0" * 64)
    with pytest.raises(ValueError):
        _verify_host(verifier, crossed)


def test_host_selected_receipt_binds_exact_limits_and_manifest(tmp_path: Path) -> None:
    """A valid alternate budget is a different host selection, not an implicit fallback."""
    proposal, selection = _host_evidence(tmp_path)
    changed = HostDiscoveryReceiptSelection.build(
        lineage_root=selection.lineage_root,
        base_name=selection.base_name,
        transaction_names=selection.transaction_names,
        base_sha256=selection.base_sha256,
        base_metadata_fields=selection.base_metadata_fields,
        progress_limits=ProgressLimits(10001, 10000, 8, 1, 1),
        replay_digest=selection.replay_digest,
        source_root=selection.source_root,
        manifest_name=selection.manifest_name,
        source_limits=selection.source_limits,
        receipt_id=selection.receipt_id,
        receipt_digest=selection.receipt_digest,
        proposal_digest=selection.proposal_digest,
    )
    assert changed.selection_digest != selection.selection_digest
    with pytest.raises(PermissionError, match="differs"):
        _verify_host(
            _host_verifier(
                HostDiscoveryReceiptState(changed, selection.selection_digest, frozenset())
            ),
            proposal,
        )
    missing = replace(selection, manifest_name="missing.json")
    with pytest.raises(PermissionError, match="differs"):
        _verify_host(
            _host_verifier(
                HostDiscoveryReceiptState(missing, selection.selection_digest, frozenset())
            ),
            proposal,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("lineage_root", Path("relative")),
        ("source_root", Path("relative")),
        ("transaction_names", cast(tuple[str, ...], ["first.json"])),
        ("base_metadata_fields", cast(tuple[str, ...], ["records"])),
        ("transaction_names", ("same.json", "same.json")),
        ("base_metadata_fields", ("same", "same")),
        ("progress_limits", cast(ProgressLimits, None)),
        ("source_limits", cast(object, None)),
    ],
)
def test_host_selection_refuses_invalid_state(tmp_path: Path, field: str, value: object) -> None:
    """Reject invalid roots, collections, duplicate names and absent limits."""
    proposal, selection = _host_evidence(tmp_path)
    altered = replace(selection, **{field: value})
    state = HostDiscoveryReceiptState(altered, selection.selection_digest, frozenset())
    with pytest.raises(ValueError):
        _verify_host(_host_verifier(state), proposal)


def test_host_receipt_refuses_missing_state(tmp_path: Path) -> None:
    """A missing or malformed host lease cannot be treated as an empty selection."""
    proposal, _ = _host_evidence(tmp_path)
    unavailable = cast(HostDiscoveryReceiptState, object())
    with pytest.raises(PermissionError, match="unavailable"):
        _verify_host(_host_verifier(unavailable), proposal)


def test_host_cannot_suppress_discovery_failure(tmp_path: Path) -> None:
    """A host lease swallowing a source mismatch cannot return a proof-shaped success."""
    proposal, selection = _host_evidence(tmp_path)
    (tmp_path / "source0.txt").write_bytes(b"changed\n")

    @contextmanager
    def suppressing_state() -> Iterator[HostDiscoveryReceiptState]:
        with suppress(ValueError):
            yield HostDiscoveryReceiptState(selection, selection.selection_digest, frozenset())

    with pytest.raises(PermissionError, match="suppressed verification failure"):
        _verify_host(HostDiscoveryReceiptVerifier(suppressing_state), proposal)
