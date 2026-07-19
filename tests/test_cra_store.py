# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — append-only CRA storage tests

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from rigor_foundry.cra_events import SecurityEventRevision
from rigor_foundry.cra_payloads import PreparedPayload, prepare_stage_payload, prepare_user_notice
from rigor_foundry.cra_registration import ProductRegistration
from rigor_foundry.cra_store import CraRepository
from rigor_foundry.cra_submissions import StageDraft, StageSkip, SubmissionReceipt, UserNoticeDraft

NOW = "2026-07-20T00:00:00Z"


def git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-c", f"safe.directory={root}", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


def worktree(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "--quiet")
    (root / ".gitignore").write_text(".rigor/\n", encoding="utf-8")
    git(root, "add", ".gitignore")
    return root


def registration() -> ProductRegistration:
    return ProductRegistration.build(
        product_key="widget",
        product_name="Widget",
        manufacturer_name="Example Manufacturer",
        main_establishment_ms="DE",
        establishment_basis="decisions",
        csirt_endpoint_id="de-csirt",
        user_notice_channel="security page",
        support_period_months=48,
        expected_use_months=36,
        expected_use_evidence_ref="evidence/use.json",
        registered_at=NOW,
    )


def event(**changes: object) -> SecurityEventRevision:
    values: dict[str, object] = {
        "event_key": "EVENT-1",
        "product_key": "widget",
        "track": "vulnerability",
        "aware_at": NOW,
        "aware_evidence_ref": "evidence/aware.json",
        "exploitation_evidence": ("evidence/exploit.json",),
        "member_states": ("DE",),
        "recorded_at": NOW,
    }
    values.update(changes)
    return SecurityEventRevision.build(**values)  # type: ignore[arg-type]


def repository(tmp_path: Path) -> CraRepository:
    return CraRepository.bootstrap(worktree(tmp_path), registration())


def receipt_for(draft_digest: str, payload_digest: str) -> SubmissionReceipt:
    return SubmissionReceipt.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        stage="early-warning",
        draft_digest=draft_digest,
        payload_digest=payload_digest,
        submitted_at="2026-07-20T01:00:00Z",
        platform_ref="operator-submission-reference",
        csirt_endpoint_id="de-csirt",
        evidence_sha256="e" * 64,
        bound_at="2026-07-20T01:01:00Z",
    )


def test_complete_storage_workflow_is_append_only_and_replayable(tmp_path: Path) -> None:
    store = repository(tmp_path)
    assert CraRepository.open(store.repository_root).storage_root == store.storage_root
    assert store.registrations() == (registration(),)
    selected = event()
    event_path = store.append_event(selected)
    assert event_path.name == f"{selected.revision_digest}.json"
    assert store.current_event("EVENT-1") == selected
    payload = prepare_stage_payload(
        registration(), selected, stage="early-warning", generated_at=NOW
    )
    draft = store.append_draft(selected, "early-warning", NOW, payload)
    assert store.append_draft(selected, "early-warning", NOW, payload) == draft
    receipt = receipt_for(draft.draft_digest, draft.payload_digest)
    assert store.append_receipt(receipt).is_file()
    skip = StageSkip.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        stage="notification",
        provided_in_stage="early-warning",
        provided_in_receipt_digest=receipt.receipt_digest,
        reason="notification information was already provided",
        evidence_ref="evidence/operator-decision.json",
        skipped_at="2026-07-20T01:02:00Z",
    )
    assert store.append_skip(skip).is_file()
    notice_payload = prepare_user_notice(
        registration(), selected, audience="impacted", machine_readable=True, generated_at=NOW
    )
    notice = UserNoticeDraft.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        revision_digest=selected.revision_digest,
        audience="impacted",
        machine_readable=True,
        json_payload_digest=notice_payload.json_digest,
        markdown_payload_digest=notice_payload.markdown_digest,
        generated_at=NOW,
    )
    assert store.append_user_notice(selected, notice, notice_payload).is_file()
    assert store.append_user_notice(selected, notice, notice_payload).is_file()
    state = store.event_state("EVENT-1")
    assert state.event == selected
    assert state.drafts == (draft,)
    assert state.receipts == (receipt,)
    assert state.skips == (skip,)
    assert store.event_keys() == ("EVENT-1",)


def test_successor_chain_selects_one_tip_and_rejects_invalid_append(tmp_path: Path) -> None:
    store = repository(tmp_path)
    first = event()
    store.append_event(first)
    second = event(
        status="fixing",
        recorded_at="2026-07-20T00:01:00Z",
        previous_revision_digest=first.revision_digest,
    )
    store.append_event(second)
    assert store.current_event("EVENT-1") == second
    with pytest.raises(ValueError, match="current digest"):
        store.append_event(
            event(
                status="fix-available",
                recorded_at="2026-07-20T00:02:00Z",
                previous_revision_digest=first.revision_digest,
            )
        )
    with pytest.raises(ValueError, match="initial event"):
        store.append_event(
            event(
                event_key="NEW",
                previous_revision_digest="a" * 64,
            )
        )
    with pytest.raises(ValueError, match="exactly one"):
        store.append_event(event(event_key="OTHER", product_key="missing"))


def test_chain_replay_rejects_missing_parent_fork_and_multiple_roots(tmp_path: Path) -> None:
    for mode in ("missing", "fork", "roots"):
        root = tmp_path / mode
        root.mkdir()
        store = CraRepository.bootstrap(worktree(root), registration())
        first = event()
        store.append_event(first)
        directory = store.storage_root / "events/EVENT-1/revisions"
        records: tuple[SecurityEventRevision, ...]
        if mode == "missing":
            records = (
                event(
                    status="fixing",
                    recorded_at="2026-07-20T00:01:00Z",
                    previous_revision_digest="f" * 64,
                ),
            )
            pattern = "missing parent"
        elif mode == "fork":
            records = (
                event(
                    status="fixing",
                    recorded_at="2026-07-20T00:01:00Z",
                    previous_revision_digest=first.revision_digest,
                ),
                event(
                    status="closed",
                    recorded_at="2026-07-20T00:02:00Z",
                    previous_revision_digest=first.revision_digest,
                ),
            )
            pattern = "forked"
        else:
            records = (event(recorded_at="2026-07-20T00:01:00Z"),)
            pattern = "multiple roots"
        for record in records:
            (directory / f"{record.revision_digest}.json").write_text(
                record.to_json(), encoding="utf-8"
            )
        with pytest.raises(ValueError, match=pattern):
            store.current_event("EVENT-1")


def test_replay_rejects_tampering_filename_and_unexpected_entries(tmp_path: Path) -> None:
    store = repository(tmp_path)
    selected = event()
    path = store.append_event(selected)
    path.write_text(path.read_text().replace("triaged", "closed"), encoding="utf-8")
    with pytest.raises(ValueError, match="digest"):
        store.current_event("EVENT-1")

    clean = tmp_path / "clean"
    clean.mkdir()
    store = repository(clean)
    selected = event()
    path = store.append_event(selected)
    renamed = path.with_name(f"{'a' * 64}.json")
    path.rename(renamed)
    with pytest.raises(ValueError, match="filename"):
        store.current_event("EVENT-1")
    renamed.unlink()
    (renamed.parent / "README.txt").write_text("unexpected", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected"):
        store.current_event("EVENT-1")

    canonical_parent = tmp_path / "canonical"
    canonical_parent.mkdir()
    store = repository(canonical_parent)
    path = store.append_event(event())
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not canonical"):
        store.current_event("EVENT-1")


def test_replay_rejects_invalid_json_utf8_symlink_and_oversize(tmp_path: Path) -> None:
    cases = ("json", "utf8", "symlink", "oversize")
    for case in cases:
        case_root = tmp_path / case
        case_root.mkdir()
        store = repository(case_root)
        selected = event()
        path = store.append_event(selected)
        if case == "json":
            path.write_text("{\n", encoding="utf-8")
            pattern = "valid JSON"
        elif case == "utf8":
            path.write_bytes(b"\xff")
            pattern = "UTF-8"
        elif case == "symlink":
            victim = case_root / "victim"
            victim.write_text(selected.to_json(), encoding="utf-8")
            path.unlink()
            path.symlink_to(victim)
            pattern = "Too many levels|single-link"
        else:
            path.write_bytes(b"x" * 1_048_577)
            pattern = "byte limit"
        with pytest.raises((OSError, ValueError), match=pattern):
            store.current_event("EVENT-1")


def test_duplicate_current_stage_records_and_binding_conflicts_fail(tmp_path: Path) -> None:
    store = repository(tmp_path)
    selected = event()
    store.append_event(selected)
    payload = prepare_stage_payload(
        registration(), selected, stage="early-warning", generated_at=NOW
    )
    first = store.append_draft(selected, "early-warning", NOW, payload)
    changed = PreparedPayload(
        json_text=payload.json_text + " ",
        markdown_text=payload.markdown_text,
        json_digest=hashlib.sha256((payload.json_text + " ").encode()).hexdigest(),
        markdown_digest=payload.markdown_digest,
    )
    with pytest.raises(ValueError, match="different draft"):
        store.append_draft(selected, "early-warning", "2026-07-20T00:00:01Z", changed)
    conflicting = StageDraft.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        stage="early-warning",
        revision_digest=selected.revision_digest,
        payload_path=(f".rigor/cra/outbox/EVENT-1/early-warning/{changed.json_digest}.json"),
        payload_digest=changed.json_digest,
        markdown_path=(f".rigor/cra/outbox/EVENT-1/early-warning/{changed.markdown_digest}.md"),
        markdown_payload_digest=changed.markdown_digest,
        generated_at="2026-07-20T00:00:01Z",
        tool_version="0.1.1",
    )
    directory = store.storage_root / "events/EVENT-1/drafts/early-warning"
    changed_json_path = store.repository_root / conflicting.payload_path
    changed_json_path.write_text(changed.json_text, encoding="utf-8")
    (directory / f"{conflicting.draft_digest}.json").write_text(
        conflicting.to_json(), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="multiple current draft"):
        store.event_state("EVENT-1")

    other_root = tmp_path / "bindings"
    other_root.mkdir()
    store = repository(other_root)
    selected = event()
    store.append_event(selected)
    first = store.append_draft(selected, "early-warning", NOW, payload)
    receipt = receipt_for(first.draft_digest, first.payload_digest)
    store.append_receipt(receipt)
    with pytest.raises(ValueError, match="already has a receipt"):
        store.append_receipt(receipt)
    conflicting_skip = StageSkip.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        stage="notification",
        provided_in_stage="early-warning",
        provided_in_receipt_digest=receipt.receipt_digest,
        reason="already provided",
        evidence_ref="evidence/decision.json",
        skipped_at=NOW,
    )
    store.append_skip(conflicting_skip)
    with pytest.raises(ValueError, match="already has a skip"):
        store.append_skip(conflicting_skip)


def test_cross_wired_draft_receipt_skip_and_notice_fail(tmp_path: Path) -> None:
    store = repository(tmp_path)
    selected = event()
    store.append_event(selected)
    payload = prepare_stage_payload(
        registration(), selected, stage="early-warning", generated_at=NOW
    )
    with pytest.raises(ValueError, match="not the current"):
        store.append_draft(event(status="closed"), "early-warning", NOW, payload)
    draft = store.append_draft(selected, "early-warning", NOW, payload)
    bad_receipt = SubmissionReceipt.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        stage="early-warning",
        draft_digest="f" * 64,
        payload_digest=draft.payload_digest,
        submitted_at="2026-07-20T01:00:00Z",
        platform_ref="operator-reference",
        csirt_endpoint_id="de-csirt",
        evidence_sha256="e" * 64,
        bound_at="2026-07-20T01:01:00Z",
    )
    with pytest.raises(ValueError, match="exactly one current draft"):
        store.append_receipt(bad_receipt)
    receipt = receipt_for(draft.draft_digest, draft.payload_digest)
    store.append_receipt(receipt)
    bad_skip = StageSkip.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        stage="notification",
        provided_in_stage="early-warning",
        provided_in_receipt_digest="f" * 64,
        reason="bad binding",
        evidence_ref="evidence/decision.json",
        skipped_at=NOW,
    )
    with pytest.raises(ValueError, match="exactly one"):
        store.append_skip(bad_skip)
    notice_payload = prepare_user_notice(
        registration(), selected, audience="all", machine_readable=False, generated_at=NOW
    )
    notice = UserNoticeDraft.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        revision_digest=selected.revision_digest,
        audience="all",
        machine_readable=False,
        json_payload_digest=notice_payload.json_digest,
        markdown_payload_digest=notice_payload.markdown_digest,
        generated_at=NOW,
    )
    mismatched_notice = UserNoticeDraft.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        revision_digest=selected.revision_digest,
        audience="all",
        machine_readable=False,
        json_payload_digest="b" * 64,
        markdown_payload_digest=notice_payload.markdown_digest,
        generated_at=NOW,
    )
    with pytest.raises(ValueError, match="does not bind"):
        store.append_user_notice(selected, mismatched_notice, notice_payload)
    with pytest.raises(ValueError, match="not the current"):
        store.append_user_notice(event(status="closed"), notice, notice_payload)


def test_bootstrap_and_open_reject_existing_missing_or_linked_state(tmp_path: Path) -> None:
    store = repository(tmp_path)
    with pytest.raises(ValueError, match="already exists"):
        CraRepository.bootstrap(store.repository_root, registration())
    missing = tmp_path / "missing"
    missing.mkdir()
    git(missing, "init", "--quiet")
    (missing / ".gitignore").write_text(".rigor/\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        CraRepository.open(missing)
    linked = tmp_path / "linked"
    linked.mkdir()
    git(linked, "init", "--quiet")
    (linked / ".gitignore").write_text(".rigor/\n", encoding="utf-8")
    (linked / ".rigor").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic"):
        CraRepository.open(linked)


def test_registration_and_event_directory_ambiguity_fail_closed(tmp_path: Path) -> None:
    store = repository(tmp_path)
    registration_path = next((store.storage_root / "registrations/widget").glob("*.json"))
    duplicate = ProductRegistration.build(
        product_key="widget",
        product_name="Other",
        manufacturer_name="Example Manufacturer",
        main_establishment_ms="DE",
        establishment_basis="decisions",
        csirt_endpoint_id="de-csirt",
        user_notice_channel="security page",
        support_period_months=48,
        expected_use_months=36,
        expected_use_evidence_ref="evidence/use.json",
        registered_at=NOW,
    )
    (registration_path.parent / f"{duplicate.registration_digest}.json").write_text(
        duplicate.to_json(), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="exactly one"):
        store.current_registration("widget")
    bad_entry = store.storage_root / "events/not-a-directory"
    bad_entry.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="directory"):
        store.event_keys()


def test_crash_replay_refuses_digest_path_with_different_bytes(tmp_path: Path) -> None:
    store = repository(tmp_path)
    selected = event()
    store.append_event(selected)
    payload = prepare_stage_payload(
        registration(), selected, stage="early-warning", generated_at=NOW
    )
    outbox = store.storage_root / "outbox/EVENT-1/early-warning"
    outbox.mkdir(parents=True)
    collision = outbox / f"{payload.json_digest}.json"
    collision.write_text("different bytes\n", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        store.append_draft(selected, "early-warning", NOW, payload)


def test_storage_public_guards_cover_links_and_graph_disconnection(tmp_path: Path) -> None:
    linked_case = tmp_path / "linked-case"
    linked_case.mkdir()
    store = repository(linked_case)
    selected = event()
    path = store.append_event(selected)
    alias = tmp_path / "revision-alias"
    os.link(path, alias)
    with pytest.raises(ValueError, match="single-link"):
        store.current_event("EVENT-1")

    duplicate = replace(selected, revision_digest="a" * 64)
    with pytest.raises(ValueError, match="duplicate digests"):
        CraRepository.select_event_tip((duplicate, duplicate))
    root = replace(selected, revision_digest="a" * 64)
    cycle_one = replace(
        selected,
        revision_digest="b" * 64,
        previous_revision_digest="c" * 64,
    )
    cycle_two = replace(
        selected,
        revision_digest="c" * 64,
        previous_revision_digest="b" * 64,
    )
    with pytest.raises(ValueError, match="multiple tips"):
        CraRepository.select_event_tip((root, cycle_one, cycle_two))


def test_receipt_and_skip_coexistence_are_rejected_both_directions(tmp_path: Path) -> None:
    store = repository(tmp_path)
    selected = event()
    store.append_event(selected)
    early_payload = prepare_stage_payload(
        registration(), selected, stage="early-warning", generated_at=NOW
    )
    early = store.append_draft(selected, "early-warning", NOW, early_payload)
    early_receipt = receipt_for(early.draft_digest, early.payload_digest)
    store.append_receipt(early_receipt)
    skip = StageSkip.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        stage="notification",
        provided_in_stage="early-warning",
        provided_in_receipt_digest=early_receipt.receipt_digest,
        reason="already provided",
        evidence_ref="evidence/decision.json",
        skipped_at=NOW,
    )
    store.append_skip(skip)
    notification_payload = prepare_stage_payload(
        registration(), selected, stage="notification", generated_at=NOW
    )
    notification = store.append_draft(selected, "notification", NOW, notification_payload)
    notification_receipt = SubmissionReceipt.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        stage="notification",
        draft_digest=notification.draft_digest,
        payload_digest=notification.payload_digest,
        submitted_at=NOW,
        platform_ref="operator-ref",
        csirt_endpoint_id="de-csirt",
        evidence_sha256="e" * 64,
        bound_at=NOW,
    )
    with pytest.raises(ValueError, match="already has a skip"):
        store.append_receipt(notification_receipt)

    other = tmp_path / "reverse"
    other.mkdir()
    reverse = repository(other)
    reverse.append_event(selected)
    early = reverse.append_draft(selected, "early-warning", NOW, early_payload)
    early_receipt = receipt_for(early.draft_digest, early.payload_digest)
    reverse.append_receipt(early_receipt)
    notification = reverse.append_draft(selected, "notification", NOW, notification_payload)
    reverse.append_receipt(
        SubmissionReceipt.build(
            product_key="widget",
            event_key="EVENT-1",
            track="vulnerability",
            stage="notification",
            draft_digest=notification.draft_digest,
            payload_digest=notification.payload_digest,
            submitted_at=NOW,
            platform_ref="operator-ref",
            csirt_endpoint_id="de-csirt",
            evidence_sha256="e" * 64,
            bound_at=NOW,
        )
    )
    skip = replace(skip, provided_in_receipt_digest=early_receipt.receipt_digest)
    with pytest.raises(ValueError, match="already has a receipt"):
        reverse.append_skip(skip)


def test_historical_draft_and_receipt_survive_a_valid_event_successor(tmp_path: Path) -> None:
    store = repository(tmp_path)
    first = event()
    store.append_event(first)
    payload = prepare_stage_payload(registration(), first, stage="early-warning", generated_at=NOW)
    draft = store.append_draft(first, "early-warning", NOW, payload)
    receipt = receipt_for(draft.draft_digest, draft.payload_digest)
    store.append_receipt(receipt)
    successor = event(
        status="fixing",
        recorded_at="2026-07-20T00:01:00Z",
        previous_revision_digest=first.revision_digest,
    )
    store.append_event(successor)
    state = store.event_state("EVENT-1")
    assert state.event == successor
    assert state.drafts == (draft,)
    assert state.receipts == (receipt,)
    assert state.revision_digests == frozenset({first.revision_digest, successor.revision_digest})


def test_full_replay_rejects_cross_wired_and_unknown_records(tmp_path: Path) -> None:
    cases = (
        "draft-identity",
        "draft-revision",
        "receipt-identity",
        "receipt-orphan",
        "skip-identity",
        "notice-identity",
        "notice-revision",
    )
    for case in cases:
        parent = tmp_path / case
        parent.mkdir()
        store = repository(parent)
        selected = event()
        store.append_event(selected)
        base = store.storage_root / "events/EVENT-1"
        record: StageDraft | SubmissionReceipt | StageSkip | UserNoticeDraft
        if case.startswith("draft"):
            record = StageDraft.build(
                product_key="other" if case == "draft-identity" else "widget",
                event_key="EVENT-1",
                track="vulnerability",
                stage="early-warning",
                revision_digest=(
                    selected.revision_digest if case == "draft-identity" else "f" * 64
                ),
                payload_path=".rigor/cra/outbox/EVENT-1/early-warning/" + "a" * 64 + ".json",
                payload_digest="a" * 64,
                markdown_path=".rigor/cra/outbox/EVENT-1/early-warning/" + "b" * 64 + ".md",
                markdown_payload_digest="b" * 64,
                generated_at=NOW,
                tool_version="0.1.1",
            )
            directory = base / "drafts/early-warning"
            pattern = "another event" if case == "draft-identity" else "unknown event revision"
        elif case.startswith("receipt"):
            record = SubmissionReceipt.build(
                product_key="other" if case == "receipt-identity" else "widget",
                event_key="EVENT-1",
                track="vulnerability",
                stage="early-warning",
                draft_digest="a" * 64,
                payload_digest="b" * 64,
                submitted_at=NOW,
                platform_ref="operator-ref",
                csirt_endpoint_id="de-csirt",
                evidence_sha256="e" * 64,
                bound_at=NOW,
            )
            directory = base / "receipts/early-warning"
            pattern = "another event" if case == "receipt-identity" else "no available"
        elif case == "skip-identity":
            record = StageSkip.build(
                product_key="other",
                event_key="EVENT-1",
                track="vulnerability",
                stage="notification",
                provided_in_stage="early-warning",
                provided_in_receipt_digest="e" * 64,
                reason="cross-wired",
                evidence_ref="evidence/decision.json",
                skipped_at=NOW,
            )
            directory = base / "skips/notification"
            pattern = "another event"
        else:
            record = UserNoticeDraft.build(
                product_key="other" if case == "notice-identity" else "widget",
                event_key="EVENT-1",
                track="vulnerability",
                revision_digest=(
                    selected.revision_digest if case == "notice-identity" else "f" * 64
                ),
                audience="all",
                machine_readable=False,
                json_payload_digest="a" * 64,
                markdown_payload_digest="b" * 64,
                generated_at=NOW,
            )
            directory = base / "user-notices"
            pattern = "another event" if case == "notice-identity" else "unknown event revision"
        directory.mkdir(parents=True)
        if isinstance(record, StageDraft):
            digest = record.draft_digest
        elif isinstance(record, SubmissionReceipt):
            digest = record.receipt_digest
        elif isinstance(record, StageSkip):
            digest = record.skip_digest
        else:
            digest = record.notice_digest
        (directory / f"{digest}.json").write_text(record.to_json(), encoding="utf-8")
        with pytest.raises(ValueError, match=pattern):
            store.event_state("EVENT-1")


def test_payload_replay_rejects_wrong_paths_and_mutated_bytes(tmp_path: Path) -> None:
    wrong_parent = tmp_path / "wrong-path"
    wrong_parent.mkdir()
    store = repository(wrong_parent)
    selected = event()
    store.append_event(selected)
    wrong = StageDraft.build(
        product_key="widget",
        event_key="EVENT-1",
        track="vulnerability",
        stage="early-warning",
        revision_digest=selected.revision_digest,
        payload_path=".rigor/cra/outbox/EVENT-1/other/" + "a" * 64 + ".json",
        payload_digest="a" * 64,
        markdown_path=".rigor/cra/outbox/EVENT-1/other/" + "b" * 64 + ".md",
        markdown_payload_digest="b" * 64,
        generated_at=NOW,
        tool_version="0.1.1",
    )
    directory = store.storage_root / "events/EVENT-1/drafts/early-warning"
    directory.mkdir(parents=True)
    (directory / f"{wrong.draft_digest}.json").write_text(wrong.to_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="payload path"):
        store.event_state("EVENT-1")

    changed_parent = tmp_path / "changed-bytes"
    changed_parent.mkdir()
    store = repository(changed_parent)
    selected = event()
    store.append_event(selected)
    payload = prepare_stage_payload(
        registration(), selected, stage="early-warning", generated_at=NOW
    )
    draft = store.append_draft(selected, "early-warning", NOW, payload)
    (store.repository_root / draft.payload_path).write_text("mutated\n", encoding="utf-8")
    with pytest.raises(ValueError, match="payload digest"):
        store.event_state("EVENT-1")


def test_missing_event_state_is_explicit(tmp_path: Path) -> None:
    store = repository(tmp_path)
    with pytest.raises(ValueError, match="no verified revisions"):
        store.event_state("MISSING")
