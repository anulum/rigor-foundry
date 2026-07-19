# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline CRA CLI integration tests

from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path

import pytest

from rigor_foundry.cli import main
from rigor_foundry.cra_events import SecurityEventRevision
from rigor_foundry.cra_store import CraRepository

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


def bootstrap(root: Path, *, registered_at: bool = True) -> list[str]:
    argv = [
        "cra-bootstrap",
        "--root",
        str(root),
        "--product-key",
        "widget",
        "--product-name",
        "Widget",
        "--manufacturer-name",
        "Example Manufacturer",
        "--main-establishment-ms",
        "DE",
        "--establishment-basis",
        "decisions",
        "--csirt-endpoint-id",
        "de-csirt",
        "--user-notice-channel",
        "security-page",
        "--support-period-months",
        "60",
    ]
    if registered_at:
        argv.extend(("--registered-at", NOW))
    return argv


def register(root: Path, *, event_key: str = "EVENT-1", track: str = "vulnerability") -> list[str]:
    argv = [
        "vuln-register",
        event_key,
        "--root",
        str(root),
        "--product-key",
        "widget",
        "--track",
        track,
        "--aware-at",
        NOW,
        "--aware-evidence",
        "evidence/aware.json",
        "--member-state",
        "DE",
        "--recorded-at",
        NOW,
    ]
    if track == "vulnerability":
        argv.extend(("--exploitation-evidence", "evidence/exploit.json"))
    else:
        argv.extend(
            (
                "--severe-prong",
                "data-or-functions",
                "--severe-evidence",
                "evidence/severe.json",
                "--suspected-cause",
                "unknown",
            )
        )
    return argv


def test_complete_cli_workflow_never_submits_or_sends(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = worktree(tmp_path)
    assert main(bootstrap(root)) == 0
    assert main(register(root)) == 0
    assert main(["vuln-timeline", "EVENT-1", "--root", str(root), "--now", NOW]) == 0
    assert (
        main(
            [
                "cra-draft",
                "EVENT-1",
                "--root",
                str(root),
                "--stage",
                "early-warning",
                "--generated-at",
                NOW,
            ]
        )
        == 0
    )
    state = CraRepository.open(root).event_state("EVENT-1")
    draft = state.drafts[0]
    evidence = root / "operator-receipt.txt"
    evidence.write_text("operator supplied evidence\n", encoding="utf-8")
    assert (
        main(
            [
                "cra-receipt",
                "EVENT-1",
                "--root",
                str(root),
                "--stage",
                "early-warning",
                "--draft-digest",
                draft.draft_digest,
                "--submitted-at",
                "2026-07-20T01:00:00Z",
                "--platform-ref",
                "operator-reference",
                "--csirt-endpoint-id",
                "de-csirt",
                "--evidence",
                str(evidence),
                "--bound-at",
                "2026-07-20T01:01:00Z",
            ]
        )
        == 0
    )
    receipt = CraRepository.open(root).event_state("EVENT-1").receipts[0]
    assert (
        main(
            [
                "cra-skip",
                "EVENT-1",
                "--root",
                str(root),
                "--stage",
                "notification",
                "--provided-in-stage",
                "early-warning",
                "--provided-in-receipt-digest",
                receipt.receipt_digest,
                "--reason",
                "already provided",
                "--evidence-ref",
                "evidence/operator-decision.json",
                "--skipped-at",
                "2026-07-20T01:02:00Z",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "user-notice",
                "EVENT-1",
                "--root",
                str(root),
                "--audience",
                "impacted",
                "--machine-readable",
                "--generated-at",
                NOW,
            ]
        )
        == 0
    )
    assert main(["cra-status", "--root", str(root), "--event-key", "EVENT-1", "--now", NOW]) == 0
    assert main(["cra-status", "--root", str(root), "--now", NOW, "--json"]) == 0
    output = capsys.readouterr().out
    assert "no authority acceptance is claimed" in output
    assert "prepare-only user notice" in output
    assert "submitted" in output
    assert '"events"' in output


def test_incident_cli_and_alert_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = worktree(tmp_path)
    assert main(bootstrap(root, registered_at=False)) == 0
    assert main(register(root, event_key="INC-1", track="incident")) == 0
    assert (
        main(
            [
                "vuln-timeline",
                "INC-1",
                "--root",
                str(root),
                "--now",
                "2026-07-21T00:00:01Z",
            ]
        )
        == 1
    )
    assert (
        main(["cra-status", "--root", str(root), "--now", "2026-07-21T00:00:01Z", "--json"]) == 1
    )
    assert '"operational_alert": true' in capsys.readouterr().out


def test_cli_rejects_mismatched_receipt_and_skip_selectors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = worktree(tmp_path)
    assert main(bootstrap(root)) == 0
    assert main(register(root)) == 0
    evidence = root / "receipt.txt"
    evidence.write_text("evidence", encoding="utf-8")
    no_draft = [
        "cra-receipt",
        "EVENT-1",
        "--root",
        str(root),
        "--stage",
        "early-warning",
        "--submitted-at",
        NOW,
        "--platform-ref",
        "operator-ref",
        "--csirt-endpoint-id",
        "de-csirt",
        "--evidence",
        str(evidence),
    ]
    assert main(no_draft) == 2
    assert (
        main(
            [
                "cra-draft",
                "EVENT-1",
                "--root",
                str(root),
                "--stage",
                "early-warning",
                "--generated-at",
                NOW,
            ]
        )
        == 0
    )
    assert main([*no_draft, "--draft-digest", "f" * 64]) == 2
    assert (
        main(
            [
                "cra-skip",
                "EVENT-1",
                "--root",
                str(root),
                "--stage",
                "notification",
                "--provided-in-stage",
                "early-warning",
                "--reason",
                "already provided",
                "--evidence-ref",
                "evidence/decision.json",
            ]
        )
        == 2
    )
    assert main([*no_draft, "--bound-at", NOW]) == 0
    receipt = CraRepository.open(root).event_state("EVENT-1").receipts[0]
    assert (
        main(
            [
                "cra-skip",
                "EVENT-1",
                "--root",
                str(root),
                "--stage",
                "notification",
                "--provided-in-stage",
                "early-warning",
                "--provided-in-receipt-digest",
                "f" * 64,
                "--reason",
                "already provided",
                "--evidence-ref",
                "evidence/decision.json",
            ]
        )
        == 2
    )
    assert receipt.receipt_digest != "f" * 64
    assert "repository audit error" in capsys.readouterr().err


def test_register_propagates_ambiguous_existing_event_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = worktree(tmp_path)
    assert main(bootstrap(root)) == 0
    assert main(register(root)) == 0
    store = CraRepository.open(root)
    first = store.current_event("EVENT-1")
    fork_one = SecurityEventRevision.build(
        event_key="EVENT-1",
        product_key="widget",
        track="vulnerability",
        aware_at=NOW,
        aware_evidence_ref="evidence/aware.json",
        exploitation_evidence=("evidence/exploit.json",),
        status="fixing",
        recorded_at="2026-07-20T00:01:00Z",
        previous_revision_digest=first.revision_digest,
    )
    fork_two = SecurityEventRevision.build(
        event_key="EVENT-1",
        product_key="widget",
        track="vulnerability",
        aware_at=NOW,
        aware_evidence_ref="evidence/aware.json",
        exploitation_evidence=("evidence/exploit.json",),
        status="closed",
        recorded_at="2026-07-20T00:02:00Z",
        previous_revision_digest=first.revision_digest,
    )
    directory = store.storage_root / "events/EVENT-1/revisions"
    for revision in (fork_one, fork_two):
        (directory / f"{revision.revision_digest}.json").write_text(
            revision.to_json(), encoding="utf-8"
        )
    assert main(register(root)) == 2
    assert "forked" in capsys.readouterr().err


def test_cli_rejects_unsafe_evidence_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = worktree(tmp_path)
    assert main(bootstrap(root)) == 0
    assert main(register(root)) == 0
    assert (
        main(
            [
                "cra-draft",
                "EVENT-1",
                "--root",
                str(root),
                "--stage",
                "early-warning",
                "--generated-at",
                NOW,
            ]
        )
        == 0
    )
    base = [
        "cra-receipt",
        "EVENT-1",
        "--root",
        str(root),
        "--stage",
        "early-warning",
        "--submitted-at",
        NOW,
        "--platform-ref",
        "operator-ref",
        "--csirt-endpoint-id",
        "de-csirt",
        "--evidence",
    ]
    directory = root / "directory"
    directory.mkdir()
    assert main([*base, str(directory)]) == 2
    large = root / "large"
    large.write_bytes(b"x")
    with large.open("r+b") as handle:
        handle.truncate(64 * 1024 * 1024 + 1)
    assert main([*base, str(large)]) == 2
    victim = root / "victim"
    victim.write_text("safe", encoding="utf-8")
    linked = root / "linked"
    linked.symlink_to(victim)
    assert main([*base, str(linked)]) == 2
    errors = capsys.readouterr().err
    assert "single-link regular" in errors
    assert "64 MiB" in errors


def test_static_cra_modules_import_no_network_clients() -> None:
    forbidden = {"aiohttp", "httpx", "requests", "socket", "urllib"}
    source_root = Path(__file__).parents[1] / "src/rigor_foundry"
    inspected = tuple(sorted(source_root.glob("cra_*.py")))
    assert inspected
    for path in inspected:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        assert imported.isdisjoint(forbidden), (
            f"network import in {path.name}: {imported & forbidden}"
        )


def test_status_json_is_machine_readable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = worktree(tmp_path)
    assert main(bootstrap(root)) == 0
    capsys.readouterr()
    assert main(["cra-status", "--root", str(root), "--now", NOW, "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"events": [], "now": NOW}
