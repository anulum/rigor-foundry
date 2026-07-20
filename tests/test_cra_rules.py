# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA probation rule integration tests
"""Exercise CR001–CR006 through real Git, ignored storage, scanner, and CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository, sample_tree_anchor

from rigor_foundry import scan_repository
from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_store import load_runs
from rigor_foundry.campaign_workflow import create_campaign, execute_campaign
from rigor_foundry.cli import main
from rigor_foundry.cra_policy import CraPolicy
from rigor_foundry.cra_rules import _started_stages, _timeline_candidates
from rigor_foundry.cra_store import CraEventState, CraRepository

NOW = "2026-07-20T10:00:00Z"


def cyclonedx() -> bytes:
    """Return one bounded top-level CycloneDX fixture."""
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [{"type": "application", "name": "widget", "version": "1.0"}],
        },
        sort_keys=True,
    ).encode()


def activate(repository: GitRepository, *, contact: bool = True) -> None:
    """Commit one explicit required CRA policy and tracked CVD policy."""
    policy = CraPolicy.build(
        applicability="required",
        rationale="Manufacturer-declared CRA audit scope for the widget.",
        product_key="widget",
        disclosure_policy_path="SECURITY.md",
        state_evidence_id="cra-state",
    )
    repository.write_text(
        "SECURITY.md",
        "# Vulnerability disclosure\n\nContact security@example.invalid.\n"
        if contact
        else "# Vulnerability disclosure\n\nUse the private reporting channel.\n",
    )
    repository.write_text("src/widget.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {
                "evidence_id": "cra-state",
                "path": ".rigor/cra",
                "capture": "directory-sha256",
            }
        ],
        cra=policy.to_dict(),
    )
    repository.commit()


def bootstrap(
    repository: GitRepository,
    *,
    support_months: int = 60,
    expected_use_months: int | None = None,
) -> None:
    """Create ignored CRA state through the public command boundary."""
    argv = [
        "cra-bootstrap",
        "--root",
        str(repository.root),
        "--product-key",
        "widget",
        "--product-name",
        "Widget",
        "--manufacturer-name",
        "Manufacturer",
        "--main-establishment-ms",
        "SK",
        "--establishment-basis",
        "decisions",
        "--csirt-endpoint-id",
        "CSIRT-SK",
        "--user-notice-channel",
        "security-page",
        "--support-period-months",
        str(support_months),
        "--registered-at",
        NOW,
    ]
    if expected_use_months is not None:
        argv.extend(
            (
                "--expected-use-months",
                str(expected_use_months),
                "--expected-use-evidence-ref",
                "evidence/expected-use.json",
            )
        )
    assert main(argv) == 0


def rule_ids(repository: GitRepository) -> tuple[str, ...]:
    """Return only CRA rule identifiers from one real repository scan."""
    return tuple(
        item.rule_id
        for item in scan_repository(repository.root).candidates
        if item.rule_id.startswith("CR")
    )


def register_fixed_event(repository: GitRepository) -> None:
    """Register one fix-available vulnerability with all clocks started."""
    repository.write_text("SECURITY/ADV-1.md", "# Fixed vulnerability advisory\n")
    assert (
        main(
            [
                "vuln-register",
                "EVENT-1",
                "--root",
                str(repository.root),
                "--product-key",
                "widget",
                "--track",
                "vulnerability",
                "--aware-at",
                NOW,
                "--aware-evidence",
                "evidence/aware.json",
                "--exploitation-evidence",
                "evidence/exploitation.json",
                "--status",
                "fix-available",
                "--corrective-measure-available-at",
                NOW,
                "--recorded-at",
                NOW,
            ]
        )
        == 0
    )


def test_absent_or_not_applicable_policy_is_fully_inert(tmp_path: Path) -> None:
    """No CRA scope means no state reads and no CR candidates."""
    legacy = GitRepository.create(tmp_path / "legacy")
    legacy.write_policy()
    legacy.write_text("src/widget.py", "VALUE = 1\n")
    legacy.commit()
    assert rule_ids(legacy) == ()

    inactive = GitRepository.create(tmp_path / "inactive")
    policy = CraPolicy.build(
        applicability="not-applicable",
        rationale="No in-scope product is declared.",
        product_key=None,
        disclosure_policy_path=None,
        state_evidence_id=None,
    )
    inactive.write_policy(cra=policy.to_dict())
    inactive.write_text("src/widget.py", "VALUE = 1\n")
    inactive.commit()
    assert rule_ids(inactive) == ()


def test_cr001_cr002_and_missing_state_are_explicit_candidates(tmp_path: Path) -> None:
    """Tracked policy/contact and unavailable state signals remain non-verdict candidates."""
    missing_state = GitRepository.create(tmp_path / "missing-state")
    activate(missing_state, contact=False)
    assert rule_ids(missing_state) == (
        "CR002-missing-security-contact",
        "CR004-untracked-reporting-timeline",
    )

    missing_policy = GitRepository.create(tmp_path / "missing-policy")
    activate(missing_policy)
    bootstrap(missing_policy)
    missing_policy.git_command("rm", "SECURITY.md")
    missing_policy.commit("remove disclosure policy")
    assert rule_ids(missing_policy) == ("CR001-missing-disclosure-policy",)


def test_cr003_and_cr005_use_exact_registration_and_repository_bindings(tmp_path: Path) -> None:
    """Short support and stale imported inventory signals use exact evidence digests."""
    repository = GitRepository.create(tmp_path / "repository")
    activate(repository)
    bootstrap(repository, support_months=36)
    sbom = repository.write_bytes("sbom-input.json", cyclonedx())
    assert (
        main(
            [
                "sbom-import",
                "--root",
                str(repository.root),
                "--product-key",
                "widget",
                "--file",
                str(sbom),
                "--format",
                "cyclonedx-1.5",
                "--source-tool",
                "fixture@1.0",
                "--source-evidence",
                "evidence/tool.json",
                "--coverage",
                "top-level-only",
                "--captured-at",
                NOW,
            ]
        )
        == 0
    )
    assert rule_ids(repository) == ("CR005-support-period-too-short",)
    repository.write_text("src/widget.py", "VALUE = 2\n")
    repository.commit("change tracked product")
    assert rule_ids(repository) == (
        "CR003-stale-component-inventory",
        "CR005-support-period-too-short",
    )

    justified = GitRepository.create(tmp_path / "justified")
    activate(justified)
    bootstrap(justified, support_months=36, expected_use_months=24)
    assert rule_ids(justified) == ()


def test_cr004_cr006_and_advisory_lifecycle_share_campaign_candidates(tmp_path: Path) -> None:
    """Started clocks and fixed status are report candidates; advisory evidence closes CR006."""
    repository = GitRepository.create(tmp_path / "repository")
    activate(repository)
    bootstrap(repository)
    register_fixed_event(repository)
    assert rule_ids(repository).count("CR004-untracked-reporting-timeline") == 3
    assert rule_ids(repository)[-1] == "CR006-fixed-vuln-without-advisory"

    assert (
        main(
            [
                "advisory-draft",
                "EVENT-1",
                "--root",
                str(repository.root),
                "--security-update-ref",
                "release/v1.2.3",
                "--advisory-path",
                "SECURITY/ADV-1.md",
                "--drafted-at",
                NOW,
            ]
        )
        == 0
    )
    assert "CR006-fixed-vuln-without-advisory" in rule_ids(repository)
    delay_evidence = repository.write_text(
        "delay-evidence.txt",
        "Operator-retained coordinated disclosure evidence.\n",
    )
    outside_evidence = tmp_path / "outside-delay-evidence.txt"
    outside_evidence.write_text("outside repository\n", encoding="utf-8")
    assert (
        main(
            [
                "advisory-delay",
                "EVENT-1",
                "--root",
                str(repository.root),
                "--reason",
                "Coordinated disclosure review remains open.",
                "--review-at",
                "2026-07-27T10:00:00Z",
                "--evidence",
                str(outside_evidence),
            ]
        )
        == 2
    )
    assert (
        main(
            [
                "advisory-delay",
                "EVENT-1",
                "--root",
                str(repository.root),
                "--reason",
                "Coordinated disclosure review remains open.",
                "--review-at",
                "2026-07-27T10:00:00Z",
                "--evidence",
                str(delay_evidence),
            ]
        )
        == 0
    )
    delayed = CraRepository.open(repository.root).advisory("EVENT-1")
    assert delayed is not None
    assert delayed.delay_evidence_path == "delay-evidence.txt"
    assert "CR006-fixed-vuln-without-advisory" not in rule_ids(repository)
    publication_evidence = repository.write_text(
        "publication-evidence.txt",
        "Operator-retained public advisory observation.\n",
    )
    assert (
        main(
            [
                "advisory-publish",
                "EVENT-1",
                "--root",
                str(repository.root),
                "--published-at",
                "2026-07-28T10:00:00Z",
                "--evidence",
                str(publication_evidence),
            ]
        )
        == 0
    )
    assert "CR006-fixed-vuln-without-advisory" not in rule_ids(repository)
    report = scan_repository(repository.root)
    assert report.rule_pack_version == "rigor-foundry/1.17.0"
    assert all(item.candidate_id for item in report.candidates if item.rule_id.startswith("CR"))

    campaign_path, campaign = create_campaign(
        repository.root,
        Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="CRA-WIDGET",
        campaign_id="cra-probation",
        actor="coordinator/one",
        expected_runs=1,
    )
    execute_campaign(
        campaign_path,
        run_id="reviewer-one",
        agent_identity="CRA-WIDGET/reviewer-one",
        session_identity="terminal/reviewer-one",
        inference_identity=InferenceIdentity.build(
            provider="provider.example",
            model="review-model-v1",
            model_family="review-model",
            operator="operator-one",
        ),
    )
    campaign_report = load_runs(campaign_path)[0].report
    assert campaign.ignored_inventory_digest == report.ignored_inventory_digest
    assert any(item.rule_id.startswith("CR") for item in campaign_report.candidates)
    delay_evidence.write_text("Mutated delay evidence.\n", encoding="utf-8")
    with pytest.raises(ValueError, match="delay evidence digest"):
        scan_repository(repository.root)
    delay_evidence.write_text(
        "Operator-retained coordinated disclosure evidence.\n",
        encoding="utf-8",
    )
    publication_evidence.write_text("Mutated publication evidence.\n", encoding="utf-8")
    with pytest.raises(ValueError, match="publication evidence digest"):
        scan_repository(repository.root)
    publication_evidence.write_text(
        "Operator-retained public advisory observation.\n",
        encoding="utf-8",
    )
    repository.write_text("SECURITY/ADV-1.md", "# Mutated advisory bytes\n")
    with pytest.raises(ValueError, match="advisory digest"):
        scan_repository(repository.root)


def test_scan_rejects_cra_state_change_between_inventory_and_locked_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real state mutation after the first digest cannot yield a mixed CRA report."""
    repository = GitRepository.create(tmp_path / "repository")
    activate(repository)
    bootstrap(repository)
    changing = repository.write_text(".rigor/cra/operator-note.txt", "before\n")
    lock_path = repository.root / ".rigor/cra/.lock"
    real_open = os.open
    mutated = False

    def mutate_before_lock(
        path: os.PathLike[str] | str | bytes | int,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal mutated
        if (
            not mutated
            and dir_fd is None
            and not isinstance(path, int)
            and os.path.abspath(os.fsdecode(path)) == os.path.abspath(lock_path)
        ):
            changing.write_text("after\n", encoding="utf-8")
            mutated = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", mutate_before_lock)
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        frozenset(
            mutate_before_lock if function is real_open else function
            for function in os.supports_dir_fd
        ),
    )
    with pytest.raises(RuntimeError, match="CRA state changed"):
        scan_repository(repository.root)
    assert mutated


def test_scan_rejects_tracked_change_between_inventory_and_cra_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tracked mutation during locked CRA replay cannot produce a mixed report."""
    repository = GitRepository.create(tmp_path / "repository")
    activate(repository)
    bootstrap(repository)
    disclosure = repository.root / "SECURITY.md"
    lock_path = repository.root / ".rigor/cra/.lock"
    real_open = os.open
    mutated = False

    def mutate_tracked_before_lock(
        path: os.PathLike[str] | str | bytes | int,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal mutated
        if (
            not mutated
            and dir_fd is None
            and not isinstance(path, int)
            and os.path.abspath(os.fsdecode(path)) == os.path.abspath(lock_path)
        ):
            disclosure.write_text(
                "# Vulnerability disclosure\n\nContact changed@example.invalid.\n",
                encoding="utf-8",
            )
            mutated = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", mutate_tracked_before_lock)
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        frozenset(
            mutate_tracked_before_lock if function is real_open else function
            for function in os.supports_dir_fd
        ),
    )
    with pytest.raises(RuntimeError, match="tracked repository state changed"):
        scan_repository(repository.root)
    assert mutated


def test_timeline_rule_branches_preserve_product_stage_and_track_boundaries() -> None:
    """Pure timeline selection ignores other products and respects covered/started stages."""
    notification = SimpleNamespace(stage="notification")
    final_report = SimpleNamespace(stage="final-report")
    incident = SimpleNamespace(
        product_key="widget",
        event_key="INCIDENT-1",
        revision_digest="1" * 64,
        track="incident",
        status="triaged",
        corrective_measure_available_at=None,
        intermediate_due_at="2026-07-21T10:00:00Z",
    )
    incident_state = cast(
        CraEventState,
        SimpleNamespace(
            event=incident,
            drafts=(final_report,),
            receipts=(notification,),
            skips=(),
        ),
    )
    assert _started_stages(incident_state) == (
        "early-warning",
        "notification",
        "final-report",
        "intermediate",
    )
    skipped_incident = cast(
        CraEventState,
        SimpleNamespace(
            event=incident,
            drafts=(),
            receipts=(),
            skips=(notification,),
        ),
    )
    assert "final-report" in _started_stages(skipped_incident)
    other = cast(
        CraEventState,
        SimpleNamespace(
            event=SimpleNamespace(
                product_key="other",
                event_key="OTHER-1",
                revision_digest="2" * 64,
                track="vulnerability",
                status="triaged",
                corrective_measure_available_at=None,
                intermediate_due_at=None,
            ),
            drafts=(),
            receipts=(),
            skips=(),
        ),
    )

    class FakeRepository:
        def event_keys(self) -> tuple[str, ...]:
            return ("OTHER-1", "INCIDENT-1")

        def event_state(self, event_key: str) -> CraEventState:
            return other if event_key == "OTHER-1" else incident_state

        def advisory(self, _event_key: str) -> None:
            return None

    candidates = _timeline_candidates(
        cast(CraRepository, FakeRepository()),
        sample_tree_anchor("rigor-foundry-policy.json"),
        "widget",
    )
    assert {item.symbol for item in candidates} == {
        "INCIDENT-1:early-warning",
        "INCIDENT-1:intermediate",
    }


def test_corrupt_component_inventory_never_degrades_to_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the exact no-inventory state is tolerated; all corruption fails closed."""
    repository = GitRepository.create(tmp_path / "repository")
    activate(repository)
    bootstrap(repository)

    def corrupt_inventory(_self: object, _product_key: str) -> None:
        raise ValueError("corrupt component inventory")

    monkeypatch.setattr(
        "rigor_foundry.cra_rules.CraP1Store.current_inventory",
        corrupt_inventory,
    )
    with pytest.raises(ValueError, match="corrupt component inventory"):
        scan_repository(repository.root)
