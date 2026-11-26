# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — lockfile integrity rules over a real repository
"""Witness the lockfile rules through a real repository scan, its candidates and anchors."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from lockfile_repository_support import build_lockfile_repository
from repository_audit_git_repository import GitRepository

from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.lockfile_integrity import (
    FINDING_RULE_IDS,
    RULE_GUIDANCE,
    assess_lockfiles,
    berry_registry_declaration,
    npm_registry_declaration,
    scan_lockfile_integrity,
    yarn1_registry_declaration,
)
from rigor_foundry.lockfile_npmrc import DEFAULT_NPM_REGISTRY, UNKNOWN_NPM_REGISTRY
from rigor_foundry.lockfile_yarnrc import YarnRegistryDeclaration
from rigor_foundry.rules import RULES_BY_ID
from rigor_foundry.scanner import scan_repository


def test_every_rule_id_is_registered_with_guidance_in_the_lockfile_pack() -> None:
    """Each finding a parser can emit maps to a registered 1.20.0 rule with guidance."""
    rule_ids = {*FINDING_RULE_IDS.values(), "SC003-lockfile-refused"}
    assert set(RULE_GUIDANCE) == rule_ids
    for rule_id in rule_ids:
        rule = RULES_BY_ID[rule_id]
        assert (rule.category, rule.introduced) == ("supply-chain", "rigor-foundry/1.20.0")
    assert "manifest-drift" not in FINDING_RULE_IDS


def test_a_real_scan_raises_one_candidate_per_recorded_finding_and_refusal(tmp_path: Path) -> None:
    """Refused files and the findings of recorded entries become anchored candidates."""
    repository = build_lockfile_repository(tmp_path / "repository")
    report = scan_repository(repository.root)
    lockfile = [
        c
        for c in report.candidates
        if c.rule_id.split("-", 1)[0]
        in {"SC003", "SC004", "SC005", "SC006", "SC007", "SC008", "SC009", "SC010", "SC012"}
    ]
    counts = Counter(candidate.rule_id for candidate in lockfile)
    assert counts == {
        "SC003-lockfile-refused": 5,
        "SC004-lockfile-missing-digest": 2,
        "SC005-lockfile-weak-digest": 1,
        "SC006-lockfile-malformed-digest": 1,
        "SC007-lockfile-floating-ref": 1,
        "SC008-lockfile-origin-mismatch": 1,
        "SC009-lockfile-origin-unknown": 3,
        "SC010-lockfile-path-escape": 1,
        "SC012-lockfile-unknown-form": 1,
    }
    confidence = {candidate.rule_id: candidate.confidence for candidate in lockfile}
    assert confidence["SC009-lockfile-origin-unknown"] == "medium"
    assert confidence["SC012-lockfile-unknown-form"] == "medium"
    assert confidence["SC004-lockfile-missing-digest"] == "high"
    assert all(candidate.category == "supply-chain" for candidate in lockfile)


def test_each_finding_candidate_points_at_its_entry_line(tmp_path: Path) -> None:
    """A finding's anchor line is the entry's line, and inherited entries raise none."""
    repository = build_lockfile_repository(tmp_path / "repository")
    inventory = load_git_inventory(repository.root)
    results = {result.path: result for result in assess_lockfiles(inventory)}
    web = results["web/package-lock.json"]
    lines = {entry.key: entry.line for entry in web.entries}
    candidates = [c for c in scan_lockfile_integrity(inventory) if c.anchor.path == web.path]
    by_rule = {candidate.rule_id: candidate for candidate in candidates}
    assert by_rule["SC004-lockfile-missing-digest"].anchor.line_start == lines["node_modules/ms"]
    assert (
        by_rule["SC007-lockfile-floating-ref"].anchor.line_start == lines["node_modules/is-number"]
    )
    assert "finding=missing-digest" in by_rule["SC004-lockfile-missing-digest"].evidence
    assert by_rule["SC008-lockfile-origin-mismatch"].evidence.endswith("origin=evil.example")
    assert by_rule["SC010-lockfile-path-escape"].evidence.endswith("origin=none")
    inherited = [entry for entry in web.entries if entry.inherited_from is not None]
    assert [entry.entry_class for entry in inherited] == ["unpinned"]
    assert all(c.anchor.line_start != inherited[0].line for c in candidates)


def test_a_refused_file_is_anchored_by_blob_or_by_tree_when_it_has_no_text(tmp_path: Path) -> None:
    """Readable refused files anchor at line 1; binary and empty ones anchor at the tree."""
    repository = build_lockfile_repository(tmp_path / "repository")
    inventory = load_git_inventory(repository.root)
    refused = {
        candidate.anchor.path: candidate
        for candidate in scan_lockfile_integrity(inventory)
        if candidate.rule_id == "SC003-lockfile-refused"
    }
    assert refused["bin/package-lock.json"].anchor.kind == "repository-tree"
    assert refused["empty/yarn.lock"].anchor.kind == "repository-tree"
    assert refused["tools/yarn.lock"].anchor.kind == "tracked-blob"
    assert refused["old/package-lock.json"].anchor.line_start == 1
    assert "reason=unreadable" in refused["bin/package-lock.json"].evidence
    assert "kind=unknown; reason=ambiguous-yarn-lock" in refused["tools/yarn.lock"].evidence
    assert "kind=cargo; reason=unsupported-file-kind" in refused["crates/Cargo.lock"].evidence


@pytest.mark.parametrize(
    ("files", "untracked", "lock_path", "expected"),
    [
        ({}, {}, "web/package-lock.json", "default"),
        (
            {"web/.npmrc": "registry=https://npm.internal.example/\n"},
            {},
            "web/package-lock.json",
            "internal",
        ),
        (
            {".npmrc": "registry=https://npm.internal.example/\n"},
            {},
            "web/package-lock.json",
            "internal",
        ),
        (
            {
                ".npmrc": "registry=https://npm.internal.example/\n",
                "web/.npmrc": "save-exact=true\n",
            },
            {},
            "web/package-lock.json",
            "default",
        ),
        (
            {},
            {"web/.npmrc": "registry=https://npm.internal.example/\n"},
            "web/package-lock.json",
            "unknown",
        ),
        (
            {},
            {".npmrc": "registry=https://npm.internal.example/\n"},
            "package-lock.json",
            "unknown",
        ),
    ],
)
def test_the_declared_registry_is_beside_the_lockfile_then_at_the_root(
    tmp_path: Path,
    files: dict[str, str],
    untracked: dict[str, str],
    lock_path: str,
    expected: str,
) -> None:
    """A tracked ``.npmrc`` beside the lockfile wins; an untracked one is never trusted.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    files : dict[str, str]
        Tracked files besides the lockfile.
    untracked : dict[str, str]
        Files present but not committed.
    lock_path : str
        The lockfile path.
    expected : str
        ``default``, ``internal`` or ``unknown``.
    """
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(lock_path, '{"lockfileVersion": 3, "packages": {}}\n')
    for path, text in files.items():
        repository.write_text(path, text)
    repository.commit()
    for path, text in untracked.items():
        repository.write_text(path, text)
    declaration = npm_registry_declaration(load_git_inventory(repository.root), lock_path)
    if expected == "default":
        assert declaration == DEFAULT_NPM_REGISTRY
    elif expected == "unknown":
        assert declaration == UNKNOWN_NPM_REGISTRY
    else:
        assert declaration.registry_host == "npm.internal.example"


def test_a_tracked_npmrc_that_is_not_text_makes_the_origin_unknown(tmp_path: Path) -> None:
    """An unreadable tracked ``.npmrc`` is never read as the default."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("package-lock.json", '{"lockfileVersion": 3, "packages": {}}\n')
    repository.write_bytes(".npmrc", b"registry=\0\n")
    repository.commit()
    inventory = load_git_inventory(repository.root)
    assert npm_registry_declaration(inventory, "package-lock.json") == UNKNOWN_NPM_REGISTRY


def test_a_repository_without_lockfiles_has_no_results(tmp_path: Path) -> None:
    """No lockfile, no result and no candidate."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/app.py", "VALUE = 1\n")
    repository.commit()
    inventory = load_git_inventory(repository.root)
    assert assess_lockfiles(inventory) == ()
    assert scan_lockfile_integrity(inventory) == ()


@pytest.mark.parametrize(
    ("files", "untracked", "expected"),
    [
        ({}, {}, "default"),
        ({".yarnrc": 'registry "https://npm.internal.example/"\n'}, {}, "internal"),
        ({"web/.yarnrc": 'registry "https://npm.internal.example/"\n'}, {}, "internal"),
        ({".npmrc": "registry=https://npm.internal.example/\n"}, {}, "internal"),
        ({".yarnrc.yml": 'npmRegistryServer: "https://npm.internal.example/"\n'}, {}, "default"),
        ({}, {"web/.yarnrc": 'registry "https://npm.internal.example/"\n'}, "unknown"),
        ({".yarnrc": 'registry "${REGISTRY}"\n'}, {}, "unknown"),
    ],
)
def test_the_yarn1_declaration_reads_npmrc_and_yarnrc_but_not_yarnrc_yml(
    tmp_path: Path, files: dict[str, str], untracked: dict[str, str], expected: str
) -> None:
    """Yarn 1 reads ``.npmrc`` and ``.yarnrc`` beside the lockfile, then at the root.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    files : dict[str, str]
        Tracked configuration files.
    untracked : dict[str, str]
        Files present but not committed.
    expected : str
        ``default``, ``internal`` or ``unknown``.
    """
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("web/yarn.lock", "# yarn lockfile v1\n")
    for path, text in files.items():
        repository.write_text(path, text)
    repository.commit()
    for path, text in untracked.items():
        repository.write_text(path, text)
    declaration = yarn1_registry_declaration(load_git_inventory(repository.root), "web/yarn.lock")
    if expected == "unknown":
        assert not declaration.known
    else:
        assert declaration.known
        host = None if expected == "default" else "npm.internal.example"
        assert declaration.declared_host("left-pad") == host


def test_a_yarn1_lockfile_is_classified_in_a_real_scan(tmp_path: Path) -> None:
    """The real Yarn 1 lockfile at the root is classified, and its archive raises one candidate."""
    repository = build_lockfile_repository(tmp_path / "repository")
    inventory = load_git_inventory(repository.root)
    yarn = next(result for result in assess_lockfiles(inventory) if result.path == "yarn.lock")
    assert (yarn.kind, yarn.format_version, yarn.status, len(yarn.entries)) == (
        "yarn-v1",
        "1",
        "classified",
        60,
    )
    candidates = [c for c in scan_lockfile_integrity(inventory) if c.anchor.path == "yarn.lock"]
    assert [c.rule_id for c in candidates] == ["SC004-lockfile-missing-digest"]
    assert candidates[0].evidence.endswith("origin=codeload.github.com")


def _yarn_declaration(
    tmp_path: Path, tracked: dict[str, str], untracked: dict[str, str]
) -> YarnRegistryDeclaration:
    """Build a repository with a lockfile at ``web/app/yarn.lock`` and read its Yarn 1 declaration."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("web/app/yarn.lock", "# yarn lockfile v1\n")
    for path, text in tracked.items():
        repository.write_text(path, text)
    repository.commit()
    for path, text in untracked.items():
        repository.write_text(path, text)
    return yarn1_registry_declaration(load_git_inventory(repository.root), "web/app/yarn.lock")


def test_a_scoped_only_yarnrc_beside_the_lockfile_keeps_the_roots_registry(tmp_path: Path) -> None:
    """Yarn 1 merges per key, so a nearer scoped line does not hide the root's registry.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    """
    declaration = _yarn_declaration(
        tmp_path,
        {
            ".yarnrc": 'registry "https://npm.internal.example/"\n',
            "web/app/.yarnrc": '"@acme:registry" "https://acme.example/"\n',
        },
        {},
    )
    assert declaration.declared_host("left-pad") == "npm.internal.example"
    assert declaration.declared_host("@acme/tool") == "acme.example"
    assert declaration.origin_finding("left-pad", "registry.yarnpkg.com") == "origin-mismatch"


def test_an_intermediate_yarnrc_decides_and_the_nearest_key_wins(tmp_path: Path) -> None:
    """A tracked ``.yarnrc`` between the root and the lockfile is read, and nearer keys win.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    """
    intermediate = _yarn_declaration(
        tmp_path / "one", {"web/.yarnrc": 'registry "https://npm.internal.example/"\n'}, {}
    )
    assert intermediate.declared_host("left-pad") == "npm.internal.example"
    nearest = _yarn_declaration(
        tmp_path / "two",
        {
            ".npmrc": "registry=https://root.example/\n",
            "web/.npmrc": "registry=https://web.example/\n",
            "web/app/.npmrc": "save-exact=true\n",
        },
        {},
    )
    assert nearest.declared_host("left-pad") == "web.example"


@pytest.mark.parametrize("name", [".yarnrc", ".npmrc"])
def test_an_untracked_intermediate_file_makes_the_origin_unknown(
    tmp_path: Path, name: str
) -> None:
    """An untracked configuration file at any level between the root and the lockfile is uncertain.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    name : str
        The configuration file name.
    """
    declaration = _yarn_declaration(tmp_path, {}, {f"web/{name}": "registry=x\n"})
    assert not declaration.known
    assert declaration.origin_finding("left-pad", "registry.yarnpkg.com") == "origin-unknown"


def test_the_berry_declaration_merges_yarnrc_yml_root_down_per_scope(tmp_path: Path) -> None:
    """Every tracked ``.yarnrc.yml`` on the path is merged, scopes per scope, nearest winning.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    """
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("web/app/yarn.lock", "__metadata:\n  version: 10\n  cacheKey: 10c0\n")
    repository.write_text(
        ".yarnrc.yml",
        'npmRegistryServer: "https://root.example"\nnpmScopes:\n  a:\n    npmRegistryServer: "https://a.example"\n',
    )
    repository.write_text(
        "web/.yarnrc.yml",
        'npmScopes:\n  b:\n    npmRegistryServer: "https://b.example"\nchecksumBehavior: ignore\n',
    )
    repository.commit()
    inventory = load_git_inventory(repository.root)
    declaration = berry_registry_declaration(inventory, "web/app/yarn.lock")
    assert declaration.declared_host("@a/x") == "a.example"
    assert declaration.declared_host("@b/x") == "b.example"
    assert declaration.declared_host("left-pad") == "root.example"
    assert declaration.config.checksum_behavior == "ignore"
    result = next(r for r in assess_lockfiles(inventory) if r.path == "web/app/yarn.lock")
    assert (result.kind, result.status, result.checksum_behavior) == (
        "yarn-berry",
        "classified",
        "ignore",
    )
    repository.write_text("web/app/.yarnrc.yml", "npmRegistryServer: x\n")
    assert not berry_registry_declaration(
        load_git_inventory(repository.root), "web/app/yarn.lock"
    ).known


@pytest.mark.parametrize("text", [b"\0", b'npmRegistryServer: "${R}"\n'])
def test_an_unreadable_or_uncertain_yarnrc_yml_makes_the_origin_unknown(
    tmp_path: Path, text: bytes
) -> None:
    """A tracked ``.yarnrc.yml`` that is not text, or is uncertain, is never read as the default.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    text : bytes
        The configuration bytes.
    """
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("yarn.lock", "__metadata:\n  version: 10\n  cacheKey: 10c0\n")
    repository.write_bytes(".yarnrc.yml", text)
    repository.commit()
    declaration = berry_registry_declaration(load_git_inventory(repository.root), "yarn.lock")
    assert not declaration.known


def test_a_checksum_behaviour_that_keeps_verification_is_not_recorded(tmp_path: Path) -> None:
    """Only ``ignore`` and ``update`` are recorded; ``throw`` is the default and stays silent."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("yarn.lock", "__metadata:\n  version: 10\n  cacheKey: 10c0\n")
    repository.write_text(".yarnrc.yml", "checksumBehavior: throw\n")
    repository.commit()
    result = assess_lockfiles(load_git_inventory(repository.root))[0]
    assert (result.status, result.checksum_behavior) == ("classified", None)
