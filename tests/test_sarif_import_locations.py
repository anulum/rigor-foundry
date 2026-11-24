# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — tracked-only SARIF import location tests on real repositories
"""Verify that imported results anchor only to exact clean tracked blobs of a real repository."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.git_inventory import GitInventory, load_git_inventory
from rigor_foundry.rules import RULES_BY_ID, rule_pack_digest
from rigor_foundry.sarif import report_sarif
from rigor_foundry.sarif_import_document import parse_sarif_document
from rigor_foundry.sarif_import_locations import LocationRoots, RunLocations, route_result
from rigor_foundry.sarif_import_records import (
    MAX_SNIPPET_BYTES,
    ImportedCandidate,
    ImportObservation,
    ImportSkip,
)
from rigor_foundry.sarif_import_rules import RunRules
from rigor_foundry.scanner import scan_repository

ROOT_ID = "%SRCROOT%"


@dataclass(frozen=True)
class Scanned:
    """A real repository, its inventory, and the SARIF that RigorFoundry exported for it."""

    repository: GitRepository
    inventory: GitInventory
    sarif: str
    run: dict[str, Any]
    rules: RunRules


def _scan(root: Path) -> Scanned:
    """Commit a small real repository, scan it, and export its SARIF."""
    repository = GitRepository.create(root)
    repository.write_text("src/pkg/core.py", "VALUE = 1\nOTHER = 2\n")
    repository.write_text(
        "src/pkg/über file.py",
        "import os  # noqa: F401\nVALUE = os.sep\nOTHER = 2  # type: ignore\n",
    )
    repository.write_text("tests/test_core.py", "from pkg.core import VALUE  # noqa: F401\n")
    repository.write_policy()
    repository.commit()
    report = scan_repository(repository.root, Path("rigor-foundry-policy.json"))
    sarif = report_sarif(report)
    (run,) = parse_sarif_document(sarif.encode()).runs
    rules = RunRules.build("semgrep", run)
    return Scanned(repository, load_git_inventory(repository.root), sarif, run, rules)


@pytest.fixture(scope="module")
def scanned(tmp_path_factory: pytest.TempPathFactory) -> Scanned:
    """Return one shared real scanned repository.

    Parameters
    ----------
    tmp_path_factory : pytest.TempPathFactory
        Owned module-scoped directory allocation.

    Returns
    -------
    Scanned
        The repository, its inventory and its exported SARIF.
    """
    return _scan(tmp_path_factory.mktemp("locations") / "repository")


def _roots(scanned: Scanned, checkout: str | None = None) -> LocationRoots:
    """Declare the scanned checkout, or another producer-side path, as the root."""
    return LocationRoots(checkout or scanned.repository.root.as_posix(), frozenset({ROOT_ID}))


def _route(
    scanned: Scanned,
    result: dict[str, Any],
    run: dict[str, Any] | None = None,
    roots: LocationRoots | None = None,
    inventory: GitInventory | None = None,
) -> ImportedCandidate | ImportObservation | ImportSkip:
    """Route one result of the real run, or of a variant of it."""
    locations = RunLocations.build(
        scanned.run if run is None else run,
        scanned.inventory if inventory is None else inventory,
        roots or _roots(scanned),
    )
    return route_result("semgrep", result, scanned.rules, locations, run_index=0, result_index=0)


def _at(scanned: Scanned, artifact: dict[str, Any], **region: Any) -> dict[str, Any]:
    """Return the real exported result on ``src/pkg/core.py`` pointed at another location."""
    result: dict[str, Any] = copy.deepcopy(
        next(
            item
            for item in scanned.run["results"]
            if item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "src/pkg/core.py"
        )
    )
    physical = result["locations"][0]["physicalLocation"]
    physical["artifactLocation"] = artifact
    physical["region"] = region or {"startLine": 2}
    return result


def _anchored(outcome: object) -> TrackedBlobAnchor:
    """Return the anchor of an imported candidate, or fail."""
    assert isinstance(outcome, ImportedCandidate), outcome
    return outcome.anchor


def _skip(outcome: object) -> str:
    """Return the reason of a skip, or fail."""
    assert isinstance(outcome, ImportSkip), outcome
    return outcome.reason


def test_our_own_exported_sarif_anchors_back_to_the_scanned_blobs(scanned: Scanned) -> None:
    """Every exported result re-anchors to the scanner's own path, lines and blob."""
    files = {item.path: item for item in scanned.inventory.files}
    report = scan_repository(scanned.repository.root, Path("rigor-foundry-policy.json"))
    digest, registered = rule_pack_digest(), dict(RULES_BY_ID)
    outcomes = [
        route_result(
            "semgrep",
            result,
            scanned.rules,
            RunLocations.build(scanned.run, scanned.inventory, _roots(scanned)),
            run_index=0,
            result_index=index,
        )
        for index, result in enumerate(scanned.run["results"])
    ]
    assert len(outcomes) == len(report.candidates) == 6
    for candidate, outcome in zip(report.candidates, outcomes, strict=True):
        anchor = _anchored(outcome)
        item = files[candidate.anchor.path]
        assert (anchor.path, anchor.line_start, anchor.line_end) == (
            candidate.anchor.path,
            candidate.anchor.line_start,
            candidate.anchor.line_end,
        )
        assert (anchor.blob_oid, anchor.content_sha256) == (
            item.scanned_blob_id,
            item.content_digest,
        )
        assert anchor.errors(scanned.inventory) == ()
    assert any(_anchored(item).path == "src/pkg/über file.py" for item in outcomes)
    assert report_sarif(report) == scanned.sarif
    assert rule_pack_digest() == digest and dict(RULES_BY_ID) == registered


def test_every_accepted_uri_form_resolves_to_the_same_tracked_blob(scanned: Scanned) -> None:
    """Relative, base-relative, base-chained, absolute and producer-side forms agree exactly."""
    root = quote(scanned.repository.root.as_posix())
    run = copy.deepcopy(scanned.run)
    run["originalUriBaseIds"] = {
        "PKG": {"uri": "pkg/", "uriBaseId": "SRC"},
        "SRC": {"uri": "src/", "uriBaseId": ROOT_ID},
        "ROOTPATH": {"uri": f"file://{root}/"},
        ROOT_ID: {"uri": "file:///ignored/for/a/declared/root/"},
    }
    run["artifacts"] = [{"location": {"uri": "src/pkg/core.py"}}]
    expected = _anchored(_route(scanned, _at(scanned, {"uri": "src/pkg/core.py"})))
    for artifact in (
        {"uri": "./src/pkg/../pkg/core.py"},
        {"uri": "src/pkg/core.py", "uriBaseId": ROOT_ID},
        {"uri": "core.py", "uriBaseId": "PKG"},
        {"uri": "src/pkg/core.py", "uriBaseId": "ROOTPATH"},
        {"uri": f"file://{root}/src/pkg/core.py"},
        {"uri": f"file:{root}/src/pkg/%63ore.py"},
        {"index": 0},
        {"uri": "src/pkg/core.py", "index": 0},
    ):
        assert _anchored(_route(scanned, _at(scanned, artifact), run)) == expected, artifact
    producer_side = _roots(scanned, "/home/runner/work/repo/repo")
    ci_uri = {"uri": "file:///home/runner/work/repo/repo/src/pkg/core.py"}
    assert _anchored(_route(scanned, _at(scanned, ci_uri), roots=producer_side)) == expected
    assert (expected.path, expected.line_start, expected.line_end) == ("src/pkg/core.py", 2, 2)


def test_a_sibling_directory_sharing_the_root_prefix_is_outside_the_checkout(
    scanned: Scanned,
) -> None:
    """``/work/repo-evil`` is not under ``/work/repo``, as a file URI or as a file base."""
    roots = _roots(scanned, "/work/repo")
    inside = _at(scanned, {"uri": "file:///work/repo/src/pkg/core.py"})
    assert _anchored(_route(scanned, inside, roots=roots)).path == "src/pkg/core.py"
    for uri in (
        "file:///work/repo-evil/src/pkg/core.py",
        "file:///work/repo/../repo-evil/src/pkg/core.py",
        "file:///work/reposrc/pkg/core.py",
        "file:///work/src/pkg/core.py",
    ):
        assert _skip(_route(scanned, _at(scanned, {"uri": uri}), roots=roots)) == (
            "outside-checkout-root"
        ), uri
    for base in ("file:///work/repo-evil/", "file:///work/"):
        run = {**scanned.run, "originalUriBaseIds": {"EVIL": {"uri": base}}}
        result = _at(scanned, {"uri": "src/pkg/core.py", "uriBaseId": "EVIL"})
        assert _skip(_route(scanned, result, run, roots)) == "base-chain-not-at-root", base


REFUSED_URIS: tuple[tuple[dict[str, Any], str], ...] = (
    ({"uri": "file:///etc/passwd"}, "outside-checkout-root"),
    ({"uri": "../outside.py"}, "dot-dot-segment"),
    ({"uri": "%2e%2e/outside.py"}, "dot-dot-segment"),
    ({"uri": "%252e%252e/outside.py"}, "untracked-path"),
    ({"uri": "src/../../outside.py"}, "dot-dot-segment"),
    ({"uri": "file:///../etc/passwd"}, "dot-dot-segment"),
    ({"uri": "src\\pkg\\core.py"}, "forbidden-path-character"),
    ({"uri": "src%5Cpkg%5Ccore.py"}, "forbidden-path-character"),
    ({"uri": "src/pkg/core.py%00"}, "forbidden-path-character"),
    ({"uri": "src/pkg/core.py%0A"}, "forbidden-path-character"),
    ({"uri": "src/pkg/%FF.py"}, "invalid-percent-encoding"),
    ({"uri": "src/pkg/core.py?x=1"}, "uri-query-or-fragment"),
    ({"uri": "src/pkg/core.py#L2"}, "uri-query-or-fragment"),
    ({"uri": "C:/src/pkg/core.py"}, "drive-letter"),
    ({"uri": "c%3A/src/pkg/core.py"}, "drive-letter"),
    ({"uri": "file:///C:/src/pkg/core.py"}, "drive-letter"),
    ({"uri": "https://example.invalid/src/pkg/core.py"}, "unsupported-scheme"),
    ({"uri": "file://host/src/pkg/core.py"}, "malformed-file-uri"),
    ({"uri": "file://"}, "malformed-file-uri"),
    ({"uri": "file:src/pkg/core.py"}, "malformed-file-uri"),
    ({"uri": "/src/pkg/core.py"}, "absolute-path-reference"),
    ({"uri": "%2Fsrc/pkg/core.py"}, "absolute-path-reference"),
    ({"uri": "file:///etc/passwd", "uriBaseId": ROOT_ID}, "absolute-uri-with-base"),
    ({"uri": "src/pkg/core.py", "uriBaseId": "NOPE"}, "unknown-uri-base-id"),
    ({"uri": "src/pkg/absent.py"}, "untracked-path"),
    ({"uri": "SRC/pkg/core.py"}, "untracked-path"),
    ({"uri": "src/pkg/Core.py"}, "untracked-path"),
    ({"uri": "src//pkg/core.py"}, "untracked-path"),
    ({"uri": "."}, "untracked-path"),
)


@pytest.mark.parametrize(
    ("artifact", "reason"), REFUSED_URIS, ids=[r[0]["uri"] for r in REFUSED_URIS]
)
def test_a_uri_that_is_not_exactly_one_tracked_path_is_skipped(
    scanned: Scanned, artifact: dict[str, Any], reason: str
) -> None:
    """Outside, climbing, encoded, backslashed, foreign, unknown, untracked or case-only URIs.

    Parameters
    ----------
    scanned : Scanned
        The real scanned repository.
    artifact : dict[str, Any]
        The refused artifact location.
    reason : str
        The skip reason.
    """
    assert _skip(_route(scanned, _at(scanned, artifact))) == reason


BASES: tuple[tuple[object, str], ...] = (
    ({"SUB": {"uri": "src/"}}, "base-chain-not-at-root"),
    ({"SUB": {"uriBaseId": ROOT_ID}}, "base-chain-not-at-root"),
    ({"SUB": {"uri": "file:///elsewhere/"}}, "base-chain-not-at-root"),
    (
        {"SUB": {"uri": "src/", "uriBaseId": "LOOP"}, "LOOP": {"uri": "x/", "uriBaseId": "SUB"}},
        "uri-base-cycle",
    ),
    ({"SUB": {"uri": "src", "uriBaseId": ROOT_ID}}, "malformed-uri-base"),
    ({"SUB": {"uri": None, "uriBaseId": ROOT_ID}}, "malformed-uri-base"),
    ({"SUB": {"uri": "src/", "uriBaseId": 7}}, "malformed-uri-base"),
    ({"SUB": {"uri": "file:///x/", "uriBaseId": ROOT_ID}}, "malformed-uri-base"),
    ({"SUB": "src/"}, "malformed-uri-base"),
    ([], "malformed-uri-base"),
    ({"SUB": {"uri": "../", "uriBaseId": ROOT_ID}}, "dot-dot-segment"),
)


@pytest.mark.parametrize(("bases", "reason"), BASES)
def test_a_base_chain_that_does_not_end_at_the_declared_root_is_skipped(
    scanned: Scanned, bases: object, reason: str
) -> None:
    """A base without a root, a cycle, a malformed entry or a climbing base is refused.

    Parameters
    ----------
    scanned : Scanned
        The real scanned repository.
    bases : object
        The run's ``originalUriBaseIds``.
    reason : str
        The skip reason.
    """
    run = {**scanned.run, "originalUriBaseIds": bases}
    result = _at(scanned, {"uri": "pkg/core.py", "uriBaseId": "SUB"})
    assert _skip(_route(scanned, result, run)) == reason


ARTIFACTS: tuple[tuple[object, dict[str, Any], str], ...] = (
    ([{"location": {"uri": "src/pkg/core.py"}}], {"index": 1}, "artifact-index-out-of-range"),
    ([{"location": {"uri": "src/pkg/core.py"}}], {"index": -2}, "artifact-index-out-of-range"),
    ([{"location": {"uri": "src/pkg/core.py"}}], {"index": -1}, "malformed-locations"),
    ([{"location": {"uri": "src/pkg/core.py"}}], {"index": "0"}, "malformed-locations"),
    (
        [{"location": {"uri": "src/pkg/core.py"}}],
        {"uri": "tests/test_core.py", "index": 0},
        "artifact-index-mismatch",
    ),
    (
        [{"location": {"uri": "src/pkg/core.py", "uriBaseId": ROOT_ID}}],
        {"uri": "src/pkg/core.py", "index": 0},
        "artifact-index-mismatch",
    ),
    ([{"location": {"uri": "src/pkg/core.py"}}], {"index": True}, "malformed-locations"),
    ({}, {"index": 0}, "malformed-locations"),
    (["src/pkg/core.py"], {"index": 0}, "malformed-locations"),
    ([{"location": {"uri": 3}}], {"index": 0}, "malformed-locations"),
    ([], {"uriBaseId": ROOT_ID}, "malformed-locations"),
    ([], {"uri": None}, "malformed-locations"),
    ([], {"uri": "src/pkg/core.py", "uriBaseId": None}, "malformed-locations"),
)


@pytest.mark.parametrize(("artifacts", "artifact", "reason"), ARTIFACTS)
def test_an_artifact_reference_must_name_one_consistent_listed_location(
    scanned: Scanned, artifacts: object, artifact: dict[str, Any], reason: str
) -> None:
    """An index out of range, contradicting its URI, or mistyped is refused.

    Parameters
    ----------
    scanned : Scanned
        The real scanned repository.
    artifacts : object
        The run's ``artifacts``.
    artifact : dict[str, Any]
        The result's artifact location.
    reason : str
        The skip reason.
    """
    run = {**scanned.run, "artifacts": artifacts}
    assert _skip(_route(scanned, _at(scanned, artifact), run)) == reason


REGIONS: tuple[tuple[dict[str, Any], str], ...] = (
    ({"startLine": 3}, "span-outside-blob"),
    ({"startLine": 1, "endLine": 3}, "span-outside-blob"),
    ({"charOffset": 4, "charLength": 2}, "no-line-region"),
    ({"startLine": 0}, "malformed-region"),
    ({"startLine": 2, "endLine": 1}, "malformed-region"),
    ({"startLine": 1, "endLine": None}, "malformed-region"),
    ({"startLine": "1"}, "malformed-region"),
    ({"startLine": True}, "malformed-region"),
    ({"startLine": 1, "startColumn": 0}, "malformed-region"),
    ({"startLine": 1, "endColumn": "9"}, "malformed-region"),
    ({"startLine": 1, "snippet": "VALUE"}, "malformed-region"),
)


@pytest.mark.parametrize(("region", "reason"), REGIONS)
def test_a_region_past_the_blob_or_without_valid_lines_is_skipped(
    scanned: Scanned, region: dict[str, Any], reason: str
) -> None:
    """A span past the two-line blob, a non-line region or a mistyped field is refused.

    Parameters
    ----------
    scanned : Scanned
        The real scanned repository.
    region : dict[str, Any]
        The result's region.
    reason : str
        The skip reason.
    """
    result = _at(scanned, {"uri": "src/pkg/core.py"}, **region)
    assert _skip(_route(scanned, result)) == reason


def test_a_missing_or_malformed_region_and_context_are_refused(scanned: Scanned) -> None:
    """No region, a non-object region, or a non-object context region each skip the result."""
    result = _at(scanned, {"uri": "src/pkg/core.py"})
    physical = result["locations"][0]["physicalLocation"]
    del physical["region"]
    assert _skip(_route(scanned, result)) == "no-line-region"
    physical["region"] = [2]
    assert _skip(_route(scanned, result)) == "malformed-region"
    physical["region"] = {"startLine": 2}
    physical["contextRegion"] = "VALUE"
    assert _skip(_route(scanned, result)) == "malformed-region"


def test_columns_snippet_and_context_are_metadata_outside_the_identity(scanned: Scanned) -> None:
    """Columns, snippet and context are kept and bounded, and never change the candidate id."""
    plain = _route(scanned, _at(scanned, {"uri": "src/pkg/core.py"}))
    region = {"startLine": 2, "startColumn": 1, "endColumn": 6, "snippet": {"text": "OTHER"}}
    detailed = _at(scanned, {"uri": "src/pkg/core.py"}, **region)
    detailed["locations"][0]["physicalLocation"]["contextRegion"] = {"startLine": 1, "endLine": 2}
    second = copy.deepcopy(detailed["locations"][0])
    second["physicalLocation"]["artifactLocation"] = {"uri": "tests/test_core.py"}
    second["physicalLocation"]["region"] = {"startLine": 1}
    detailed["locations"].append(second)
    outcome = _route(scanned, detailed)
    assert isinstance(plain, ImportedCandidate) and isinstance(outcome, ImportedCandidate)
    assert outcome.candidate_id == plain.candidate_id and outcome.anchor == plain.anchor
    assert (outcome.anchor.path, outcome.anchor.line_start) == ("src/pkg/core.py", 2)
    metadata = outcome.location.to_dict()
    assert metadata["start_column"] == 1 and metadata["end_column"] == 6
    assert metadata["snippet"] == {"text": "OTHER"} and not metadata["snippet_truncated"]
    assert metadata["context_region"] == {"startLine": 1, "endLine": 2}
    assert metadata["location_count"] == 2
    assert outcome.to_dict()["location"] == metadata
    assert plain.location.snippet_sha256 is None and plain.location.context_region_sha256 is None
    large = _at(
        scanned, {"uri": "src/pkg/core.py"}, startLine=2, snippet={"text": "x" * MAX_SNIPPET_BYTES}
    )
    cut = _route(scanned, large)
    assert isinstance(cut, ImportedCandidate)
    assert cut.location.snippet is None and cut.location.snippet_truncated
    assert cut.location.snippet_sha256 is not None


@pytest.mark.parametrize(
    "locations",
    [
        None,
        [],
        [{"logicalLocations": [{"name": "VALUE"}]}],
        [{"physicalLocation": {"address": {"absoluteAddress": 4}}}],
    ],
)
def test_a_finding_without_a_physical_artifact_location_is_an_unanchored_observation(
    scanned: Scanned, locations: list[object] | None
) -> None:
    """No location, an empty list, logical locations only, or an address only is unanchored.

    Parameters
    ----------
    scanned : Scanned
        The real scanned repository.
    locations : list[object] | None
        The result's locations, or None to remove them.
    """
    result = _at(scanned, {"uri": "src/pkg/core.py"})
    if locations is None:
        del result["locations"]
    else:
        result["locations"] = locations
    outcome = _route(scanned, result)
    assert isinstance(outcome, ImportObservation) and outcome.reason == "unanchored"


@pytest.mark.parametrize(
    "locations",
    [
        {},
        None,
        ["src/pkg/core.py"],
        [{"physicalLocation": []}],
        [{"physicalLocation": {"artifactLocation": "x"}}],
        [{"physicalLocation": {"artifactLocation": 5}}],
    ],
)
def test_a_malformed_location_list_is_skipped(scanned: Scanned, locations: object) -> None:
    """A non-array list, a non-object location, physical location or artifact is refused.

    Parameters
    ----------
    scanned : Scanned
        The real scanned repository.
    locations : object
        The result's locations.
    """
    result = {**_at(scanned, {"uri": "src/pkg/core.py"}), "locations": locations}
    assert _skip(_route(scanned, result)) == "malformed-locations"


def test_routing_keeps_kind_observations_and_record_skips_before_locations(
    scanned: Scanned,
) -> None:
    """A non-finding kind is an observation wherever it points, and a bad record is a skip."""
    passed = {**_at(scanned, {"uri": "../outside.py"}), "kind": "pass"}
    outcome = _route(scanned, passed)
    assert isinstance(outcome, ImportObservation) and outcome.reason == "kind-pass"
    assert _skip(_route(scanned, {**passed, "kind": None})) == "malformed-kind"


def test_dirty_symlinked_and_gitlink_paths_are_never_anchored(tmp_path: Path) -> None:
    """A path changed since the commit, a tracked symlink and a gitlink are each refused.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    """
    scanned = _scan(tmp_path / "repository")
    repository = scanned.repository
    repository.symlink("src/pkg/link.py", "core.py")
    head = repository.git_command("rev-parse", "HEAD").stdout.strip()
    repository.git_command("add", "src/pkg/link.py")
    repository.git_command("update-index", "--add", "--cacheinfo", f"160000,{head},vendor/sub")
    repository.git_command("commit", "-m", "test: link and gitlink")
    # An uninitialised submodule keeps an empty directory, so the gitlink itself is clean.
    (repository.root / "vendor/sub").mkdir(parents=True)
    repository.write_text("tests/test_core.py", "VALUE = 3\n")
    inventory = load_git_inventory(repository.root)
    kinds = {item.path: item.content_kind for item in inventory.files}
    assert (kinds["src/pkg/link.py"], kinds["vendor/sub"]) == ("symlink", "gitlink")
    assert inventory.dirty_paths == ("tests/test_core.py",)
    for uri, reason in (
        ("tests/test_core.py", "dirty-path"),
        ("src/pkg/link.py", "symlink-path"),
        ("vendor/sub", "no-scanned-blob"),
    ):
        result = _at(scanned, {"uri": uri}, startLine=1)
        assert _skip(_route(scanned, result, inventory=inventory)) == reason


@pytest.mark.parametrize(
    ("checkout", "base_ids", "message"),
    [
        ("relative/root", frozenset(), "canonical absolute POSIX path"),
        ("/", frozenset(), "canonical absolute POSIX path"),
        ("/a/../b", frozenset(), "canonical absolute POSIX path"),
        ("/a/", frozenset(), "canonical absolute POSIX path"),
        ("/a\\b", frozenset(), "control characters or backslashes"),
        ("/a\nb", frozenset(), "control characters or backslashes"),
        ("/a", frozenset({""}), "non-empty string"),
    ],
)
def test_a_declared_root_must_be_one_canonical_absolute_directory(
    checkout: str, base_ids: frozenset[str], message: str
) -> None:
    """A relative, filesystem-root, climbing, trailing-slash or escaped root is refused.

    Parameters
    ----------
    checkout : str
        The declared checkout root.
    base_ids : frozenset[str]
        The declared root base ids.
    message : str
        Text the refusal must contain.
    """
    with pytest.raises(ValueError, match=message):
        LocationRoots(checkout, base_ids)


def test_import_report_records_keep_their_json_shape(scanned: Scanned) -> None:
    """A routed candidate serialises to JSON with its anchor, location and preserved result."""
    outcome = _route(scanned, _at(scanned, {"uri": "src/pkg/core.py"}))
    assert isinstance(outcome, ImportedCandidate)
    record = json.loads(json.dumps(outcome.to_dict()))
    assert sorted(record) == [
        "anchor",
        "candidate_id",
        "location",
        "producer_id",
        "result",
        "state",
    ]
    assert record["anchor"]["path"] == "src/pkg/core.py" and record["state"] == "unreviewed"
