# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — reviewed rule-to-CWE mapping tests
"""Verify the reviewed CWE mapping, its fail-closed loading, and its SARIF and catalogue use."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from importlib import resources
from pathlib import Path
from typing import Any

import pytest

from rigor_foundry.cwe_mapping import (
    CWE_MAPPING_RESOURCE,
    CWE_TAXONOMY_NAME,
    cwe_catalogue,
    cwe_definition_uri,
    parse_cwe_catalogue,
)
from rigor_foundry.models import AuditReport
from rigor_foundry.rule_catalogue import render_rule_catalogue
from rigor_foundry.rules import RULES
from rigor_foundry.sarif import CATEGORY_TAXONOMY_NAME, report_sarif
from rigor_foundry.sarif_github_profile import GITHUB_CODE_SCANNING_PROFILE

ROOT = Path(__file__).resolve().parents[1]
MAPPING_PATH = ROOT / "src/rigor_foundry" / CWE_MAPPING_RESOURCE
REVIEWED = {
    "AS001-dynamic-code-execution": 95,
    "AS002-shell-command-execution": 78,
    "AS003-unsafe-deserialization": 502,
    "AS004-weak-hash-primitive": 328,
    "AS005-insecure-temporary-file": 367,
    "AS006-js-dynamic-code-execution": 95,
    "AS007-go-command-execution": 78,
    "AS009-c-unsafe-libc": 676,
    "AS010-julia-unsafe-memory": 676,
    "AS011-shell-eval-execution": 78,
    "AS012-disabled-tls-verification": 295,
    "AS013-insecure-ssl-context": 295,
    "RL001-bare-except": 396,
    "SC001-unhashed-pinned-requirement": 494,
    "SC002-vcs-url-requirement": 494,
    "DK001-unpinned-base-image": 494,
    "DK002-root-runtime-user": 250,
    "DP001-hardcoded-credential": 798,
    "DP002-embedded-private-key": 321,
    "OP002-credential-in-log-call": 532,
    "GA001-unpinned-action-reference": 829,
    "GA002-run-context-interpolation": 94,
    "GA003-pull-request-target-checkout": 829,
}


def _document() -> dict[str, Any]:
    """Return a fresh copy of the tracked mapping document."""
    loaded: dict[str, Any] = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    return loaded


def _run(profile: str | None = None) -> dict[str, Any]:
    """Return the only SARIF run exported from a committed real zero-result report."""
    report = AuditReport.from_path(ROOT / "tests/fixtures/sarif/report-empty.json")
    (run,) = json.loads(report_sarif(report, profile=profile))["runs"]
    result: dict[str, Any] = run
    return result


def test_the_tracked_mapping_is_exactly_the_reviewed_set_on_the_pinned_version() -> None:
    """The packaged mapping holds exactly the reviewed pairs, each with its evidence review."""
    catalogue = cwe_catalogue()
    assert (catalogue.version, catalogue.release_date) == ("5.0", "2026-10-28")
    assert catalogue.download_uri == "https://cwe.mitre.org/data/xml/cwec_v5.0.xml.zip"
    assert catalogue.member_sha256 == (
        "47165a9593def89c69b9ef50c34d99ac68db55df8373613e85e9cc9ceecefb1d"
    )
    assert {rule_id: mapping.cwe_id for rule_id, mapping in catalogue.mappings.items()} == REVIEWED
    assert list(catalogue.mappings) == [rule.rule_id for rule in RULES if rule.rule_id in REVIEWED]
    for mapping in catalogue.mappings.values():
        assert (mapping.kind, mapping.author) == ("relevant", "7b7e")
        assert (mapping.review.reviewer, mapping.review.scope) == ("b0f9", "evidence")
        assert f"CWE-{mapping.cwe_id}" in mapping.justification
    assert catalogue.taxa() == tuple(sorted(set(REVIEWED.values())))
    packaged = resources.files("rigor_foundry").joinpath(CWE_MAPPING_RESOURCE)
    assert packaged.read_text(encoding="utf-8") == MAPPING_PATH.read_text(encoding="utf-8")


def _drop_review(document: dict[str, Any]) -> None:
    """Remove the review record of the first mapping."""
    del document["mappings"][0]["review"]


def _empty_review(document: dict[str, Any]) -> None:
    """Replace the first review record with an empty object."""
    document["mappings"][0]["review"] = {}


def _null_review(document: dict[str, Any]) -> None:
    """Replace the first review record with JSON null."""
    document["mappings"][0]["review"] = None


def _equal_kind(document: dict[str, Any]) -> None:
    """Claim that the first rule equals its CWE entry."""
    document["mappings"][0]["kind"] = "equal"


def _self_review(document: dict[str, Any]) -> None:
    """Make the first mapping's author its own reviewer."""
    document["mappings"][0]["review"]["reviewer"] = document["mappings"][0]["author"]


def _missing_author(document: dict[str, Any]) -> None:
    """Remove the author of the first mapping."""
    del document["mappings"][0]["author"]


def _latest_download(document: dict[str, Any]) -> None:
    """Point the download at the moving latest alias."""
    document["cwe_download_uri"] = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


def _short_member_digest(document: dict[str, Any]) -> None:
    """Truncate the pinned member digest."""
    document["cwe_member_sha256"] = document["cwe_member_sha256"][:63]


def _string_cwe_id(document: dict[str, Any]) -> None:
    """Write the first CWE id as a string."""
    document["mappings"][0]["cwe_id"] = "95"


def _boolean_cwe_id(document: dict[str, Any]) -> None:
    """Write the first CWE id as a boolean."""
    document["mappings"][0]["cwe_id"] = True


def _zero_cwe_id(document: dict[str, Any]) -> None:
    """Write the first CWE id as zero."""
    document["mappings"][0]["cwe_id"] = 0


def _upper_case_author(document: dict[str, Any]) -> None:
    """Write the first author in upper case."""
    document["mappings"][0]["author"] = "7B7E"


def _spaced_reviewer(document: dict[str, Any]) -> None:
    """Put a space inside the first reviewer's seat identifier."""
    document["mappings"][0]["review"]["reviewer"] = "b0 f9"


def _dash_led_reviewer(document: dict[str, Any]) -> None:
    """Start the first reviewer's seat identifier with a dash."""
    document["mappings"][0]["review"]["reviewer"] = "-b0f9"


def _list_entry(document: dict[str, Any]) -> None:
    """Replace the first mapping entry with a list."""
    document["mappings"][0] = []


def _string_entry(document: dict[str, Any]) -> None:
    """Replace the first mapping entry with a string."""
    document["mappings"][0] = "AS001-dynamic-code-execution"


def _blank_reviewer(document: dict[str, Any]) -> None:
    """Blank the first reviewer."""
    document["mappings"][0]["review"]["reviewer"] = ""


def _wrong_scope(document: dict[str, Any]) -> None:
    """Give the first review a scope other than evidence."""
    document["mappings"][0]["review"]["scope"] = "exact-tree"


def _bad_review_date(document: dict[str, Any]) -> None:
    """Give the first review an impossible date."""
    document["mappings"][0]["review"]["date"] = "2026-02-30"


def _unregistered_rule(document: dict[str, Any]) -> None:
    """Map a rule id that the registry does not hold."""
    document["mappings"][0]["rule_id"] = "AS999-unregistered"


def _duplicate_rule(document: dict[str, Any]) -> None:
    """List the first mapping twice."""
    document["mappings"].append(copy.deepcopy(document["mappings"][0]))


def _uncited_justification(document: dict[str, Any]) -> None:
    """Make the first justification cite another CWE entry."""
    document["mappings"][0]["cwe_id"] = 94


def _two_sentences(document: dict[str, Any]) -> None:
    """Append a second sentence to the first justification."""
    document["mappings"][0]["justification"] += " It is also risky."


def _extra_key(document: dict[str, Any]) -> None:
    """Add an undeclared key to the first mapping."""
    document["mappings"][0]["severity"] = "high"


def _schema_version_number(document: dict[str, Any]) -> None:
    """Replace the schema version string with a number."""
    document["schema_version"] = 1


def _unpinned_version(document: dict[str, Any]) -> None:
    """Replace the pinned CWE version with an alias."""
    document["cwe_version"] = "latest"


def _mappings_object(document: dict[str, Any]) -> None:
    """Replace the mapping list with an object."""
    document["mappings"] = {}


REFUSALS: tuple[tuple[Callable[[dict[str, Any]], None], str], ...] = (
    (_drop_review, "unreviewed CWE mapping refused: AS001-dynamic-code-execution"),
    (_empty_review, "unreviewed CWE mapping refused: AS001-dynamic-code-execution"),
    (_null_review, "unreviewed CWE mapping refused: AS001-dynamic-code-execution"),
    (_equal_kind, "must have kind 'relevant', not 'equal'"),
    (_self_review, "AS001-dynamic-code-execution was reviewed by its own author: 7b7e"),
    (_missing_author, "the author of AS001-dynamic-code-execution must be a non-empty string"),
    (_latest_download, "cwe_download_uri must be the version-specific archive"),
    (_short_member_digest, "cwe_member_sha256 must be a lower-case hexadecimal SHA-256"),
    (_string_cwe_id, "must be a positive integer, not '95'"),
    (_boolean_cwe_id, "must be a positive integer, not True"),
    (_zero_cwe_id, "must be a positive integer, not 0"),
    (_upper_case_author, "the author of AS001-dynamic-code-execution must be a lower-case seat"),
    (_spaced_reviewer, "the reviewer of AS001-dynamic-code-execution must be a lower-case seat"),
    (_dash_led_reviewer, "the reviewer of AS001-dynamic-code-execution must be a lower-case seat"),
    (_list_entry, "each CWE mapping must be an object"),
    (_string_entry, "each CWE mapping must be an object"),
    (_blank_reviewer, "the reviewer of AS001-dynamic-code-execution must be a non-empty string"),
    (_wrong_scope, "must have scope 'evidence'"),
    (_bad_review_date, "the review date of AS001-dynamic-code-execution must be an ISO 8601"),
    (_unregistered_rule, "CWE mapping names an unregistered rule: AS999-unregistered"),
    (_duplicate_rule, "CWE mapping lists a rule twice: AS001-dynamic-code-execution"),
    (_uncited_justification, "must be one sentence that cites CWE-94"),
    (_two_sentences, "must be one sentence that cites CWE-95"),
    (_extra_key, "the CWE mapping of AS001-dynamic-code-execution must be an object"),
    (_schema_version_number, "schema_version must be '1.0'"),
    (_unpinned_version, "cwe_version must be a CWE List version"),
    (_mappings_object, "the CWE mappings must be a list"),
)


@pytest.mark.parametrize(
    ("alter", "message"), REFUSALS, ids=[item[0].__name__ for item in REFUSALS]
)
def test_loading_refuses_every_unreviewed_or_malformed_mapping(
    alter: Callable[[dict[str, Any]], None], message: str
) -> None:
    """Each altered copy of the real mapping is refused with a message naming the fault.

    Parameters
    ----------
    alter : Callable[[dict[str, Any]], None]
        Changes one fact of the tracked document.
    message : str
        Text the refusal must contain.
    """
    document = _document()
    assert parse_cwe_catalogue(json.dumps(document)).mappings
    alter(document)
    with pytest.raises(ValueError) as refusal:
        parse_cwe_catalogue(json.dumps(document))
    assert message in str(refusal.value)
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_cwe_catalogue("{")


@pytest.mark.parametrize("profile", [None, GITHUB_CODE_SCANNING_PROFILE])
def test_every_relationship_resolves_and_cwe_is_only_ever_relevant(profile: str | None) -> None:
    """Each rule has one category subset and, only when reviewed, one relevant CWE relationship.

    Parameters
    ----------
    profile : str or None
        The canonical export or the GitHub profile, which keeps both taxonomies.
    """
    run = _run(profile)
    taxonomies = run["taxonomies"]
    assert [taxonomy["name"] for taxonomy in taxonomies] == [
        CATEGORY_TAXONOMY_NAME,
        CWE_TAXONOMY_NAME,
    ]
    cwe = taxonomies[1]
    assert {key: value for key, value in cwe.items() if key != "taxa"} == {
        "name": "CWE",
        "organization": "MITRE",
        "version": "5.0",
        "releaseDateUtc": "2026-10-28",
        "informationUri": "https://cwe.mitre.org/",
        "downloadUri": "https://cwe.mitre.org/data/xml/cwec_v5.0.xml.zip",
        "isComprehensive": False,
    }
    assert cwe["taxa"] == [{"id": str(cwe_id)} for cwe_id in cwe_catalogue().taxa()]
    related: dict[str, int] = {}
    used: set[str] = set()
    for rule in run["tool"]["driver"]["rules"]:
        kinds_by_component: dict[str, list[list[str]]] = {}
        for relationship in rule["relationships"]:
            target = relationship["target"]
            component = target["toolComponent"]
            taxonomy = taxonomies[component["index"]]
            assert taxonomy["name"] == component["name"]
            assert taxonomy["taxa"][target["index"]]["id"] == target["id"]
            kinds_by_component.setdefault(component["name"], []).append(relationship["kinds"])
            if component["name"] == CWE_TAXONOMY_NAME:
                related[rule["id"]] = int(target["id"])
                used.add(target["id"])
        assert kinds_by_component[CATEGORY_TAXONOMY_NAME] == [["subset"]]
        assert kinds_by_component.get(CWE_TAXONOMY_NAME, [["relevant"]]) == [["relevant"]]
    assert related == REVIEWED
    assert used == {taxon["id"] for taxon in cwe["taxa"]}


def test_the_catalogue_shows_each_reviewed_mapping_and_no_other() -> None:
    """A mapped rule's section names its CWE entry and justification; an unmapped one names none."""
    catalogue = cwe_catalogue()
    sections = {
        section.split("\n", 1)[0]: section
        for section in render_rule_catalogue().split("\n### ")[1:]
    }
    assert sorted(sections) == sorted(rule.rule_id for rule in RULES)
    for rule in RULES:
        section = sections[rule.rule_id]
        mapping = catalogue.mappings.get(rule.rule_id)
        if mapping is None:
            assert "Related weakness" not in section
            continue
        line = (
            f"**Related weakness.** [CWE-{mapping.cwe_id}]({cwe_definition_uri(mapping.cwe_id)})"
            f" (relevant). {mapping.justification}"
        )
        assert section.count("Related weakness") == 1
        assert line in section.splitlines()
