# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — tests for the Poetry and Pipenv manifest-hash comparison
"""Witness every manifest-hash form on the real drift fixtures, and each refusal and edge."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from lockfile_repository_support import fixture_text

from rigor_foundry.lockfile_manifest import (
    MANIFEST_STATES,
    NEWER_WRITER,
    UNTRACKED_MANIFEST,
    ManifestCheck,
    TrackedManifest,
    compare_to_release,
    pipenv_manifest_check,
    poetry_manifest_check,
)

FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"
ALL_FORMS = ("F1", "F2", "F3")
PIPENV_FORMS = ("plette", "canonical")


def _manifest(name: str, text: str | None, *, certain: bool = True) -> TrackedManifest:
    """Return a tracked manifest with the digest of its text."""
    digest = None if text is None else hashlib.sha256(text.encode()).hexdigest()
    return TrackedManifest(name, certain, text, digest)


def _poetry_case(case: str) -> ManifestCheck:
    """Compare one stored Poetry case's lockfile with its pyproject.toml."""
    directory = FIXTURES / f"manifest-{case}"
    lock = fixture_text(directory / "poetry.lock.gz")
    recorded = next(
        line.split('"')[1] for line in lock.splitlines() if line.startswith("content-hash")
    )
    text = fixture_text(directory / "pyproject.toml.gz")
    return poetry_manifest_check(lock, recorded, _manifest("pyproject.toml", text))


def _pipenv_case(case: str) -> ManifestCheck:
    """Compare one stored Pipenv case's lockfile with its Pipfile."""
    directory = FIXTURES / f"manifest-{case}"
    lock = fixture_text(directory / "Pipfile.lock.gz")
    recorded = json.loads(lock)["_meta"]["hash"]["sha256"]
    return pipenv_manifest_check(
        lock, recorded, _manifest("Pipfile", fixture_text(directory / "Pipfile.gz"))
    )


def _tool_exit(case: str) -> int:
    """Return the exit status the tool's own freshness check gave on one stored case."""
    status = (
        (FIXTURES / f"manifest-{case}" / "verdict.txt").read_text(encoding="utf-8").splitlines()[1]
    )
    return int(status.removeprefix("exit status: "))


@pytest.mark.parametrize(
    ("case", "state", "reason", "writer", "accepted"),
    [
        ("poetry-1.8.5-legacy-fresh", "fresh", None, "1.8.5", ALL_FORMS),
        ("poetry-1.8.5-legacy-drift", "drift", None, "1.8.5", ALL_FORMS),
        ("poetry-1.8.5-with-project-table", "fresh", None, "1.8.5", ALL_FORMS),
        ("poetry-1.8.5-with-project-table-checked-by-2.5.2", "fresh", None, "1.8.5", ALL_FORMS),
        ("poetry-1.8.5-toml-date", "manifest-unparseable", None, "1.8.5", ALL_FORMS),
        ("poetry-2.2.1-project-fresh", "fresh", None, "2.2.1", ("F1", "F2")),
        ("poetry-2.2.1-project-group-changed", "fresh", None, "2.2.1", ("F1", "F2")),
        ("poetry-2.2.1-project-header-2.3.0b1", "fresh", None, "2.3.0b1", ("F1", "F2")),
        (
            "poetry-2.2.1-project-header-9.0.0",
            "manifest-uncertain",
            NEWER_WRITER,
            "9.0.0",
            ("F1",),
        ),
        ("poetry-2.5.2-legacy-fresh", "fresh", None, "2.5.2", ("F1",)),
        ("poetry-2.5.2-legacy-drift", "drift", None, "2.5.2", ("F1",)),
        ("poetry-2.5.2-project-fresh", "fresh", None, "2.5.2", ("F1",)),
        ("poetry-2.5.2-project-nogroups-fresh", "fresh", None, "2.5.2", ("F1",)),
        ("poetry-2.5.2-project-groups-added", "drift", None, "2.5.2", ("F1",)),
        # An empty [project] list or table is hashed, as 2.5.2 keeps any value that is not None.
        ("poetry-2.5.2-project-empty-dependencies", "fresh", None, "2.5.2", ("F1",)),
        ("poetry-2.5.2-project-empty-optional", "fresh", None, "2.5.2", ("F1",)),
        ("poetry-2.5.2-toml-date", "manifest-unparseable", None, "2.5.2", ("F1",)),
    ],
)
def test_poetry_cases_follow_the_writer_on_line_1(
    case: str, state: str, reason: str | None, writer: str, accepted: tuple[str, ...]
) -> None:
    """Each real Poetry case gets the state the union of writer and 2.5.2 verdicts gives."""
    check = _poetry_case(case)
    assert (check.state, check.reason, check.writer, check.accepted) == (
        state,
        reason,
        writer,
        accepted,
    )


def test_poetry_agrees_with_poetry_on_fresh_and_drift_and_departs_only_where_ruled() -> None:
    """Fresh and drift agree with each writer's own check; 1.8.5's [project] case follows 1.8.5."""
    for case in (
        "poetry-1.8.5-legacy-fresh",
        "poetry-2.5.2-project-fresh",
        "poetry-2.2.1-project-header-2.3.0b1",
    ):
        assert (_poetry_case(case).state, _tool_exit(case)) == ("fresh", 0)
    for case in (
        "poetry-1.8.5-legacy-drift",
        "poetry-2.5.2-legacy-drift",
        "poetry-2.5.2-project-groups-added",
    ):
        assert (_poetry_case(case).state, _tool_exit(case)) == ("drift", 1)
    # 2.5.2 calls 1.8.5's [project] lock stale; the writer called it fresh, and a false drift is worse.
    assert _tool_exit("poetry-1.8.5-with-project-table-checked-by-2.5.2") == 1
    assert _tool_exit("poetry-1.8.5-with-project-table") == 0
    # A writer newer than 2.5.2 whose F1 misses is uncertain, though 2.5.2 itself calls it stale.
    assert _tool_exit("poetry-2.2.1-project-header-9.0.0") == 1
    # Both releases refuse a TOML date in a hashed key; it cannot be compared here either.
    assert _tool_exit("poetry-2.5.2-toml-date") == 1


@pytest.mark.parametrize(
    ("case", "state", "tool_exit"),
    [
        ("pipenv-2025.0.4-fresh", "fresh", 0),
        ("pipenv-2025.0.4-drift", "drift", 1),
        ("pipenv-2026.12.1-fresh", "fresh", 0),
        ("pipenv-2026.12.1-drift", "drift", 1),
        # Each current release calls the other's fresh lock of a Pipfile naming "Six" stale.
        ("pipenv-2025.0.4-fresh-checked-by-2026.12.1", "fresh", 1),
        ("pipenv-2026.12.1-fresh-checked-by-2025.0.4", "fresh", 1),
        ("pipenv-2025.0.4-no-source", "fresh", 0),
        # Names that differ from their PEP 503 form only by separators: typing_extensions and
        # backports.tarfile. 2026.12.1 folds the separators, so a case-only rule would drift.
        ("pipenv-2025.0.4-separator-names", "fresh", 0),
        ("pipenv-2026.12.1-separator-names", "fresh", 0),
        ("pipenv-2026.12.1-no-source", "fresh", 0),
        ("pipenv-2025.0.4-env-source", "fresh", 0),
        ("pipenv-2026.12.1-env-source", "fresh", 0),
        ("pipenv-2025.0.4-toml-date", "manifest-unparseable", 1),
        ("pipenv-2026.12.1-toml-date", "manifest-unparseable", 1),
    ],
)
def test_pipenv_cases_accept_either_form(case: str, state: str, tool_exit: int) -> None:
    """Either Pipenv form is accepted; the tool's own verdict is pinned beside each case."""
    check = _pipenv_case(case)
    assert (check.state, check.writer, check.accepted, check.hash_line) == (
        state,
        None,
        PIPENV_FORMS,
        3,
    )
    assert _tool_exit(case) == tool_exit


def test_pipenv_2020_hashes_the_inserted_default_source() -> None:
    """2020.11.15 locked a Pipfile with no [[source]]; its hash covers the inserted PyPI source."""
    assert _pipenv_case("pipenv-2020.11.15-no-source").state == "fresh"


def test_an_environment_variable_in_a_source_url_is_hashed_as_written() -> None:
    """Both current releases record and hash the URL's ${VAR} text, never its expansion."""
    lock = fixture_text(FIXTURES / "manifest-pipenv-2026.12.1-env-source" / "Pipfile.lock.gz")
    assert json.loads(lock)["_meta"]["sources"][0]["url"] == "https://${RIGOR_INDEX_HOST}/simple"


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("2.3.0", 0),
        ("2.3", 0),
        ("v2.3.0", 0),
        ("2.3.0b1", -1),
        ("2.3.0.dev0", -1),
        ("2.3.0rc1", -1),
        ("2.3.0-alpha.2", -1),
        ("2.2.9", -1),
        ("2.3.0.post1", 1),
        ("2.3.0-1", 1),
        ("2.3.0.post1.dev0", 1),
        ("2.3.0+local.7", 1),
        ("2.10.0", 1),
        ("1!1.0", 1),
        ("and", None),
        ("2.3.0-", None),
    ],
)
def test_versions_are_ordered_as_pep_440_orders_them(version: str, expected: int | None) -> None:
    """Pre-releases and dev releases come before 2.3.0; post and local releases after it."""
    assert compare_to_release(version, (2, 3, 0)) == expected


def test_a_header_with_no_version_accepts_every_form() -> None:
    """1.3.2's real header names no version, so the writer is unknown and every form counts."""
    directory = FIXTURES / "manifest-poetry-1.8.5-legacy-fresh"
    lock = fixture_text(directory / "poetry.lock.gz")
    unnamed = lock.replace("Poetry 1.8.5 and", "Poetry and", 1)
    recorded = next(
        line.split('"')[1] for line in lock.splitlines() if line.startswith("content-hash")
    )
    check = poetry_manifest_check(
        unnamed,
        recorded,
        _manifest("pyproject.toml", fixture_text(directory / "pyproject.toml.gz")),
    )
    assert (check.state, check.writer, check.accepted) == ("fresh", "and", ALL_FORMS)
    headless = "\n".join(lock.splitlines()[1:])
    check = poetry_manifest_check(
        headless,
        recorded,
        _manifest("pyproject.toml", fixture_text(directory / "pyproject.toml.gz")),
    )
    assert (check.state, check.writer, check.accepted) == ("fresh", None, ALL_FORMS)


def test_a_newer_writer_whose_f1_matches_is_fresh_and_a_pre_2_0_writer_takes_every_form() -> None:
    """A newer writer is judged by F1; a 2.0.0 pre-release is a 1.x writer."""
    directory = FIXTURES / "manifest-poetry-2.5.2-project-fresh"
    lock = fixture_text(directory / "poetry.lock.gz")
    recorded = next(
        line.split('"')[1] for line in lock.splitlines() if line.startswith("content-hash")
    )
    manifest = _manifest("pyproject.toml", fixture_text(directory / "pyproject.toml.gz"))
    newer = poetry_manifest_check(
        lock.replace("Poetry 2.5.2 and", "Poetry 9.0.0 and", 1), recorded, manifest
    )
    assert (newer.state, newer.reason, newer.accepted) == ("fresh", None, ("F1",))
    early = poetry_manifest_check(
        lock.replace("Poetry 2.5.2 and", "Poetry 2.0.0b1 and", 1), recorded, manifest
    )
    assert early.accepted == ALL_FORMS


def test_a_lockfile_without_its_hash_is_drift_at_line_1() -> None:
    """Both tools call a lock without its manifest hash stale."""
    poetry = poetry_manifest_check(
        "[metadata]\n", None, _manifest("pyproject.toml", "[tool.poetry]\n")
    )
    assert (poetry.state, poetry.recorded, poetry.hash_line) == ("drift", None, 1)
    pipenv = pipenv_manifest_check('{"_meta": {}}', None, _manifest("Pipfile", "[packages]\n"))
    assert (pipenv.state, pipenv.recorded, pipenv.hash_line) == ("drift", None, 1)


def test_a_newer_writer_without_a_recorded_hash_is_drift_not_uncertain() -> None:
    """Uncertainty covers only a hash that a newer Poetry may compute differently."""
    check = poetry_manifest_check(
        "# @generated by Poetry 9.0.0 and\n", None, _manifest("pyproject.toml", "")
    )
    assert (check.state, check.reason) == ("drift", None)


def test_an_untracked_or_missing_manifest_is_not_compared() -> None:
    """An uncertain manifest is uncertain, an absent one missing, and neither is drift."""
    uncertain = poetry_manifest_check(
        "", "a" * 64, _manifest("pyproject.toml", None, certain=False)
    )
    assert (uncertain.state, uncertain.reason, uncertain.accepted) == (
        "manifest-uncertain",
        UNTRACKED_MANIFEST,
        (),
    )
    missing = pipenv_manifest_check("{}", "a" * 64, _manifest("Pipfile", None))
    assert (missing.state, missing.reason, missing.manifest_sha256) == (
        "manifest-missing",
        None,
        None,
    )


@pytest.mark.parametrize(
    "text",
    ["[tool\n", "tool = 1\n", "[tool]\npoetry = 1\n", "project = 1\n", "dependency-groups = 1\n"],
)
def test_a_pyproject_that_poetry_cannot_hash_is_unparseable(text: str) -> None:
    """Broken TOML or a hashed table of another type cannot be compared."""
    check = poetry_manifest_check("", "a" * 64, _manifest("pyproject.toml", text))
    assert check.state == "manifest-unparseable"


@pytest.mark.parametrize(
    "text",
    ["[packages\n", 'source = "pypi"\n', "packages = 1\n", "docs = 1\n", "requires = 1\n"],
)
def test_a_pipfile_that_pipenv_cannot_hash_is_unparseable(text: str) -> None:
    """Broken TOML, a source that is not a list, or a category that is not a table."""
    check = pipenv_manifest_check("{}", "a" * 64, _manifest("Pipfile", text))
    assert check.state == "manifest-unparseable"


def test_every_field_is_serialised_and_every_state_is_named() -> None:
    """The report object carries every field; the state list is the report's vocabulary."""
    check = _poetry_case("poetry-2.5.2-legacy-drift")
    data = check.to_dict()
    assert set(data) == {
        "manifest_path",
        "manifest_sha256",
        "state",
        "reason",
        "recorded",
        "hash_line",
        "writer",
        "accepted",
    }
    assert data["accepted"] == ["F1"] and data["hash_line"] == 18 and data["state"] == "drift"
    assert MANIFEST_STATES == (
        "fresh",
        "drift",
        "manifest-missing",
        "manifest-uncertain",
        "manifest-unparseable",
    )


@pytest.mark.parametrize(
    ("writer", "accepted"),
    [
        ("1.9.9", ALL_FORMS),
        ("2.0.0", ("F1", "F2")),
        ("2.2.9", ("F1", "F2")),
        ("2.3.0", ("F1",)),
        ("2.5.2", ("F1",)),
        ("2.5.3", ("F1",)),
    ],
)
def test_the_writer_buckets_turn_exactly_at_each_release(
    writer: str, accepted: tuple[str, ...]
) -> None:
    """2.0.0 and 2.3.0 open their buckets, and only a writer after 2.5.2 is newer."""
    lock = (
        f"# This file is automatically @generated by Poetry {writer} and should not be changed.\n"
    )
    check = poetry_manifest_check(lock, "a" * 64, _manifest("pyproject.toml", ""))
    expected_state = "manifest-uncertain" if writer == "2.5.3" else "drift"
    assert (check.accepted, check.state) == (accepted, expected_state)


def test_a_develop_table_in_the_pipfile_is_not_hashed() -> None:
    """Pipenv skips a category named default or develop, so adding one changes no form."""
    directory = FIXTURES / "manifest-pipenv-2026.12.1-fresh"
    lock = fixture_text(directory / "Pipfile.lock.gz")
    recorded = json.loads(lock)["_meta"]["hash"]["sha256"]
    text = (
        fixture_text(directory / "Pipfile.gz") + '\n[develop]\nsix = "*"\n\n[default]\nsix = "*"\n'
    )
    assert pipenv_manifest_check(lock, recorded, _manifest("Pipfile", text)).state == "fresh"
