# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Pipenv lockfile classification witnesses
"""Witness Pipenv classification on the lockfiles Pipenv 2020.11.15 to 2026.12.1 wrote.

See each fixture's GENERATED_BY.txt. Every failing case is one recorded edit of a clean lockfile,
written out in the test using it.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest
from lockfile_repository_support import fixture_text

from rigor_foundry.lockfile_model import LockedEntry, LockfileRefusal
from rigor_foundry.lockfile_pipenv import PipenvLockfile, classify_pipenv_lockfile

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lockfiles"
P2020 = FIXTURES / "pipenv-2020.11.15"
P2022 = FIXTURES / "pipenv-2022.12.19"
P2024 = FIXTURES / "pipenv-2024.4.1"
P2025 = FIXTURES / "pipenv-2025.0.4"
P2026 = FIXTURES / "pipenv-2026.12.1"
SIX = "default/six"
SIX_HASH = '"sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"'
GIT_REF = '"ref": "c634324fe22b72b31178fcf60cb388c7519e9cc0"'
SPEC = '"pipfile-spec": 6,'


def _lock(fixture: Path) -> str:
    """Return a clean lockfile's text."""
    return fixture_text(fixture / "Pipfile.lock.gz")


def _edit(text: str, old: str, new: str, count: int = 1) -> str:
    """Return a clean lockfile with exactly one recorded edit."""
    assert text.count(old) == count, old
    return text.replace(old, new)


def _classify(text: str, lock_dir: str = "") -> PipenvLockfile:
    """Classify one lockfile."""
    return classify_pipenv_lockfile(text, lock_dir)


def _entries(text: str, lock_dir: str = "") -> dict[str, LockedEntry]:
    """Classify a lockfile and index its entries by key."""
    return {entry.key: entry for entry in _classify(text, lock_dir).entries}


def _refusal(text: str) -> str:
    """Return the reason a lockfile is refused."""
    with pytest.raises(LockfileRefusal) as refused:
        _classify(text)
    return refused.value.reason


def _with_entry(category: str, name: str, entry: object) -> str:
    """Return the clean 2026.12.1 lockfile with one entry added or replaced (recorded edit)."""
    document = json.loads(_lock(P2026))
    document[category][name] = entry
    return json.dumps(document, indent=4) + "\n"


@pytest.mark.parametrize(
    ("fixture", "classes"),
    [
        (P2020, {"artifact-pinned": 4, "commit-pinned": 1, "local": 2}),
        (P2022, {"artifact-pinned": 5, "commit-pinned": 1, "local": 2}),
        (P2024, {"artifact-pinned": 5, "commit-pinned": 1, "local": 2}),
        (P2025, {"artifact-pinned": 5, "commit-pinned": 1, "local": 2}),
        (P2026, {"unpinned": 1, "artifact-pinned": 4, "commit-pinned": 1, "local": 2}),
    ],
)
def test_each_real_lockfile_classifies_as_the_rulings_say(
    fixture: Path, classes: dict[str, int]
) -> None:
    """Every release pins its index, URL and Git entries; 2026.12.1 drops the URL's hashes.

    Parameters
    ----------
    fixture : Path
        The real fixture.
    classes : dict[str, int]
        The count of each class.
    """
    lockfile = _classify(_lock(fixture))
    assert dict(Counter(entry.entry_class for entry in lockfile.entries)) == classes
    assert lockfile.meta_hash is not None and len(lockfile.meta_hash) == 64


def test_the_real_2026_url_entry_without_hashes_is_missing_its_digest() -> None:
    """Pipenv 2026.12.1 records no hash for the attrs URL; the stored fixture shows it."""
    attrs = _entries(_lock(P2026))["default/attrs"]
    assert (attrs.entry_class, attrs.findings, attrs.form, attrs.origin) == (
        "unpinned",
        ("missing-digest",),
        "artifact",
        "files.pythonhosted.org",
    )
    assert '"hashes"' not in json.dumps(json.loads(_lock(P2026))["default"]["attrs"])
    earlier = _entries(_lock(P2025))["default/attrs"]
    assert (earlier.entry_class, earlier.digest_algorithms) == (
        "artifact-pinned",
        ("sha256", "sha256"),
    )


def test_every_form_carries_its_evidence() -> None:
    """Categories key the entries; sources, Git, editable paths and local files are recorded."""
    entries = _entries(_lock(P2026))
    assert {key for key in entries if key.endswith("/six")} == {"default/six", "develop/six"}
    assert {key for key in entries if key.endswith("/idna")} == {"default/idna", "docs/idna"}
    six = entries[SIX]
    assert (six.entry_class, six.origin, six.notes, six.digest_algorithms) == (
        "artifact-pinned",
        "pypi.org",
        (),
        ("sha256", "sha256"),
    )
    assert entries["docs/idna"].notes == (("verify_ssl", "false"),)
    assert entries["docs/idna"].origin == "127.0.0.1:19441"
    git = entries["default/gitlib"]
    assert (git.entry_class, git.origin, git.commit_hash_algorithm) == (
        "commit-pinned",
        "127.0.0.1",
        "sha1",
    )
    assert entries["default/localpkg"].notes == (("editable", "true"),)
    toml = entries["default/toml"]
    assert toml.entry_class == "local"
    assert dict(toml.notes)["file_hash"].split() == [
        "sha256:806143ae5bfb6a3c6e736a764057db0e6a0e05e338b5630894a5f779cabb4f9b",
        "sha256:b3bda1d108d5dd99f4a20d24d9c348e91c4db7ab1b749200bded2f839ccbe68f",
    ]
    lines = {key: entry.line for key, entry in entries.items()}
    assert (
        lines["default/attrs"],
        lines["default/six"],
        lines["develop/six"],
        lines["docs/idna"],
    ) == (
        24,
        42,
        60,
        71,
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (SPEC, '"pipfile-spec": 5,'),
        (SPEC, '"pipfile-spec": "6",'),
        (SPEC, '"pipfile-spec": 6.0,'),
        (SPEC, '"pipfile-spec": true,'),
    ],
)
def test_only_the_integer_six_is_read(old: str, new: str) -> None:
    """Another number, a string, the float 6.0 and a boolean are unsupported.

    Parameters
    ----------
    old : str
        The clean text.
    new : str
        Its recorded edit.
    """
    assert _refusal(_edit(_lock(P2026), old, new)) == "unsupported-version"


def test_a_missing_marker_is_a_missing_version() -> None:
    """No _meta, or no pipfile-spec in it."""
    assert _refusal(_edit(_lock(P2026), SPEC, "")) == "missing-version"
    assert _refusal('{"default": {}}\n') == "missing-version"


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("[]\n", "unparseable"),
        ("{\n", "unparseable"),
        ('{"_meta": {"pipfile-spec": 6}, "default": {}, "default": {}}\n', "conflicting-entries"),
        ('{"_meta": 6}\n', "unparseable"),
        ('{"_meta": {"pipfile-spec": 6}, "default": []}\n', "unparseable"),
        ('{"_meta": {"pipfile-spec": 6}, "default": {"a": 1}}\n', "unparseable"),
        ('{"_meta": {"pipfile-spec": 6, "sources": {}}}\n', "unparseable"),
        ('{"_meta": {"pipfile-spec": 6, "sources": [{"name": "a"}]}}\n', "unparseable"),
        (
            '{"_meta": {"pipfile-spec": 6, "sources": '
            '[{"name": "a", "url": "u", "verify_ssl": "no"}]}}\n',
            "unparseable",
        ),
        ('{"_meta": {"pipfile-spec": 6, "hash": 3}}\n', "unparseable"),
        ('{"_meta": {"pipfile-spec": 6}, "default": {"a": {"hashes": "x"}}}\n', "unparseable"),
        ('{"_meta": {"pipfile-spec": 6}, "default": {"a": {"hashes": [1]}}}\n', "unparseable"),
        ('{"_meta": {"pipfile-spec": 6}, "default": {"a": {"version": 1}}}\n', "unparseable"),
    ],
)
def test_a_lockfile_pipenv_does_not_write_is_refused(text: str, reason: str) -> None:
    """Strict JSON, objects where Pipenv writes them, and string or list fields.

    Parameters
    ----------
    text : str
        The lockfile text.
    reason : str
        The refusal.
    """
    assert _refusal(text) == reason


def test_a_repeated_source_name_conflicts() -> None:
    """Which of two same-named sources an index means is not in the lockfile, so it is refused."""
    document = json.loads(_lock(P2026))
    document["_meta"]["sources"].append(
        {"name": "pypi", "url": "https://mirror.example.invalid/simple", "verify_ssl": True}
    )
    assert _refusal(json.dumps(document, indent=4) + "\n") == "conflicting-entries"


def test_a_lockfile_without_a_hash_or_sources_reads() -> None:
    """Nothing in _meta but the marker: no recorded hash, and no source to name."""
    lockfile = _classify(
        '{"_meta": {"pipfile-spec": 6}, "default": {"a": {"version": "==1.0"}}}\n'
    )
    assert lockfile.meta_hash is None
    assert lockfile.entries[0].findings == ("missing-digest", "origin-unknown")


def test_a_weak_hash_beside_an_accepted_one_is_weak() -> None:
    """Pip accepts a file when any listed hash matches, so the md5 is a way in."""
    lock = _edit(_lock(P2026), SIX_HASH, '"md5:529d7fd7e14612ccde86417b4402d6f3"', count=2)
    six = _entries(lock)[SIX]
    assert (six.entry_class, six.findings, six.digest_algorithms) == (
        "unpinned",
        ("weak-digest",),
        ("sha256", "md5"),
    )


def test_an_unrecognised_algorithm_from_an_unverified_source_keeps_both_notes() -> None:
    """Both notes are recorded, in name order."""
    lock = _edit(_lock(P2026), '"sha256:90b77e79', '"blake2b:90b77e79', count=2)
    idna = _entries(lock)["default/idna"]
    assert idna.notes == (("unrecognised_algorithm", "blake2b"), ("verify_ssl", "false"))


def test_an_unrecognised_algorithm_is_malformed_and_noted() -> None:
    """Pip refuses an unknown hash name; the note says which."""
    lock = _edit(_lock(P2026), SIX_HASH, SIX_HASH.replace("sha256:", "blake2b:"), count=2)
    six = _entries(lock)[SIX]
    assert (six.findings, six.notes) == (
        ("malformed-digest",),
        (("unrecognised_algorithm", "blake2b"),),
    )


def test_empty_hashes_are_missing() -> None:
    """A version entry with an empty list pins nothing."""
    six = _entries(
        _with_entry("default", "six", {"hashes": [], "index": "pypi", "version": "==1.16.0"})
    )[SIX]
    assert (six.entry_class, six.findings) == ("unpinned", ("missing-digest",))


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("main", ("unpinned", ("floating-ref",), None)),
        ("c634324f", ("unpinned", ("floating-ref",), None)),
        ("a" * 64, ("commit-pinned", (), "sha256")),
    ],
)
def test_a_git_ref_pins_only_as_a_full_commit(
    ref: str, expected: tuple[str, tuple[str, ...], str | None]
) -> None:
    """A branch or a short commit floats; 64 hex is a sha256 commit.

    Parameters
    ----------
    ref : str
        The edited ref.
    expected : tuple[str, tuple[str, ...], str | None]
        The class, findings and commit hash algorithm.
    """
    git = _entries(_edit(_lock(P2026), GIT_REF, f'"ref": "{ref}"'))["default/gitlib"]
    assert (git.entry_class, git.findings, git.commit_hash_algorithm) == expected


def test_a_git_entry_records_its_subdirectory_and_floats_without_a_ref() -> None:
    """The subdirectory is noted; a missing ref floats."""
    lock = _edit(_lock(P2026), GIT_REF, GIT_REF + ',\n            "subdirectory": "lib"')
    assert _entries(lock)["default/gitlib"].notes == (("subdirectory", "lib"),)
    git = _entries(_edit(_lock(P2026), ",\n            " + GIT_REF, ""))["default/gitlib"]
    assert git.findings == ("floating-ref",)


@pytest.mark.parametrize(
    ("old", "new"),
    [('"index": "loop"', '"index": "other"'), ('"index": "loop"', '"index": "Loop"')],
)
def test_an_index_must_name_a_recorded_source_exactly(old: str, new: str) -> None:
    """An undeclared name, or the same name in another case, is a mismatch.

    Parameters
    ----------
    old : str
        The clean text.
    new : str
        Its recorded edit, on the default and docs idna entries.
    """
    idna = _entries(_edit(_lock(P2026), old, new, count=2))["default/idna"]
    assert (idna.entry_class, idna.findings, idna.origin) == (
        "artifact-pinned",
        ("origin-mismatch",),
        None,
    )


def test_without_an_index_one_source_is_the_origin_and_two_are_unknown() -> None:
    """Pip may take an unindexed entry from any declared source."""
    two = _entries(_edit(_lock(P2026), '"index": "pypi",', "", count=2))[SIX]
    assert (two.findings, two.origin) == (("origin-unknown",), None)
    document = json.loads(_edit(_lock(P2026), '"index": "pypi",', "", count=2))
    document["_meta"]["sources"] = document["_meta"]["sources"][:1]
    one = _entries(json.dumps(document, indent=4) + "\n")[SIX]
    assert (one.findings, one.origin) == ((), "pypi.org")


@pytest.mark.parametrize(
    ("entry", "lock_dir", "expected"),
    [
        (
            {"path": "../../outside", "editable": True},
            "",
            ("unpinned", ("path-escape",), (("editable", "true"),)),
        ),
        ({"path": "../sibling"}, "app", ("local", (), ())),
        ({"file": "../../outside.whl"}, "", ("unpinned", ("path-escape",), ())),
        ({"file": "../vendor/x.whl"}, "app", ("local", (), ())),
        (
            {"file": "/abs/x.whl", "hashes": ["sha256:" + "a" * 64]},
            "",
            ("unpinned", ("path-escape",), (("file_hash", "sha256:" + "a" * 64),)),
        ),
    ],
)
def test_local_entries_outside_the_repository_escape(
    entry: dict[str, object],
    lock_dir: str,
    expected: tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]],
) -> None:
    """Paths are read from the lockfile's directory; notes survive an escape.

    Parameters
    ----------
    entry : dict[str, object]
        The edited localpkg entry.
    lock_dir : str
        The directory of the lockfile.
    expected : tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]]
        The class, findings and notes.
    """
    local = _entries(_with_entry("default", "localpkg", entry), lock_dir)["default/localpkg"]
    assert (local.entry_class, local.findings, local.notes) == expected


@pytest.mark.parametrize(
    "entry",
    [
        {"hg": "https://hg.example/repo", "ref": "a" * 40},
        {"hg": "https://hg.example/repo", "version": "==1.16.0", "hashes": [SIX_HASH.strip('"')]},
        {"svn": "https://svn.example/repo"},
        {"bzr": "lp:repo"},
        {"version": "*", "hashes": [SIX_HASH.strip('"')]},
        {"version": "===1.16.0", "hashes": [SIX_HASH.strip('"')]},
        {"version": ">=1.16", "hashes": [SIX_HASH.strip('"')]},
        {"version": "==1.*", "hashes": [SIX_HASH.strip('"')], "index": "pypi"},
        {"version": "==1.16.*", "hashes": [SIX_HASH.strip('"')], "index": "pypi"},
        {"version": "==1.16.0,<2", "hashes": [SIX_HASH.strip('"')], "index": "pypi"},
        {"version": "==1.16.0,!=1.16.0", "hashes": [SIX_HASH.strip('"')], "index": "pypi"},
        {
            "version": "==1.16.0; python_version > '3'",
            "hashes": [SIX_HASH.strip('"')],
            "index": "pypi",
        },
        {
            "version": "==1.16.0;python_version>'3'",
            "hashes": [SIX_HASH.strip('"')],
            "index": "pypi",
        },
        {"file": "ftp://mirror.example/six.whl"},
        {"markers": "python_version >= '3'"},
    ],
)
def test_forms_b7_does_not_name_are_unclassified(entry: dict[str, object]) -> None:
    """Other VCS kinds, inexact versions, other schemes and keyless entries are unknown forms.

    Parameters
    ----------
    entry : dict[str, object]
        The replaced six entry.
    """
    six = _entries(_with_entry("default", "six", entry))[SIX]
    assert (six.entry_class, six.findings) == ("unclassified", ("unknown-form",))


def test_a_remote_file_with_accepted_hashes_is_pinned_and_ignores_its_index() -> None:
    """The URL is the source; an index beside it is not compared."""
    url = "https://files.pythonhosted.org/packages/x/six-1.16.0-py2.py3-none-any.whl"
    entry = {"file": url, "hashes": [SIX_HASH.strip('"')], "index": "nowhere"}
    six = _entries(_with_entry("default", "six", entry))[SIX]
    assert (six.entry_class, six.findings, six.origin) == (
        "artifact-pinned",
        (),
        "files.pythonhosted.org",
    )


@pytest.mark.parametrize(
    ("hashes", "findings", "notes"),
    [
        (["md5:529d7fd7e14612ccde86417b4402d6f3"], ("weak-digest",), ()),
        (
            ["blake2b:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"],
            ("malformed-digest",),
            (("unrecognised_algorithm", "blake2b"),),
        ),
    ],
)
def test_a_remote_file_reads_its_hashes_like_a_version_entry(
    hashes: list[str], findings: tuple[str, ...], notes: tuple[tuple[str, str], ...]
) -> None:
    """A weak hash beside an accepted one weakens it; an unrecognised one is noted.

    Parameters
    ----------
    hashes : list[str]
        The hashes listed after the accepted one.
    findings : tuple[str, ...]
        The entry's findings.
    notes : tuple[tuple[str, str], ...]
        The entry's notes.
    """
    url = "https://files.pythonhosted.org/packages/x/six-1.16.0-py2.py3-none-any.whl"
    entry = {"file": url, "hashes": [SIX_HASH.strip('"'), *hashes]}
    six = _entries(_with_entry("default", "six", entry))[SIX]
    assert (six.entry_class, six.findings, six.notes) == ("unpinned", findings, notes)


def test_a_verified_source_carries_no_note() -> None:
    """Only verify_ssl false is noted."""
    assert _entries(_lock(P2026))[SIX].notes == ()
