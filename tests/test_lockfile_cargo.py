# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Cargo lockfile classification witnesses
"""Witness Cargo classification on lockfiles Cargo 1.40.0 to 1.100.0 generated.

See each fixture's GENERATED_BY.txt. Every failing case is one recorded edit of a clean
lockfile, written out in the test that uses it.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from lockfile_repository_support import fixture_text

from rigor_foundry.lockfile_cargo import classify_cargo_lockfile
from rigor_foundry.lockfile_model import LockedEntry, LockfileRefusal

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lockfiles"
V1 = FIXTURES / "cargo-1.40.0-v1"
V2 = FIXTURES / "cargo-1.47.0-v2"
V3 = FIXTURES / "cargo-1.75.0-v3"
V4 = FIXTURES / "cargo-1.83.0-v4"
SPARSE = FIXTURES / "cargo-1.83.0-sparse-v4"
REPLACE_V1 = FIXTURES / "cargo-1.40.0-replace-v1"
REPLACE_V4 = FIXTURES / "cargo-1.100.0-replace-v4"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
ITOA_V4 = f'name = "itoa"\nversion = "0.4.8"\nsource = "{CRATES_IO}"\n'
ITOA_CHECKSUM = 'checksum = "b71991ff56294aa922b450139ee08b3bfc70982c6b2c7562771375cf73542dd4"\n'
VCS_LIB_COMMIT = "4f3909b16a56bddcf960ae9b45c860612fa6555d"


def _text(fixture: Path) -> str:
    """Return a clean lockfile's text."""
    return fixture_text(fixture / "Cargo.lock.gz")


def _edited(fixture: Path, old: str, new: str) -> str:
    """Return a clean lockfile with exactly one recorded edit."""
    text = _text(fixture)
    assert text.count(old) == 1, old
    return text.replace(old, new)


def _entries(text: str) -> dict[str, LockedEntry]:
    """Classify a lockfile and index its entries by key."""
    return {entry.key: entry for entry in classify_cargo_lockfile(text).entries}


def _refusal(text: str) -> str:
    """Return the reason a lockfile is refused."""
    with pytest.raises(LockfileRefusal) as refused:
        classify_cargo_lockfile(text)
    return refused.value.reason


@pytest.mark.parametrize(
    ("fixture", "version", "classes", "unused"),
    [
        (V1, "1", {"artifact-pinned": 3, "local": 3, "commit-pinned": 2}, 0),
        (V2, "2", {"artifact-pinned": 3, "local": 3, "commit-pinned": 2}, 0),
        (V3, "3", {"artifact-pinned": 3, "local": 3, "commit-pinned": 2}, 0),
        (V4, "4", {"artifact-pinned": 3, "local": 3, "commit-pinned": 2}, 0),
        (SPARSE, "4", {"artifact-pinned": 2, "local": 1}, 1),
        (REPLACE_V1, "1", {"commit-pinned": 1, "graph-only": 1, "local": 1}, 0),
        (REPLACE_V4, "4", {"commit-pinned": 1, "graph-only": 1, "local": 1}, 0),
    ],
)
def test_each_clean_lockfile_classifies_as_the_rulings_say(
    fixture: Path, version: str, classes: dict[str, int], unused: int
) -> None:
    """Every real lockfile reads, with no finding, and counts its unused patches.

    Parameters
    ----------
    fixture : Path
        The clean fixture.
    version : str
        Its format.
    classes : dict[str, int]
        The count of each class.
    unused : int
        Its ``[[patch.unused]]`` count.
    """
    lockfile = classify_cargo_lockfile(_text(fixture))
    assert lockfile.version == version
    assert dict(Counter(entry.entry_class for entry in lockfile.entries)) == classes
    assert all(not entry.findings for entry in lockfile.entries)
    assert lockfile.unused_patches == unused


@pytest.mark.parametrize("fixture", [V1, V2, V3, V4])
def test_registry_git_and_path_entries_carry_their_evidence(fixture: Path) -> None:
    """crates.io is the origin, Git records its query and commit hash, paths are unverified.

    Parameters
    ----------
    fixture : Path
        The clean fixture.
    """
    entries = _entries(_text(fixture))
    itoa = entries["itoa 0.4.8"]
    assert (itoa.origin, itoa.digest_algorithms, itoa.notes) == ("crates.io", ("sha256",), ())
    branch = entries["vcs-branch-lib 1.0.0"]
    assert (branch.entry_class, branch.origin, branch.commit_hash_algorithm) == (
        "commit-pinned",
        "127.0.0.1",
        "sha1",
    )
    assert dict(branch.notes) == {"git_reference": "branch=main"}
    assert dict(entries["vcs-lib 1.0.0"].notes) == {"git_reference": f"rev={VCS_LIB_COMMIT}"}
    assert dict(entries["local-lib 1.0.0"].notes) == {"path_unverified": "manifest"}


def test_an_alternate_registry_is_noted_and_shared_names_take_their_source() -> None:
    """The sparse index is recorded by host; two ``itoa 0.4.8`` entries are told apart by source."""
    entries = _entries(_text(SPARSE))
    alternate = entries["itoa 0.4.8 (sparse+http://127.0.0.1:19421/index/)"]
    assert (alternate.entry_class, alternate.origin, dict(alternate.notes)) == (
        "artifact-pinned",
        "127.0.0.1:19421",
        {"alternate_registry": "true"},
    )
    assert entries[f"itoa 0.4.8 ({CRATES_IO})"].origin == "crates.io"


def test_both_crates_io_source_ids_report_crates_io() -> None:
    """``sparse+https://index.crates.io/`` is crates.io too, with no alternate-registry note."""
    edited = _edited(
        V4,
        ITOA_V4,
        'name = "itoa"\nversion = "0.4.8"\nsource = "sparse+https://index.crates.io/"\n',
    )
    itoa = _entries(edited)["itoa 0.4.8"]
    assert (itoa.origin, itoa.notes) == ("crates.io", ())


@pytest.mark.parametrize("fixture", [REPLACE_V1, REPLACE_V4])
def test_a_replaced_package_is_in_the_graph_only_and_names_its_replacement(fixture: Path) -> None:
    """The replaced registry entry is not fetched; its Git replacement is classified itself.

    Parameters
    ----------
    fixture : Path
        The clean ``[replace]`` fixture.
    """
    entries = _entries(_text(fixture))
    replaced = entries[f"itoa 0.4.8 ({CRATES_IO})"]
    assert replaced.entry_class == "graph-only"
    assert dict(replaced.notes)["replaced_by"].startswith(
        "itoa 0.4.8 (git+git://127.0.0.1:19420/itoa-fork.git?rev="
    )
    clone = next(entry for key, entry in entries.items() if "itoa-fork" in key)
    assert clone.entry_class == "commit-pinned"


@pytest.mark.parametrize(
    ("fixture", "old", "new", "finding"),
    [
        (V4, ITOA_V4 + ITOA_CHECKSUM, ITOA_V4, "missing-digest"),
        (V4, ITOA_V4 + ITOA_CHECKSUM, ITOA_V4 + 'checksum = "b71991ff"\n', "malformed-digest"),
        (
            V4,
            ITOA_V4 + ITOA_CHECKSUM,
            ITOA_V4 + ITOA_CHECKSUM.upper().replace("CHECKSUM", "checksum"),
            "malformed-digest",
        ),
        (V4, ITOA_V4 + ITOA_CHECKSUM, ITOA_V4 + "checksum = 1\n", "malformed-digest"),
        (
            V1,
            f'"checksum itoa 0.4.8 ({CRATES_IO})" = "b71991ff56294aa922b450139ee08b3bfc70982c6b2c7562771375cf73542dd4"\n',
            f'"checksum itoa 0.4.8 ({CRATES_IO})" = "<none>"\n',
            "missing-digest",
        ),
        (
            V1,
            f'"checksum itoa 0.4.8 ({CRATES_IO})" = "b71991ff56294aa922b450139ee08b3bfc70982c6b2c7562771375cf73542dd4"\n',
            "",
            "missing-digest",
        ),
    ],
)
def test_a_registry_package_is_pinned_only_by_a_64_hex_sha256(
    fixture: Path, old: str, new: str, finding: str
) -> None:
    """A missing, ``<none>``, short, upper-case or non-string checksum leaves it unpinned.

    Parameters
    ----------
    fixture : Path
        The clean fixture edited.
    old : str
        The clean text.
    new : str
        Its replacement.
    finding : str
        The expected finding.
    """
    itoa = _entries(_edited(fixture, old, new))["itoa 0.4.8"]
    assert (itoa.entry_class, itoa.findings) == ("unpinned", (finding,))


@pytest.mark.parametrize(
    ("fragment", "entry_class", "findings", "algorithm"),
    [
        ("a" * 64, "commit-pinned", (), "sha256"),
        ("abc1234", "unpinned", ("floating-ref",), None),
        ("", "unpinned", ("floating-ref",), None),
    ],
)
def test_a_git_package_is_pinned_by_a_full_commit_fragment(
    fragment: str, entry_class: str, findings: tuple[str, ...], algorithm: str | None
) -> None:
    """A 64-hex fragment is a sha256 commit; a short or missing one floats.

    Parameters
    ----------
    fragment : str
        The edited fragment after ``#``.
    entry_class : str
        The expected class.
    findings : tuple[str, ...]
        The expected findings.
    algorithm : str | None
        The recorded commit hash algorithm.
    """
    old = f'?rev={VCS_LIB_COMMIT}#{VCS_LIB_COMMIT}"'
    new = f'?rev={VCS_LIB_COMMIT}#{fragment}"' if fragment else f'?rev={VCS_LIB_COMMIT}"'
    entry = _entries(_edited(V4, old, new))["vcs-lib 1.0.0"]
    assert (entry.entry_class, entry.findings, entry.commit_hash_algorithm) == (
        entry_class,
        findings,
        algorithm,
    )


def test_a_git_source_without_a_query_follows_the_default_branch() -> None:
    """With no query, Cargo follows the default branch, and the note says so."""
    edited = _edited(V4, "vcs-branch-lib.git?branch=main#", "vcs-branch-lib.git#")
    entry = _entries(edited)["vcs-branch-lib 1.0.0"]
    assert (entry.entry_class, dict(entry.notes)) == (
        "commit-pinned",
        {"git_reference": "default-branch"},
    )


@pytest.mark.parametrize(
    "source", ["path+file:///home/x/crate", "registry+file:///srv/index", "directory+/x"]
)
def test_another_source_kind_is_unknown(source: str) -> None:
    """Sources Cargo does not write into a lockfile, or without an HTTP(S) index, are unknown.

    Parameters
    ----------
    source : str
        The edited source.
    """
    itoa = _entries(
        _edited(V4, ITOA_V4, f'name = "itoa"\nversion = "0.4.8"\nsource = "{source}"\n')
    )["itoa 0.4.8"]
    assert itoa.findings == ("unknown-form",)


def test_a_replace_naming_a_sourceless_package_is_read() -> None:
    """A replacement may be a path package, which has no source."""
    edited = _edited(
        REPLACE_V4,
        'replace = "itoa 0.4.8 (git+git://127.0.0.1:19420/itoa-fork.git?rev=27167e1cbff42f04097873ee5e433a1c9d4f5173)"\n',
        'replace = "rigor-lockfile-fixture-cargo-replace 1.0.0"\n',
    )
    replaced = _entries(edited)[f"itoa 0.4.8 ({CRATES_IO})"]
    assert dict(replaced.notes) == {"replaced_by": "rigor-lockfile-fixture-cargo-replace 1.0.0"}


@pytest.mark.parametrize(
    ("fixture", "old", "new", "reason"),
    [
        (V4, "version = 4\n", "version = 5\n", "unsupported-version"),
        (V4, "version = 4\n", "version = 4.0\n", "unsupported-version"),
        (V3, "version = 3\n", "version = 3.0\n", "unsupported-version"),
        (V4, "version = 4\n", 'version = "4"\n', "unsupported-version"),
        (V4, "version = 4\n", "version = true\n", "unsupported-version"),
        (V4, "version = 4\n", "version = 2\n", "unsupported-version"),
        (
            V3,
            "version = 3\n",
            f'version = 3\n\n[metadata]\n"checksum itoa 0.4.8 ({CRATES_IO})" = "{"0" * 64}"\n',
            "conflicting-entries",
        ),
        (V4, "version = 4\n", "version = [\n", "unparseable"),
        (V4, "version = 4\n", "version = 4\npackage = 1\n", "unparseable"),
        (V4, "version = 4\n", "version = 4\nmetadata = 1\n", "unparseable"),
        (V4, "version = 4\n", "version = 4\npatch = 1\n", "unparseable"),
        (V4, "version = 4\n", "version = 4\n[patch]\nunused = 1\n", "unparseable"),
        (V4, ITOA_V4, 'name = "itoa"\nversion = "0.4.8"\nsource = 1\n', "unparseable"),
        (
            V4,
            'name = "itoa"\nversion = "0.4.8"\n',
            'version = "0.4.8"\nname = "itoa"\n',
            "unparseable",
        ),
        (V4, 'name = "itoa"\n', "name = 'itoa'\n", "unparseable"),
        (V4, '[[package]]\nname = "itoa"\n', '[[package]] \nname = "itoa"\n', "unparseable"),
        (V4, 'name = "itoa"\nversion = "0.4.8"\n', 'name = "itoa"\n', "unparseable"),
        (
            V4,
            ITOA_V4 + ITOA_CHECKSUM,
            ITOA_V4 + ITOA_CHECKSUM + "\n[[package]]\n" + ITOA_V4 + ITOA_CHECKSUM,
            "conflicting-entries",
        ),
        (
            V4,
            'name = "local-lib"\nversion = "1.0.0"\n',
            'name = "local-lib"\nversion = "1.0.0"\n\n[[package]]\nname = "local-lib"\nversion = "1.0.0"\n',
            "conflicting-entries",
        ),
        (
            REPLACE_V4,
            '?rev=27167e1cbff42f04097873ee5e433a1c9d4f5173)"',
            '?rev=0000000000000000000000000000000000000000)"',
            "unparseable",
        ),
        (REPLACE_V4, 'replace = "itoa 0.4.8 (git', 'replace = "itoa(git', "unparseable"),
    ],
)
def test_a_lockfile_that_cannot_be_classified_is_refused(
    fixture: Path, old: str, new: str, reason: str
) -> None:
    """Only fixture-backed formats are read, and every structural defect refuses the file.

    Parameters
    ----------
    fixture : Path
        The clean fixture.
    old : str
        The clean text edited.
    new : str
        Its replacement.
    reason : str
        The expected refusal reason.
    """
    assert _refusal(_edited(fixture, old, new)) == reason


def test_v1_checksums_in_a_v2_file_are_a_bad_merge() -> None:
    """With inline checksums and ``[metadata]`` checksum keys, Cargo would drop every checksum."""
    text = _text(V2) + f'\n[metadata]\n"checksum itoa 0.4.8 ({CRATES_IO})" = "{"0" * 64}"\n'
    assert _refusal(text) == "conflicting-entries"


def test_a_package_header_inside_a_string_is_not_an_entry() -> None:
    """A ``[[package]]`` line that is not a header leaves the headers and the packages unequal."""
    text = _text(V4) + 'note = """\n[[package]]\n"""\n'
    assert _refusal(text) == "unparseable"


def test_a_v1_git_checksum_is_found_by_its_source_without_the_commit() -> None:
    """Cargo's v1 key drops the ``#`` commit; a malformed value there unpins the clone."""
    old = f'"checksum vcs-lib 1.0.0 (git+git://127.0.0.1:19420/vcs-lib.git?rev={VCS_LIB_COMMIT})" = "<none>"'
    entry = _entries(_edited(V1, old, old.replace('"<none>"', '"zz"')))["vcs-lib 1.0.0"]
    assert (entry.entry_class, entry.findings) == ("unpinned", ("malformed-digest",))


@pytest.mark.parametrize(
    "old,new",
    [('name = "itoa"\n', "name = 1\n"), ('version = "0.4.8"\nsource', "version = 4\nsource")],
)
def test_a_name_or_version_that_is_not_a_string_is_unparseable(old: str, new: str) -> None:
    """Cargo writes both as quoted strings; the layout check refuses anything else.

    Parameters
    ----------
    old : str
        The clean line.
    new : str
        Its replacement.
    """
    text = _text(V4)
    start = text.index(ITOA_V4)
    edited = text[:start] + text[start:].replace(old, new, 1)
    assert _refusal(edited) == "unparseable"


def test_a_package_without_a_name_is_unparseable() -> None:
    """A missing ``name`` breaks Cargo's layout and refuses the file before anything reads it."""
    assert (
        _refusal(_edited(V4, ITOA_V4, f'version = "0.4.8"\nsource = "{CRATES_IO}"\n'))
        == "unparseable"
    )


CFG_IF_V4 = f'name = "cfg-if"\nversion = "0.1.10"\nsource = "{CRATES_IO}"\n'
EITHER_V4 = f'name = "either"\nversion = "1.5.3"\nsource = "{CRATES_IO}"\n'


def _without_checksum(text: str, block: str) -> str:
    """Drop the checksum line that follows one package's source line."""
    start = text.index(block) + len(block)
    end = text.index("\n", start) + 1
    assert text[start:end].startswith("checksum = ")
    return text[:start] + text[end:]


def test_a_package_that_replaces_itself_is_unparseable() -> None:
    """A self-replace would leave an unpinned registry package in the graph only, unseen."""
    text = _without_checksum(_text(V4), ITOA_V4)
    edited = text.replace(ITOA_V4, ITOA_V4 + f'replace = "itoa 0.4.8 ({CRATES_IO})"\n', 1)
    assert _refusal(edited) == "unparseable"


def test_two_packages_that_replace_each_other_are_unparseable() -> None:
    """A two-cycle of replacements hides both packages' missing checksums."""
    text = _without_checksum(_without_checksum(_text(V4), CFG_IF_V4), EITHER_V4)
    text = text.replace(CFG_IF_V4, CFG_IF_V4 + f'replace = "either 1.5.3 ({CRATES_IO})"\n', 1)
    text = text.replace(EITHER_V4, EITHER_V4 + f'replace = "cfg-if 0.1.10 ({CRATES_IO})"\n', 1)
    assert _refusal(text) == "unparseable"


def test_a_crates_io_look_alike_index_is_an_alternate_registry() -> None:
    """Only crates.io's exact source IDs report crates.io; a longer URL on its host does not."""
    look_alike = "registry+https://github.com/rust-lang/crates.io-index.example.net"
    edited = _edited(V4, ITOA_V4, f'name = "itoa"\nversion = "0.4.8"\nsource = "{look_alike}"\n')
    itoa = _entries(edited)["itoa 0.4.8"]
    assert (itoa.origin, dict(itoa.notes)) == ("github.com", {"alternate_registry": "true"})


def test_a_replace_id_with_trailing_text_is_unparseable() -> None:
    """The whole ID must read as ``name version (source)``; trailing text names nothing."""
    edited = _edited(
        REPLACE_V4,
        'replace = "itoa 0.4.8 (git+git://127.0.0.1:19420/itoa-fork.git?rev=27167e1cbff42f04097873ee5e433a1c9d4f5173)"\n',
        'replace = "rigor-lockfile-fixture-cargo-replace 1.0.0 trailing"\n',
    )
    assert _refusal(edited) == "unparseable"
