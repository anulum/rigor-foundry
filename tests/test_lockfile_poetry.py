# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Poetry lockfile classification witnesses
"""Witness Poetry classification on the lockfiles Poetry 1.2.2 to 2.5.2 wrote.

See each fixture's GENERATED_BY.txt. Every failing case is one recorded edit of a clean lockfile
or of its pyproject.toml, written out in the test using it.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from lockfile_repository_support import fixture_text

from rigor_foundry.lockfile_model import LockedEntry, LockfileRefusal
from rigor_foundry.lockfile_poetry import PoetryLockfile, classify_poetry_lockfile
from rigor_foundry.lockfile_poetry_sources import read_poetry_declaration

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lockfiles"
P122 = FIXTURES / "poetry-1.2.2-lock-1.1"
P132 = FIXTURES / "poetry-1.3.2-lock-2.0"
P185 = FIXTURES / "poetry-1.8.5-lock-2.0"
P201 = FIXTURES / "poetry-2.0.1-lock-2.1"
P252 = FIXTURES / "poetry-2.5.2-lock-2.1"
SIX_WHEEL = (
    '{file = "six-1.16.0-py2.py3-none-any.whl", '
    'hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"}'
)
SIX_KEY = "six 1.16.0"
EXPLICIT = 'priority = "explicit"\n'
LOOP_URL = 'url = "http://127.0.0.1:19431/simple/"\n'
GIT_COMMIT = 'resolved_reference = "8a2b9a8d5f053ac9e7cf2623633c9e3ba93afbba"\n'


def _lock(fixture: Path) -> str:
    """Return a clean lockfile's text."""
    return fixture_text(fixture / "poetry.lock.gz")


def _pyproject(fixture: Path) -> str:
    """Return a clean pyproject.toml's text."""
    return fixture_text(fixture / "pyproject.toml.gz")


def _edit(text: str, old: str, new: str) -> str:
    """Return a clean file with exactly one recorded edit."""
    assert text.count(old) == 1, old
    return text.replace(old, new)


def _classify(lock: str, pyproject: str | None, lock_dir: str = "") -> PoetryLockfile:
    """Classify one lockfile with the declaration of its pyproject.toml."""
    return classify_poetry_lockfile(lock, lock_dir, read_poetry_declaration(pyproject))


def _entries(lock: str, pyproject: str | None, lock_dir: str = "") -> dict[str, LockedEntry]:
    """Classify a pair and index its entries by key."""
    return {entry.key: entry for entry in _classify(lock, pyproject, lock_dir).entries}


def _refusal(lock: str) -> str:
    """Return the reason a lockfile is refused."""
    with pytest.raises(LockfileRefusal) as refused:
        _classify(lock, _pyproject(P252))
    return refused.value.reason


@pytest.mark.parametrize(
    ("fixture", "version"), [(P132, "2.0"), (P185, "2.0"), (P201, "2.1"), (P252, "2.1")]
)
def test_each_clean_lockfile_classifies_as_the_rulings_say(fixture: Path, version: str) -> None:
    """Three pinned artifacts, one pinned Git package and two local packages, with no finding.

    Parameters
    ----------
    fixture : Path
        The clean fixture.
    version : str
        Its lock-version.
    """
    lockfile = _classify(_lock(fixture), _pyproject(fixture))
    assert lockfile.version == version
    assert dict(Counter(entry.entry_class for entry in lockfile.entries)) == {
        "artifact-pinned": 3,
        "commit-pinned": 1,
        "local": 2,
    }
    assert all(not entry.findings for entry in lockfile.entries)
    assert lockfile.content_hash is not None and len(lockfile.content_hash) == 64


def test_every_source_form_carries_its_evidence() -> None:
    """PyPI, the declared index, the URL, Git, the directory and the local wheel."""
    entries = _entries(_lock(P252), _pyproject(P252))
    six = entries[SIX_KEY]
    assert (six.line, six.origin, six.digest_algorithms, six.digest_scope) == (
        70,
        "pypi.org",
        ("sha256", "sha256"),
        "artifact",
    )
    assert entries["idna 3.4"].origin == "127.0.0.1:19431"
    assert entries["attrs 22.1.0"].origin == "files.pythonhosted.org"
    git = entries["gitlib 0.1.0"]
    assert (git.entry_class, git.origin, git.commit_hash_algorithm, git.notes) == (
        "commit-pinned",
        "127.0.0.1",
        "sha1",
        (("git_reference", "main"),),
    )
    assert entries["localpkg 0.1.0"].notes == (("develop", "true"),)
    toml = entries["toml 0.10.2"]
    assert toml.notes == (
        ("file_hash", "sha256:806143ae5bfb6a3c6e736a764057db0e6a0e05e338b5630894a5f779cabb4f9b"),
    )


def test_a_lock_version_below_two_is_refused_on_the_real_1_2_2_file() -> None:
    """Lock-version 1.1 keeps its hashes by name alone in [metadata.files]."""
    assert 'lock-version = "1.1"' in _lock(P122)
    assert _refusal(_lock(P122)) == "unsupported-lock-version"
    assert _refusal(_edit(_lock(P252), 'lock-version = "2.1"', 'lock-version = "1.0"')) == (
        "unsupported-lock-version"
    )


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ('"2.2"', "unsupported-version"),
        ('"3.0"', "unsupported-version"),
        ('"two"', "unsupported-version"),
        ("2.1", "unsupported-version"),
    ],
)
def test_other_lock_versions_are_unsupported(value: str, reason: str) -> None:
    """Only the versions real releases wrote are read; a float is not a version string.

    Parameters
    ----------
    value : str
        The TOML value written for lock-version.
    reason : str
        The refusal.
    """
    assert (
        _refusal(_edit(_lock(P252), 'lock-version = "2.1"', f"lock-version = {value}")) == reason
    )


def test_a_missing_lock_version_or_metadata_is_refused() -> None:
    """Poetry refuses a lockfile without them; so does this reader."""
    assert _refusal(_edit(_lock(P252), 'lock-version = "2.1"\n', "")) == "missing-version"
    assert _refusal('[[package]]\nname = "a"\nversion = "1"\nfiles = []\n') == "missing-version"


def test_metadata_files_in_a_version_two_file_conflicts() -> None:
    """The two encodings mixed: Poetry would read only the per-package lists."""
    lock = _lock(P252) + "\n[metadata.files]\nsix = []\n"
    assert _refusal(lock) == "conflicting-entries"


def test_an_accepted_file_beside_a_weak_one_is_weak() -> None:
    """Poetry's row: every file must carry an accepted hash, whichever file an install picks."""
    weak = SIX_WHEEL.replace(
        "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254",
        "md5:529d7fd7e14612ccde86417b4402d6f3",
    )
    six = _entries(_edit(_lock(P252), SIX_WHEEL, weak), _pyproject(P252))[SIX_KEY]
    assert (six.entry_class, six.findings, six.form) == ("unpinned", ("weak-digest",), "artifact")
    assert six.digest_algorithms == ("md5", "sha256")


@pytest.mark.parametrize(
    ("value", "notes"),
    [
        ("sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e025", ()),
        ("sha256:8ABB2F1D86890A2DFB989F9A77CFCFD3E47C2A354B01111771326F8AA26E0254", ()),
        ("8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254", ()),
        (
            "sha3_256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254",
            (("unrecognised_algorithm", "sha3_256"),),
        ),
    ],
)
def test_a_malformed_or_unrecognised_hash_is_malformed(
    value: str, notes: tuple[tuple[str, str], ...]
) -> None:
    """63 hex, upper case and no algorithm are malformed; an unread algorithm is noted.

    Parameters
    ----------
    value : str
        The replaced hash of six's wheel.
    notes : tuple[tuple[str, str], ...]
        The notes the entry carries.
    """
    edited = SIX_WHEEL.replace(
        "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254", value
    )
    six = _entries(_edit(_lock(P252), SIX_WHEEL, edited), _pyproject(P252))[SIX_KEY]
    assert (six.entry_class, six.findings, six.notes) == ("unpinned", ("malformed-digest",), notes)


def test_a_malformed_weak_hash_is_malformed_not_weak() -> None:
    """Only a weak hash that decodes weakens the entry; one that does not is malformed."""
    broken = SIX_WHEEL.replace(
        "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254",
        "md5:not-hex",
    )
    six = _entries(_edit(_lock(P252), SIX_WHEEL, broken), _pyproject(P252))[SIX_KEY]
    assert (six.entry_class, six.findings) == ("unpinned", ("malformed-digest",))


def test_an_empty_file_list_is_missing_its_digest() -> None:
    """Poetry verifies nothing when files is empty."""
    lock = _edit(
        _lock(P252),
        "files = [\n    "
        + SIX_WHEEL
        + ',\n    {file = "six-1.16.0.tar.gz", '
        + 'hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"},\n]',
        "files = []",
    )
    six = _entries(lock, _pyproject(P252))[SIX_KEY]
    assert (six.entry_class, six.findings) == ("unpinned", ("missing-digest",))


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("files = [\n    " + SIX_WHEEL, "files_dropped = [\n    " + SIX_WHEEL),
        (SIX_WHEEL, '{file = "six-1.16.0-py2.py3-none-any.whl"}'),
        (SIX_WHEEL, '{hash = "sha256:00"}'),
        (SIX_WHEEL, '"six-1.16.0-py2.py3-none-any.whl"'),
        ('type = "url"', "type = 1"),
    ],
)
def test_a_package_poetry_cannot_read_is_unparseable(old: str, new: str) -> None:
    """A version 2 package without files, a file without both fields, or a non-string type.

    Parameters
    ----------
    old : str
        The clean text.
    new : str
        Its recorded edit.
    """
    assert _refusal(_edit(_lock(P252), old, new)) == "unparseable"


def test_a_source_that_is_not_a_table_or_a_header_out_of_layout_is_unparseable() -> None:
    """The layout and shape checks hold for Poetry as for Cargo."""
    assert _refusal(
        _edit(_lock(P252), 'name = "six"\nversion = "1.16.0"', 'version = "1.16.0"\nname = "six"')
    ) == ("unparseable")
    assert _refusal(
        '[metadata]\nlock-version = "2.1"\n'
        '[[package]]\nname = "a"\nversion = "1"\nfiles = []\nsource = 3\n'
    ) == ("unparseable")
    assert _refusal("not toml = = =\n") == "unparseable"


def test_a_missing_resolved_reference_floats() -> None:
    """A Git source with only its branch is not pinned."""
    git = _entries(_edit(_lock(P252), GIT_COMMIT, ""), _pyproject(P252))["gitlib 0.1.0"]
    assert (git.entry_class, git.findings, git.form, git.notes) == (
        "unpinned",
        ("floating-ref",),
        "vcs",
        (("git_reference", "main"),),
    )


def test_a_sha256_commit_and_a_subdirectory_are_recorded() -> None:
    """A 64-hex resolved reference is a sha256 commit; a subdirectory is noted."""
    lock = _edit(
        _lock(P252),
        GIT_COMMIT,
        'resolved_reference = "' + "a" * 64 + '"\nsubdirectory = "lib"\n',
    )
    git = _entries(lock, _pyproject(P252))["gitlib 0.1.0"]
    assert (git.entry_class, git.commit_hash_algorithm) == ("commit-pinned", "sha256")
    assert git.notes == (("git_reference", "main"), ("subdirectory", "lib"))


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('reference = "loop"', 'reference = "other"'),
        ('url = "http://127.0.0.1:19431/simple"', 'url = "http://127.0.0.1:19432/simple"'),
        ('reference = "loop"\n', ""),
    ],
)
def test_an_index_package_must_name_the_declared_source_at_its_url(old: str, new: str) -> None:
    """An undeclared name, another URL or no name at all is an origin mismatch.

    Parameters
    ----------
    old : str
        The clean text.
    new : str
        Its recorded edit.
    """
    idna = _entries(_edit(_lock(P252), old, new), _pyproject(P252))["idna 3.4"]
    assert (idna.entry_class, idna.findings) == ("artifact-pinned", ("origin-mismatch",))


def test_trailing_slashes_and_name_case_are_ignored_as_poetry_ignores_them() -> None:
    """The real pair already differs by the trailing slash; the name's case does not matter."""
    pyproject = _edit(_pyproject(P252), 'name = "loop"', 'name = "LOOP"')
    assert _entries(_lock(P252), pyproject)["idna 3.4"].findings == ()


def test_an_index_package_without_a_url_is_a_mismatch() -> None:
    """Nothing to compare is never a match."""
    lock = _edit(_lock(P252), 'url = "http://127.0.0.1:19431/simple"\n', "")
    idna = _entries(lock, _pyproject(P252))["idna 3.4"]
    assert (idna.findings, idna.origin) == (("origin-mismatch",), None)


@pytest.mark.parametrize("pyproject", [None, "not toml = = =", "[tool]\npoetry = 3\n"])
def test_without_a_readable_declaration_origins_are_unknown(pyproject: str | None) -> None:
    """PyPI and index packages need the declaration; URL, Git and local ones do not.

    Parameters
    ----------
    pyproject : str | None
        An absent or unreadable declaration.
    """
    entries = _entries(_lock(P252), pyproject)
    assert entries[SIX_KEY].findings == ("origin-unknown",)
    assert entries["idna 3.4"].findings == ("origin-unknown",)
    assert entries["attrs 22.1.0"].findings == ()
    assert entries["gitlib 0.1.0"].findings == ()


@pytest.mark.parametrize(
    ("fixture", "old", "new", "findings"),
    [
        (P252, EXPLICIT, 'priority = "primary"\n', ("origin-mismatch",)),
        (P252, EXPLICIT, "", ("origin-mismatch",)),
        (P252, EXPLICIT, 'priority = "supplemental"\n', ()),
        (P252, 'name = "loop"', 'name = "PyPI"', ()),
        (P252, EXPLICIT, "secondary = true\n", ("origin-unknown",)),
        (P185, EXPLICIT, 'priority = "primary"\n', ("origin-mismatch",)),
        (P185, EXPLICIT, 'priority = "default"\n', ("origin-mismatch",)),
        (P132, "secondary = true\n", "default = true\n", ("origin-mismatch",)),
        (P132, "secondary = true\n", "", ("origin-unknown",)),
        (P132, "secondary = true\n", "default = false\n", ("origin-unknown",)),
    ],
)
def test_pypi_is_judged_by_the_generation_that_wrote_the_lock(
    fixture: Path, old: str, new: str, findings: tuple[str, ...]
) -> None:
    """Poetry 2 deactivates PyPI for a primary source; Poetry 1 for default, or a 1.8 primary.

    A 2.0 source with no setting is primary to 1.8.5 but not to 1.3.2, so it cannot be judged.

    Parameters
    ----------
    fixture : Path
        The clean pair: 2.5.2 writes 2.1, 1.8.5 and 1.3.2 write 2.0.
    old : str
        The clean declaration text.
    new : str
        Its recorded edit.
    findings : tuple[str, ...]
        The PyPI package's findings.
    """
    pyproject = _edit(_pyproject(fixture), old, new)
    assert _entries(_lock(fixture), pyproject)[SIX_KEY].findings == findings


def test_the_real_controls_keep_pypi_active() -> None:
    """1.3.2's secondary source and the explicit source of the others leave PyPI on."""
    for fixture in (P132, P185, P201, P252):
        assert _entries(_lock(fixture), _pyproject(fixture))[SIX_KEY].findings == ()


@pytest.mark.parametrize(
    ("old", "new", "lock_dir", "expected"),
    [
        (
            'url = "vendor/toml-0.10.2-py2.py3-none-any.whl"',
            'url = "../../outside.whl"',
            "",
            ("unpinned", ("path-escape",)),
        ),
        ('url = "localpkg"', 'url = "/abs/localpkg"', "", ("unpinned", ("path-escape",))),
        ('url = "localpkg"', 'url = "../sibling"', "app", ("local", ())),
        (
            'url = "vendor/toml-0.10.2-py2.py3-none-any.whl"',
            'url = "../vendor/toml-0.10.2-py2.py3-none-any.whl"',
            "app",
            ("local", ()),
        ),
    ],
)
def test_local_paths_outside_the_repository_escape(
    old: str, new: str, lock_dir: str, expected: tuple[str, tuple[str, ...]]
) -> None:
    """Paths are read from the lockfile's directory, as Poetry writes them.

    Parameters
    ----------
    old : str
        The clean text.
    new : str
        Its recorded edit.
    lock_dir : str
        The directory of the lockfile.
    expected : tuple[str, tuple[str, ...]]
        The class and findings of the edited entry.
    """
    entries = _entries(_edit(_lock(P252), old, new), _pyproject(P252), lock_dir)
    name = "toml 0.10.2" if "vendor" in old else "localpkg 0.1.0"
    assert (entries[name].entry_class, entries[name].findings) == expected
    if name == "toml 0.10.2":
        assert dict(entries[name].notes)["file_hash"].startswith("sha256:806143ae")


def test_a_directory_that_is_not_developed_has_no_note() -> None:
    """Only develop = true is recorded."""
    lock = _edit(_lock(P252), "develop = true\n", "develop = false\n")
    assert _entries(lock, _pyproject(P252))["localpkg 0.1.0"].notes == ()


@pytest.mark.parametrize(
    ("old", "new"),
    [('type = "git"', 'type = "hg"'), ('type = "url"\nurl', 'type = "url"\nhref')],
)
def test_an_unknown_source_form_is_unclassified(old: str, new: str) -> None:
    """A type this reader does not know, or a known one without its URL.

    Parameters
    ----------
    old : str
        The clean text.
    new : str
        Its recorded edit.
    """
    entries = _entries(_edit(_lock(P252), old, new), _pyproject(P252))
    assert Counter(entry.entry_class for entry in entries.values())["unclassified"] == 1


def test_fields_that_play_no_part_in_the_pin_are_ignored_even_when_malformed() -> None:
    """groups, markers and the rest are not read."""
    lock = _edit(
        _lock(P252),
        'groups = ["main"]\nfiles = [\n    ' + SIX_WHEEL,
        "groups = 5\nfiles = [\n    " + SIX_WHEEL,
    )
    assert _entries(lock, _pyproject(P252))[SIX_KEY].entry_class == "artifact-pinned"


def test_a_shared_name_and_version_is_keyed_by_source_and_a_repeat_conflicts() -> None:
    """Two sources of one version are two entries; the same source twice is a conflict."""
    lock = _lock(P252)
    start = lock.index('[[package]]\nname = "idna"')
    block = lock[start : lock.index("[[package]]", start + 1)]
    twin = block.replace(
        'url = "http://127.0.0.1:19431/simple"', 'url = "http://127.0.0.1:19431/simple/"'
    )
    entries = _entries(lock.replace(block, block + twin), _pyproject(P252))
    assert {key for key in entries if key.startswith("idna")} == {
        "idna 3.4 (http://127.0.0.1:19431/simple)",
        "idna 3.4 (http://127.0.0.1:19431/simple/)",
    }
    assert _refusal(lock.replace(block, block + block)) == "conflicting-entries"
