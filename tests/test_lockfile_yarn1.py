# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Yarn 1 lockfile classification witnesses
"""Witness Yarn 1 classification on the lockfile yarn 1.22.22 generated (see GENERATED_BY.txt).

Every failing case is one recorded edit of that lockfile, written out in the test that uses it.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from lockfile_repository_support import fixture_text

from rigor_foundry.lockfile_model import LockedEntry
from rigor_foundry.lockfile_npmrc import npmrc_registry_hosts
from rigor_foundry.lockfile_yarn1 import classify_yarn1_lockfile
from rigor_foundry.lockfile_yarnrc import (
    UNKNOWN_YARN_REGISTRY,
    YarnRegistryDeclaration,
    yarn_registry_declaration,
    yarnrc_registry_hosts,
)

YARN1 = (
    Path(__file__).resolve().parent / "fixtures" / "lockfiles" / "yarn-1.22.22-v1" / "yarn.lock.gz"
)
DEFAULT = yarn_registry_declaration({}, {})
COMMIT = "98e8ff1da1a89f93d1397a24d7413ed15421c139"
CODELOAD = f"https://codeload.github.com/jonschlinkert/is-number/tar.gz/{COMMIT}"
SHA512 = "sha512-" + base64.b64encode(hashlib.sha512(b"x").digest()).decode()
MS = 'ms@2.1.2:\n  version "2.1.2"\n'
MS_RESOLVED = '  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.2.tgz#d09d1f357b443f493382a8eb3ccd183872ae6009"\n'


def _text() -> str:
    """Return the clean lockfile text."""
    return fixture_text(YARN1)


def _edited(old: str, new: str) -> str:
    """Return the clean lockfile with exactly one recorded edit."""
    text = _text()
    assert text.count(old) == 1, old
    return text.replace(old, new)


def _entries(
    text: str, registry: YarnRegistryDeclaration = DEFAULT, lock_dir: str = ""
) -> dict[str, LockedEntry]:
    """Classify a lockfile and index its entries by key."""
    version, entries = classify_yarn1_lockfile(text, lock_dir, registry)
    assert version == "1"
    return {entry.key: entry for entry in entries}


def _ms_block() -> str:
    """Return the clean ``ms`` entry exactly as Yarn wrote it, integrity included."""
    text = _text()
    start = text.index(MS + MS_RESOLVED)
    return text[start : text.index("\n\n", start) + 1]


def _ms(text: str) -> LockedEntry:
    """Return the ``ms`` entry."""
    return _entries(text)["ms@2.1.2"]


def test_the_clean_lockfile_classifies_every_entry_as_the_rulings_say() -> None:
    """Registry artifacts pin; a Git clone pins by commit; a codeload archive does not."""
    entries = _entries(_text())
    classes = [entry.entry_class for entry in entries.values()]
    assert classes.count("artifact-pinned") == 56
    debug = entries["debug@4.3.4"]
    assert (debug.digest_algorithms, debug.origin) == (("sha512", "sha1"), "registry.yarnpkg.com")
    archive = entries[f"is-number@github:jonschlinkert/is-number#{COMMIT}"]
    assert (archive.entry_class, archive.form, archive.findings) == (
        "unpinned",
        "artifact",
        ("missing-digest",),
    )
    assert (archive.archive_commit, archive.commit_hash_algorithm, archive.origin) == (
        COMMIT,
        "sha1",
        "codeload.github.com",
    )
    clone = next(entry for key, entry in entries.items() if key.startswith("vcs-lib@"))
    assert (clone.entry_class, clone.commit_hash_algorithm, clone.origin) == (
        "commit-pinned",
        "sha1",
        None,
    )
    assert entries["local-lib@file:./local-lib"].entry_class == "local"
    assert entries["linked-lib@link:./linked-lib"].entry_class == "local"
    grouped = entries["lodash.assign@^4.0.3, lodash.assign@^4.0.6"]
    assert grouped.entry_class == "artifact-pinned"


@pytest.mark.parametrize(
    ("resolved", "integrity", "entry_class", "findings", "archive_commit"),
    [
        (
            f"https://codeload.github.com/a/b/tar.gz/{'c' * 64}",
            None,
            "unpinned",
            ("missing-digest",),
            "c" * 64,
        ),
        (CODELOAD, SHA512, "artifact-pinned", (), COMMIT),
        (
            "https://codeload.github.com/a/b/tar.gz/main",
            None,
            "unpinned",
            ("missing-digest", "floating-ref"),
            None,
        ),
        (
            f"https://codeload.github.com/a/b/tar.gz/{COMMIT[:7]}",
            SHA512,
            "unpinned",
            ("floating-ref",),
            None,
        ),
    ],
)
def test_a_codeload_archive_is_pinned_only_by_a_digest_and_records_its_commit(
    resolved: str,
    integrity: str | None,
    entry_class: str,
    findings: tuple[str, ...],
    archive_commit: str | None,
) -> None:
    """A full commit in the archive path is evidence, never a pin; a moving reference floats.

    Parameters
    ----------
    resolved : str
        The edited archive URL.
    integrity : str | None
        An added ``integrity``, if any.
    entry_class : str
        The expected class.
    findings : tuple[str, ...]
        The expected findings.
    archive_commit : str | None
        The commit recorded as evidence.
    """
    new = f'  resolved "{resolved}"\n'
    if integrity is not None:
        new += f"  integrity {integrity}\n"
    text = _edited(f'  resolved "{CODELOAD}"\n', new)
    entry = _entries(text)[f"is-number@github:jonschlinkert/is-number#{COMMIT}"]
    assert (entry.entry_class, entry.findings, entry.archive_commit) == (
        entry_class,
        findings,
        archive_commit,
    )
    assert entry.origin == "codeload.github.com"


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("/a/b.tar.gz", "too short"),
        ("/a/b/zip/" + COMMIT, "not tar.gz"),
        ("//b/tar.gz/" + COMMIT, "empty owner"),
    ],
)
def test_a_codeload_url_of_another_shape_is_an_ordinary_artifact(path: str, kind: str) -> None:
    """Only ``/<owner>/<repo>/tar.gz/<ref>`` is an archive; anything else is compared as an artifact.

    Parameters
    ----------
    path : str
        The edited URL path.
    kind : str
        Why the shape is not an archive, for the failure message.
    """
    text = _edited(
        f'  resolved "{CODELOAD}"\n', f'  resolved "https://codeload.github.com{path}"\n'
    )
    entry = _entries(text)[f"is-number@github:jonschlinkert/is-number#{COMMIT}"]
    assert entry.archive_commit is None, kind
    assert entry.findings == ("missing-digest", "origin-mismatch"), kind


@pytest.mark.parametrize(
    ("edit", "entry_class", "findings", "algorithms"),
    [
        (MS + MS_RESOLVED, "unpinned", ("weak-digest",), ("sha1",)),
        (
            MS + '  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.2.tgz"\n',
            "unpinned",
            ("missing-digest",),
            (),
        ),
        (
            MS + MS_RESOLVED + "  integrity sha512-!!!\n",
            "unpinned",
            ("weak-digest", "malformed-digest"),
            ("sha1",),
        ),
        (
            MS
            + '  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.2.tgz#nothex"\n  integrity '
            + SHA512
            + "\n",
            "unpinned",
            ("malformed-digest",),
            ("sha512",),
        ),
        (
            MS
            + '  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.2.tgz"\n  integrity '
            + SHA512
            + "\n",
            "artifact-pinned",
            (),
            ("sha512",),
        ),
    ],
)
def test_a_registry_artifact_is_pinned_by_an_accepted_integrity(
    edit: str, entry_class: str, findings: tuple[str, ...], algorithms: tuple[str, ...]
) -> None:
    """The ``#sha1`` fragment alone is weak; a malformed integrity or fragment unpins.

    Parameters
    ----------
    edit : str
        The edited ``ms`` entry.
    entry_class : str
        The expected class.
    findings : tuple[str, ...]
        The expected findings.
    algorithms : tuple[str, ...]
        The algorithms that decode.
    """
    original = _ms_block()
    entry = _ms(_edited(original, edit))
    assert (entry.entry_class, entry.findings, entry.digest_algorithms) == (
        entry_class,
        findings,
        algorithms,
    )


@pytest.mark.parametrize(
    ("resolved", "entry_class", "findings"),
    [
        ("git+https://git.example/a/b.git#main", "unpinned", ("floating-ref",)),
        (f"git+ssh://git@git.example/a/b.git#{COMMIT}", "commit-pinned", ()),
        ("file:../outside.tgz", "unpinned", ("path-escape",)),
        ("file:vendor/x.tgz", "local", ()),
        ("ftp://mirror.example/x.tgz", "unclassified", ("unknown-form",)),
    ],
)
def test_other_resolved_forms_are_classified_by_their_shape(
    resolved: str, entry_class: str, findings: tuple[str, ...]
) -> None:
    """Git URLs, local tarballs and unknown schemes each take their own class.

    Parameters
    ----------
    resolved : str
        The edited ``resolved`` of ``ms``.
    entry_class : str
        The expected class.
    findings : tuple[str, ...]
        The expected findings.
    """
    entry = _ms(_edited(MS + MS_RESOLVED, MS + f'  resolved "{resolved}"\n'))
    assert (entry.entry_class, entry.findings) == (entry_class, findings)


def test_a_malformed_integrity_on_a_git_clone_unpins_it() -> None:
    """A Git clone with a malformed digest is unpinned, as for npm."""
    old = '  resolved "git+file:///tmp/rigor-yarn1-fixture/vcs-lib.git#'
    text = _text()
    start = text.index(old)
    end = text.index("\n", start) + 1
    edited = text[:end] + "  integrity sha512-!!!\n" + text[end:]
    clone = next(entry for key, entry in _entries(edited).items() if key.startswith("vcs-lib@"))
    assert (clone.entry_class, clone.form, clone.findings) == (
        "unpinned",
        "vcs",
        ("malformed-digest",),
    )


@pytest.mark.parametrize(
    ("old", "new", "key"),
    [
        (
            '"linked-lib@link:./linked-lib":',
            '"linked-lib@link:../../outside":',
            "linked-lib@link:../../outside",
        ),
        (
            '"local-lib@file:./local-lib":',
            '"local-lib@file:/srv/outside":',
            "local-lib@file:/srv/outside",
        ),
    ],
)
def test_a_local_specifier_that_leaves_the_repository_is_a_path_escape(
    old: str, new: str, key: str
) -> None:
    """``link:`` and ``file:`` paths are checked against the repository root.

    Parameters
    ----------
    old : str
        The clean key line.
    new : str
        The edited key line.
    key : str
        The edited entry key.
    """
    entry = _entries(_edited(old, new), lock_dir="web")[key]
    assert (entry.entry_class, entry.form, entry.findings) == (
        "unpinned",
        "path",
        ("path-escape",),
    )


@pytest.mark.parametrize(
    "edit",
    [
        MS,
        MS.replace('  version "2.1.2"\n', "") + MS_RESOLVED,
    ],
)
def test_an_entry_with_no_url_or_no_version_is_unclassified(edit: str) -> None:
    """A registry entry needs both its ``resolved`` URL and its version.

    Parameters
    ----------
    edit : str
        The edited ``ms`` entry, without its integrity.
    """
    original = _ms_block()
    entry = _ms(_edited(original, edit))
    assert (entry.entry_class, entry.findings) == ("unclassified", ("unknown-form",))


def test_origins_follow_the_declared_registry_and_scoped_names() -> None:
    """A declared registry makes the default host a mismatch; an uncertain one is unknown."""
    declared = yarn_registry_declaration(
        {}, yarnrc_registry_hosts('registry "https://npm.internal.example/"\n')
    )
    assert _entries(_text(), declared)["debug@4.3.4"].findings == ("origin-mismatch",)
    assert _entries(_text(), UNKNOWN_YARN_REGISTRY)["debug@4.3.4"].findings == ("origin-unknown",)
    scoped = MS.replace("ms@2.1.2", '"@acme/ms@2.1.2"')
    text = _edited(MS, scoped)
    npm = npmrc_registry_hosts("@acme:registry=https://registry.yarnpkg.com/\n")
    entries = _entries(
        text,
        yarn_registry_declaration(
            npm, yarnrc_registry_hosts('registry "https://npm.internal.example/"\n')
        ),
    )
    assert entries["@acme/ms@2.1.2"].findings == ()
    assert entries["debug@4.3.4"].findings == ("origin-mismatch",)


def test_a_specifier_without_a_range_is_classified_by_its_url() -> None:
    """A key with no ``@range`` keeps its whole text as the name."""
    entry = _entries(_edited(MS, MS.replace("ms@2.1.2", "ms")))["ms"]
    assert entry.entry_class == "artifact-pinned"
