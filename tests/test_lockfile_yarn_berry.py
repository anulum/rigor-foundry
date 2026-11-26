# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Yarn 2+ lockfile classification witnesses
"""Witness Yarn 2+ classification on lockfiles yarn 3.8.7 and 4.19.0 generated.

See each fixture's GENERATED_BY.txt. Every failing case is one recorded edit of a clean
lockfile, written out in the test that uses it.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

import pytest
from lockfile_repository_support import fixture_text

from rigor_foundry.lockfile_model import LockedEntry, LockfileRefusal
from rigor_foundry.lockfile_yarn_berry import classify_yarn_berry_lockfile
from rigor_foundry.lockfile_yarnrc_yml import (
    UNKNOWN_BERRY_REGISTRY,
    BerryRegistryDeclaration,
    read_yarnrc_yml,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lockfiles"
Y3 = FIXTURES / "yarn-3.8.7-berry" / "yarn.lock.gz"
Y4 = FIXTURES / "yarn-4.19.0-berry" / "yarn.lock.gz"
DEFAULT = BerryRegistryDeclaration(known=True)
COMMIT = "98e8ff1da1a89f93d1397a24d7413ed15421c139"
GITHUB_KEY = f"is-number@github:jonschlinkert/is-number#{COMMIT}"
MS_KEY = "ms@npm:2.1.2"


def _text(path: Path = Y4) -> str:
    """Return a clean lockfile's text."""
    return fixture_text(path)


def _edited(old: str, new: str, path: Path = Y4) -> str:
    """Return a clean lockfile with exactly one recorded edit."""
    text = _text(path)
    assert text.count(old) == 1, old
    return text.replace(old, new)


def _entries(text: str, registry: BerryRegistryDeclaration = DEFAULT) -> dict[str, LockedEntry]:
    """Classify a lockfile and index its entries by key."""
    _, entries = classify_yarn_berry_lockfile(text, "", registry)
    return {entry.key: entry for entry in entries}


def _ms_checksum() -> str:
    """Return the clean ``ms`` checksum line of the Yarn 4 fixture."""
    text = _text()
    start = text.index('"ms@npm:2.1.2":')
    line_start = text.index("  checksum: ", start)
    return text[line_start : text.index("\n", line_start) + 1]


@pytest.mark.parametrize(("path", "version"), [(Y3, "6"), (Y4, "10")])
def test_each_clean_lockfile_classifies_as_the_rulings_say(path: Path, version: str) -> None:
    """Registry artifacts, the archive and the patch pin by checksum; the clone by commit.

    Parameters
    ----------
    path : Path
        The clean fixture.
    version : str
        Its ``__metadata.version``.
    """
    found, ordered = classify_yarn_berry_lockfile(_text(path), "", DEFAULT)
    assert found == version
    entries = {entry.key: entry for entry in ordered}
    classes = [entry.entry_class for entry in ordered]
    assert (
        classes.count("artifact-pinned"),
        classes.count("local"),
        classes.count("commit-pinned"),
    ) == (10, 5, 1)
    assert all(not entry.findings for entry in ordered)
    ms = entries[MS_KEY]
    assert (ms.origin, ms.digest_scope, ms.digest_algorithms) == (
        "registry.yarnpkg.com",
        "cache-archive",
        ("sha512",),
    )
    archive = entries[GITHUB_KEY]
    assert (archive.archive_commit, archive.origin, archive.commit_hash_algorithm) == (
        COMMIT,
        "github.com",
        "sha1",
    )
    clone = next(entry for key, entry in entries.items() if key.startswith("vcs-lib@"))
    assert (clone.entry_class, clone.origin, clone.digest_scope) == (
        "commit-pinned",
        "127.0.0.1",
        "cache-archive",
    )
    patched = next(entry for key, entry in entries.items() if key.startswith("resolve@patch:"))
    assert dict(patched.notes) == {"patch_source": "builtin<compat/resolve>"}
    local = next(entry for key, entry in entries.items() if key.startswith("local-lib@"))
    assert (local.entry_class, local.digest_scope) == ("local", "cache-archive")


def test_a_checksum_with_a_foreign_cache_key_is_malformed_with_both_keys_recorded() -> None:
    """Yarn does not verify a checksum whose cache key is not the lockfile's own."""
    checksum = _ms_checksum()
    entry = _entries(_edited(checksum, checksum.replace("10c0/", "9/")))[MS_KEY]
    assert (entry.entry_class, entry.findings) == ("unpinned", ("malformed-digest",))
    assert dict(entry.notes) == {
        "checksum_cache_key": "9",
        "digest_problem": "foreign-cache-key",
        "lockfile_cache_key": "10c0",
    }


@pytest.mark.parametrize(
    ("replacement", "finding"),
    [
        ("  checksum: 10c0/abc\n", "malformed-digest"),
        ("  checksum:\n    nested: x\n", "malformed-digest"),
        ("", "missing-digest"),
    ],
)
def test_a_registry_artifact_is_pinned_only_by_its_checksum(
    replacement: str, finding: str
) -> None:
    """A short, structured or absent checksum leaves the artifact unpinned and named.

    Parameters
    ----------
    replacement : str
        The edited checksum line of ``ms``.
    finding : str
        The expected finding.
    """
    entry = _entries(_edited(_ms_checksum(), replacement))[MS_KEY]
    assert (entry.entry_class, entry.form, entry.findings) == ("unpinned", "artifact", (finding,))


@pytest.mark.parametrize(
    ("old", "new", "findings", "archive_commit"),
    [
        (
            f'#commit={COMMIT}"\n  checksum:',
            f'#commit={COMMIT}"\n  unused:',
            ("missing-digest",),
            COMMIT,
        ),
        (f'is-number.git#commit={COMMIT}"', 'is-number.git#head=main"', ("floating-ref",), None),
        (
            f'is-number.git#commit={COMMIT}"',
            f'is-number.git#commit={COMMIT[:7]}"',
            ("floating-ref",),
            None,
        ),
    ],
)
def test_a_github_archive_is_an_artifact_and_never_commit_pinned(
    old: str, new: str, findings: tuple[str, ...], archive_commit: str | None
) -> None:
    """Without a checksum the archive is missing a digest; a moving reference floats.

    Parameters
    ----------
    old : str
        The clean text edited.
    new : str
        Its replacement.
    findings : tuple[str, ...]
        The expected findings.
    archive_commit : str | None
        The commit recorded as evidence.
    """
    entry = _entries(_edited(old, new))[GITHUB_KEY]
    assert (entry.entry_class, entry.form, entry.findings, entry.archive_commit) == (
        "unpinned",
        "artifact",
        findings,
        archive_commit,
    )


@pytest.mark.parametrize(
    "fragment",
    [
        "commit=ee7225a",
        "tag=v1.0.0",
        "semver=^1.0.0",
        "commit=ee7225ad8820e4fbfcc0a6909a85af289e3f70e7&head=main",
    ],
)
def test_a_clone_floats_unless_a_full_commit_alone_pins_it(fragment: str) -> None:
    """``#head=``, ``#tag=``, ``#semver=`` and a short commit give ``floating-ref`` for a clone.

    Parameters
    ----------
    fragment : str
        The edited fragment of the clone's resolution.
    """
    old = '"vcs-lib@git://127.0.0.1:19418/vcs-lib.git#commit=ee7225ad8820e4fbfcc0a6909a85af289e3f70e7"'
    entries = _entries(_edited(old, f'"vcs-lib@git://127.0.0.1:19418/vcs-lib.git#{fragment}"'))
    clone = next(entry for key, entry in entries.items() if key.startswith("vcs-lib@"))
    assert (clone.entry_class, clone.form, clone.findings) == (
        "unpinned",
        "vcs",
        ("floating-ref",),
    )


def test_a_clone_with_a_foreign_cache_key_keeps_its_digest_problem() -> None:
    """A clone's malformed checksum unpins it, and the keys stay recorded."""
    text = _text()
    start = text.index('"vcs-lib@')
    line_start = text.index("  checksum: 10c0/", start)
    edited = text[: line_start + 12] + "8/" + text[line_start + 17 :]
    clone = next(entry for key, entry in _entries(edited).items() if key.startswith("vcs-lib@"))
    assert (clone.entry_class, clone.findings) == ("unpinned", ("malformed-digest",))
    assert dict(clone.notes)["digest_problem"] == "foreign-cache-key"


def test_an_npm_alias_is_the_target_package_with_the_alias_recorded() -> None:
    """``foo@npm:debug@4.3.4`` resolves the registry artifact ``debug``."""
    entry = _entries(_edited('"debug@npm:4.3.4":', '"foo@npm:debug@4.3.4":'))[
        "foo@npm:debug@4.3.4"
    ]
    assert entry.entry_class == "artifact-pinned"
    assert dict(entry.notes) == {"alias": "foo"}


def _locator(locator: str) -> str:
    """Return a ``locator`` binding as Yarn encodes it."""
    return "locator=" + quote(locator, safe="")


ROOT = _locator("rigor-lockfile-fixture-yarn-berry@workspace:.")
WS_A = _locator("ws-a@workspace:packages/ws-a")
LOCAL_LIB = "local-lib@file:./local-lib#./local-lib::hash=ddd187&" + ROOT
Y4_PATCH = "#optional!builtin<compat/resolve>::version=1.22.8&hash=9bd1a5"
Y3_PATCH = "#~builtin<compat/resolve>::version=1.22.8&hash=c3c19d"


def _patched(path: Path, old: str, selector: str, bindings: str) -> LockedEntry:
    """Return the ``resolve`` patch entry with its selector and bindings edited."""
    suffix = old[old.index("::") :] + (f"&{bindings}" if bindings else "")
    entries = _entries(_edited(old, f"#{selector}{suffix}", path))
    return next(entry for key, entry in entries.items() if key.startswith("resolve@patch:"))


@pytest.mark.parametrize(
    ("path", "old", "selector", "bindings", "entry_class", "findings", "source"),
    [
        (Y4, Y4_PATCH, "../outside.patch", ROOT, "unpinned", ("path-escape",), "../outside.patch"),
        (Y4, Y4_PATCH, "../shared/fix.patch", WS_A, "artifact-pinned", (), "../shared/fix.patch"),
        (
            Y4,
            Y4_PATCH,
            "../../../out.patch",
            WS_A,
            "unpinned",
            ("path-escape",),
            "../../../out.patch",
        ),
        (Y4, Y4_PATCH, "~/patches/fix.patch", "", "artifact-pinned", (), "~/patches/fix.patch"),
        (Y4, Y4_PATCH, "%7E/patches/fix.patch", "", "artifact-pinned", (), "~/patches/fix.patch"),
        (
            Y4,
            Y4_PATCH,
            "optional!~/patches/fix.patch",
            "",
            "artifact-pinned",
            (),
            "~/patches/fix.patch",
        ),
        (
            Y4,
            Y4_PATCH,
            "~/../outside.patch",
            "",
            "unpinned",
            ("path-escape",),
            "~/../outside.patch",
        ),
        (Y4, Y4_PATCH, "/etc/fix.patch", "", "unpinned", ("path-escape",), "/etc/fix.patch"),
        (
            Y4,
            Y4_PATCH,
            "~/patches/a.patch&../outside.patch",
            ROOT,
            "unpinned",
            ("path-escape",),
            "~/patches/a.patch&../outside.patch",
        ),
        (
            Y3,
            Y3_PATCH,
            "~/patches/fix.patch",
            "",
            "unpinned",
            ("path-escape",),
            "/patches/fix.patch",
        ),
        (Y3, Y3_PATCH, "./patches/fix.patch", ROOT, "artifact-pinned", (), "./patches/fix.patch"),
        (Y3, Y3_PATCH, "~~/../x.patch", ROOT, "artifact-pinned", (), "~/../x.patch"),
    ],
)
def test_a_patch_path_is_resolved_as_the_yarn_that_wrote_the_lockfile_resolves_it(
    path: Path,
    old: str,
    selector: str,
    bindings: str,
    entry_class: str,
    findings: tuple[str, ...],
    source: str,
) -> None:
    """Relative paths resolve from the locator's workspace; ``~/`` is the root only for Yarn 4.

    Yarn 3 reads a leading ``~`` as "optional", so ``~/patches/fix.patch`` is the absolute
    ``/patches/fix.patch`` there. Every ``&``-separated path is checked.

    Parameters
    ----------
    path : Path
        The clean fixture edited.
    old : str
        Its builtin patch selector and bindings.
    selector : str
        The edited selector.
    bindings : str
        A binding added after the clean ones, or ``""``.
    entry_class : str
        The expected class.
    findings : tuple[str, ...]
        The expected findings.
    source : str
        The recorded ``patch_source``.
    """
    patched = _patched(path, old, selector, bindings)
    assert (patched.entry_class, patched.findings) == (entry_class, findings)
    assert dict(patched.notes) == {"patch_source": source}


@pytest.mark.parametrize(
    ("selector", "bindings"),
    [
        ("./fix.patch", ""),
        ("./fix.patch", _locator("dep@npm:1.0.0")),
        ("./fix.patch", f"{ROOT}&{ROOT}"),
        ("./fix%zz.patch", ROOT),
        ("~builtin<compat/resolve>", ""),
        ("", ""),
        ("", ROOT),
    ],
)
def test_a_patch_path_yarn_cannot_read_from_the_repository_is_unknown(
    selector: str, bindings: str
) -> None:
    """No single locator, a fetched parent, a bad escape, Yarn 3's flag in a Yarn 4 file, none.

    Parameters
    ----------
    selector : str
        The edited selector.
    bindings : str
        A binding added after the clean ones, or ``""``.
    """
    patched = _patched(Y4, Y4_PATCH, selector, bindings)
    assert (patched.entry_class, patched.findings) == ("unclassified", ("unknown-form",))


def _nested(depth: int) -> str:
    """Return a ``link:`` locator nested ``depth`` levels below the root workspace."""
    locator = "rigor-lockfile-fixture-yarn-berry@workspace:."
    for level in range(depth):
        locator = f"l{level}@link:./d::" + _locator(locator)
    return _locator(locator)


@pytest.mark.parametrize(
    ("reference", "entry_class", "findings"),
    [
        (f"link:../shared::{WS_A}", "local", ()),
        (f"link:../../../outside::{WS_A}", "unpinned", ("path-escape",)),
        (f"link:./x::{_locator('x@workspace:../..')}", "unpinned", ("path-escape",)),
        (f"link:./inner::{_locator(LOCAL_LIB)}", "local", ()),
        (f"link:../../x::{_locator(LOCAL_LIB)}", "unpinned", ("path-escape",)),
        (f"link:/abs/x::{ROOT}", "unpinned", ("path-escape",)),
        (f"link:/abs/x::{_locator('dep@npm:1.0.0')}", "unpinned", ("path-escape",)),
        ("link:/abs/x", "unclassified", ("unknown-form",)),
        (f"link:./d::{_nested(3)}", "local", ()),
        (f"link:./d::{_nested(40)}", "unclassified", ("unknown-form",)),
        (f"link:./x::{_locator('dep@npm:1.0.0')}", "unclassified", ("unknown-form",)),
        ("link:./x", "unclassified", ("unknown-form",)),
        (f"link:./x%zz::{ROOT}", "unclassified", ("unknown-form",)),
        (f"link:./x%C3::{ROOT}", "unclassified", ("unknown-form",)),
        (f"link:./x::{ROOT}{chr(92)}nb", "unclassified", ("unknown-form",)),
    ],
)
def test_a_local_path_resolves_from_the_package_that_declared_it(
    reference: str, entry_class: str, findings: tuple[str, ...]
) -> None:
    """A workspace's or local package's folder is the base; a fetched package is not the repository.

    Parameters
    ----------
    reference : str
        The edited ``linked-lib`` resolution.
    entry_class : str
        The expected class.
    findings : tuple[str, ...]
        The expected findings.
    """
    clean = f'resolution: "linked-lib@link:./linked-lib::{ROOT}"'
    entries = _entries(_edited(clean, f'resolution: "linked-lib@{reference}"'))
    linked = next(entry for key, entry in entries.items() if key.startswith("linked-lib@"))
    assert (linked.entry_class, linked.findings) == (entry_class, findings)


def test_a_file_source_is_read_from_its_selector_as_yarn_reads_it() -> None:
    """Yarn fetches the path after ``#``, so an escaping selector escapes whatever precedes it."""
    entries = _entries(_edited("#./local-lib::hash=ddd187", "#../../evil::hash=ddd187"))
    local = next(entry for key, entry in entries.items() if key.startswith("local-lib@"))
    assert (local.entry_class, local.findings) == ("unpinned", ("path-escape",))


@pytest.mark.parametrize(
    ("old", "new", "key_prefix", "entry_class", "findings"),
    [
        ('::version=1.22.8&hash=9bd1a5"', '"', "resolve@patch:", "artifact-pinned", ()),
        (
            'resolution: "resolve@patch:resolve@npm%3A1.22.8#optional!builtin<compat/resolve>::version=1.22.8&hash=9bd1a5"',
            'resolution: "resolve@patch:resolve@npm%3A1.22.8"',
            "resolve@patch:",
            "unclassified",
            ("unknown-form",),
        ),
        (
            'resolution: "linked-lib@link:./linked-lib::',
            'resolution: "linked-lib@link:../../outside::',
            "linked-lib@",
            "unpinned",
            ("path-escape",),
        ),
        (
            'resolution: "linked-lib@link:./linked-lib::',
            'resolution: "linked-lib@exec:./build.js::',
            "linked-lib@",
            "unclassified",
            ("unknown-form",),
        ),
        (
            '  resolution: "ms@npm:2.1.2"\n',
            '  resolution: "ms@https://evil.example/ms-2.1.2.tgz"\n',
            "ms@",
            "artifact-pinned",
            ("origin-mismatch",),
        ),
        (
            '  resolution: "ms@npm:2.1.2"\n',
            '  resolution: "ms@ftp://mirror.example/ms.tgz"\n',
            "ms@",
            "unclassified",
            ("unknown-form",),
        ),
        (
            '  resolution: "ms@npm:2.1.2"\n',
            "  resolution:\n    nested: x\n",
            "ms@",
            "unclassified",
            ("unknown-form",),
        ),
        (
            '  resolution: "ms@npm:2.1.2"\n',
            "  unresolved: x\n",
            "ms@",
            "unclassified",
            ("unknown-form",),
        ),
        (
            '"ms@npm:2.1.2":\n  version: 2.1.2\n',
            '"ms@npm:2.1.2":\n  version: ""\n',
            "ms@",
            "unclassified",
            ("unknown-form",),
        ),
        (
            'resolution: "resolve@patch:resolve@npm%3A1.22.8#optional!builtin<compat/resolve>::version=1.22.8&hash=9bd1a5"',
            f'resolution: "resolve@patch:resolve@npm%3A1.22.8::{ROOT}"',
            "resolve@patch:",
            "unclassified",
            ("unknown-form",),
        ),
        (
            'resolution: "rigor-lockfile-fixture-yarn-berry@workspace:."',
            'resolution: "rigor-lockfile-fixture-yarn-berry@workspace:../outside"',
            "rigor-lockfile-fixture-yarn-berry@",
            "unpinned",
            ("path-escape",),
        ),
    ],
)
def test_other_resolutions_are_classified_by_their_protocol(
    old: str, new: str, key_prefix: str, entry_class: str, findings: tuple[str, ...]
) -> None:
    """Patches, local escapes, ``exec:``, tarball URLs and unknown shapes each take their class.

    Parameters
    ----------
    old : str
        The clean text edited.
    new : str
        Its replacement.
    key_prefix : str
        The prefix of the edited entry's key.
    entry_class : str
        The expected class.
    findings : tuple[str, ...]
        The expected findings.
    """
    entries = _entries(_edited(old, new))
    entry = next(entry for key, entry in entries.items() if key.startswith(key_prefix))
    assert (entry.entry_class, entry.findings) == (entry_class, findings)


def test_the_declared_registry_decides_npm_origins() -> None:
    """A declared registry is the origin of every ``npm:`` resolution; unknown is never a pass."""
    config = read_yarnrc_yml('npmRegistryServer: "https://npm.internal.example"\n')
    assert config is not None
    declared = _entries(_text(), BerryRegistryDeclaration(known=True, config=config))[MS_KEY]
    assert (declared.origin, declared.findings) == ("npm.internal.example", ())
    unknown = _entries(_text(), UNKNOWN_BERRY_REGISTRY)[MS_KEY]
    assert (unknown.origin, unknown.findings) == (None, ("origin-unknown",))


@pytest.mark.parametrize(
    ("old", "new", "reason"),
    [
        ("  version: 10\n", "  version: 8\n", "unsupported-version"),
        ("  version: 10\n", "  version: 4\n", "unsupported-version"),
        ("  version: 10\n", "  version: [10]\n", "unsupported-version"),
        ("  version: 10\n", "", "missing-version"),
        ("  cacheKey: 10c0\n", "  cacheKey: 10C0\n", "unparseable"),
        ("  cacheKey: 10c0\n", "  cacheKey: c0\n", "unparseable"),
        ("  cacheKey: 10c0\n", "", "unparseable"),
        ("__metadata:\n  version: 10\n  cacheKey: 10c0\n", "__metadata: 1\n", "unparseable"),
        (
            '"ms@npm:2.1.2":\n  version: 2.1.2\n',
            '"ms@npm:2.1.2":\n  version: 2.1.2\n  version: 2.1.3\n',
            "unparseable",
        ),
        ('"ms@npm:2.1.2":', '"ms@npm:2.1.2": &anchor', "unparseable"),
        ('"ms@npm:2.1.2":', '"debug@npm:4.3.4, ms@npm:2.1.2":', "conflicting-entries"),
        ('"ms@npm:2.1.2":', '"ms@npm:2.1.2, ms@npm:2.1.2":', "conflicting-entries"),
    ],
)
def test_a_lockfile_that_cannot_be_classified_is_refused(old: str, new: str, reason: str) -> None:
    """Only fixture-backed versions are read, and every structural defect refuses the file.

    Parameters
    ----------
    old : str
        The clean text edited.
    new : str
        Its replacement.
    reason : str
        The expected refusal reason.
    """
    with pytest.raises(LockfileRefusal) as refused:
        classify_yarn_berry_lockfile(_edited(old, new), "", DEFAULT)
    assert refused.value.reason == reason


@pytest.mark.parametrize("text", ["- a\n", "a: [\n"])
def test_a_document_that_is_not_one_yaml_mapping_is_unparseable(text: str) -> None:
    """A sequence or invalid YAML is refused before any entry.

    Parameters
    ----------
    text : str
        The refused document.
    """
    with pytest.raises(LockfileRefusal) as refused:
        classify_yarn_berry_lockfile(text, "", DEFAULT)
    assert refused.value.reason == "unparseable"


@pytest.mark.parametrize(
    "replacement",
    ['"ms@npm:2.1.2": {version: 2.1.2, resolution: "ms@npm:2.1.2"}\n', '"ms@npm:2.1.2": x\n'],
)
def test_an_entry_not_written_as_yarn_writes_it_is_unparseable(replacement: str) -> None:
    """An entry must be a block mapping whose fields start on the line after its key.

    Parameters
    ----------
    replacement : str
        The whole ``ms`` entry, rewritten as a flow mapping or a scalar.
    """
    text = _text()
    start = text.index('"ms@npm:2.1.2":')
    end = text.index("\n\n", start) + 1
    with pytest.raises(LockfileRefusal) as refused:
        classify_yarn_berry_lockfile(text[:start] + replacement + text[end:], "", DEFAULT)
    assert refused.value.reason == "unparseable"


def test_an_alias_in_a_field_value_is_refused_even_where_the_layout_holds() -> None:
    """Anchors and aliases are refused by the reader itself, not only by the layout check."""
    text = _text()
    first = text.index("  linkType: hard\n")
    second = text.index("  linkType: hard\n", first + 1)
    edited = (
        text[:first]
        + "  linkType: &kind hard\n"
        + text[first + 17 : second]
        + "  linkType: *kind\n"
        + text[second + 17 :]
    )
    with pytest.raises(LockfileRefusal) as refused:
        classify_yarn_berry_lockfile(edited, "", DEFAULT)
    assert refused.value.reason == "unparseable"


def _ms_entry_rekeyed(key_lines: str) -> str:
    """Return the Yarn 4 fixture with the ``ms`` entry's key line replaced."""
    return _edited('"ms@npm:2.1.2":\n', key_lines)


LONG_KEY = ", ".join(["ms@npm:2.1.2", *(f"ms@npm:2.1.2-long-{index:03d}" for index in range(60))])


def test_a_key_longer_than_1024_characters_is_read_in_yarns_explicit_form() -> None:
    """Yarn writes ``? key`` and a lone ``:`` for a long key; the entry's line is the ``?`` line."""
    text = _ms_entry_rekeyed(f'? "{LONG_KEY}"\n:\n')
    entry = _entries(text)[LONG_KEY]
    assert entry.entry_class == "artifact-pinned"
    assert text.splitlines()[entry.line - 1].startswith('? "ms@npm:2.1.2, ')
    assert entry.notes == ()


@pytest.mark.parametrize(
    "key_lines",
    [
        '? "ms@npm:2.1.2"\n:\n',
        "ms@npm:2.1.2:\n",
        '"ms@npm:2.1.2" :\n',
        f'? "{LONG_KEY}"\n: \n',
        f'? "{LONG_KEY}"\n\n:\n',
    ],
)
def test_a_key_not_written_as_yarn_writes_it_is_unparseable(key_lines: str) -> None:
    """A short explicit key, a plain key that needs quoting, or a stray space are refused.

    Parameters
    ----------
    key_lines : str
        The ``ms`` entry's key lines.
    """
    with pytest.raises(LockfileRefusal) as refused:
        classify_yarn_berry_lockfile(_ms_entry_rekeyed(key_lines), "", DEFAULT)
    assert refused.value.reason == "unparseable"


def test_a_plain_key_is_written_without_quotes() -> None:
    """A key that is a plain YAML string, such as a bare package name, needs no quotes."""
    text = _edited('"ms@npm:2.1.2":\n', "ms-plain:\n")
    entry = _entries(text)["ms-plain"]
    assert (entry.entry_class, dict(entry.notes)) == ("artifact-pinned", {"alias": "ms-plain"})
