# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — pnpm resolution classification witnesses
"""Witness how one pnpm ``resolution`` is classified, as B7 unit 4 Q3 to Q6 and Q8 rule."""

from __future__ import annotations

import pytest

from rigor_foundry.lockfile_model import EntryFinding, LockedEntry
from rigor_foundry.lockfile_pnpm_config import (
    UNKNOWN_PNPM_REGISTRY,
    pnpm_registry_declaration,
    read_pnpm_workspace,
)
from rigor_foundry.lockfile_pnpm_resolution import classify_resolution, git_hosted_reference
from rigor_foundry.workflow_yaml import parse_workflow_yaml

COMMIT = "98e8ff1da1a89f93d1397a24d7413ed15421c139"
CODELOAD = f"https://codeload.github.com/jonschlinkert/is-number/tar.gz/{COMMIT}"
WORKSPACE = read_pnpm_workspace("")
assert WORKSPACE is not None
REGISTRY = pnpm_registry_declaration("9.0", {}, WORKSPACE)


def _integrity() -> str:
    """Return a well-formed sha512 SRI value, built so no encoded literal sits in the source."""
    return "sha512-" + "A" * 86 + "=="


def _classify(
    resolution: str | None,
    name: str = "pkg",
    lock_dir: str = "",
    extra: frozenset[EntryFinding] = frozenset(),
) -> LockedEntry:
    """Classify one resolution written as YAML flow text, or none."""
    value = (
        None if resolution is None else parse_workflow_yaml(f"r: {resolution}\n").mapping()["r"]
    )
    return classify_resolution("key", 3, name, value, lock_dir, REGISTRY, (), extra)


@pytest.mark.parametrize(
    ("url", "reference"),
    [
        (CODELOAD, COMMIT),
        ("https://codeload.github.com/o/r/tar.gz/main", "main"),
        ("https://codeload.github.com/o/r/legacy.tar.gz/main", None),
        (f"https://bitbucket.org/o/r/get/{COMMIT}.tar.gz", COMMIT),
        ("https://bitbucket.org/o/r/get/main.zip", None),
        (f"https://gitlab.com/api/v4/projects/7/repository/archive.tar.gz?ref={COMMIT}", COMMIT),
        (f"https://gitlab.com/g/sub/r/-/archive/{COMMIT}/r-{COMMIT}.tar.gz", COMMIT),
        ("https://gitlab.com/g/r/-/archive/main/r-main.zip", None),
        ("https://gitlab.com/g/r/-/archive/main/r-main.tar.gz/extra", None),
        ("https://gitlab.com/g/r/raw/file", None),
        (f"http://codeload.github.com/o/r/tar.gz/{COMMIT}", None),
        (f"https://example.com/o/r/tar.gz/{COMMIT}", None),
    ],
)
def test_git_host_archive_shapes_are_those_pnpm_11_recognises(
    url: str, reference: str | None
) -> None:
    """codeload, Bitbucket and GitLab archive paths name a reference; nothing else does.

    Parameters
    ----------
    url : str
        A tarball URL.
    reference : str | None
        The reference it names, or ``None``.
    """
    assert git_hosted_reference(url) == reference


def test_a_registry_entry_takes_its_scope_registry_and_is_pinned_by_integrity() -> None:
    """No ``type`` and no ``tarball``: the registry, pinned only by a valid integrity."""
    pinned = _classify(f"{{integrity: {_integrity()}}}")
    assert (pinned.entry_class, pinned.origin, pinned.digest_algorithms) == (
        "artifact-pinned",
        "registry.npmjs.org",
        ("sha512",),
    )
    assert _classify("{}").findings == ("missing-digest",)
    assert _classify("{integrity: [a]}").findings == ("malformed-digest",)
    unknown = classify_resolution(
        "key", 3, "pkg", parse_workflow_yaml("r: {}\n").mapping()["r"], "", UNKNOWN_PNPM_REGISTRY
    )
    assert unknown.findings == ("missing-digest", "origin-unknown")


@pytest.mark.parametrize(
    ("tarball", "origin", "findings", "url_dependency"),
    [
        ("ms/-/ms-2.0.0.tgz", "registry.npmjs.org", (), False),
        ("//evil.example/ms.tgz", "evil.example", ("origin-mismatch",), False),
        ("https://registry.npmjs.org/ms/-/ms-2.0.0.tgz", "registry.npmjs.org", (), True),
        (
            "https://registry.yarnpkg.com/ms/-/ms-2.0.0.tgz",
            "registry.yarnpkg.com",
            ("origin-mismatch",),
            True,
        ),
    ],
)
def test_a_tarball_is_resolved_against_the_registry_as_new_url_does(
    tarball: str, origin: str, findings: tuple[str, ...], url_dependency: bool
) -> None:
    """A relative tarball takes the registry's host; an absolute one is compared and recorded.

    Parameters
    ----------
    tarball : str
        The ``tarball`` value.
    origin : str
        The expected origin host.
    findings : tuple[str, ...]
        The expected findings.
    url_dependency : bool
        Whether ``tarball_url_dependency`` is recorded.
    """
    entry = _classify(f"{{integrity: {_integrity()}, tarball: '{tarball}'}}")
    assert (entry.origin, entry.findings) == (origin, findings)
    assert ("tarball_url_dependency", "true") in entry.notes if url_dependency else not entry.notes


@pytest.mark.parametrize(
    "resolution",
    [
        "{tarball: 'ftp://mirror.example/ms.tgz'}",
        "{tarball: 'https:\\\\evil.example\\ms.tgz'}",
        "{tarball: [a]}",
        "{type: binary, url: 'https://nodejs.org/x.tgz'}",
        "{type: variations, variants: []}",
        "{type: 'custom:cdn'}",
        "{type: [git]}",
        "{type: directory}",
        "{type: binary, directory: local-lib}",
        "{type: directory, directory: [a]}",
        "{type: git, repo: 'git://h/r.git'}",
        "{type: git, commit: 'abc'}",
        "{type: git, repo: [a], commit: 'abc'}",
        f"{{type: git, repo: 'git://h/r.git', commit: {COMMIT}, path: [a]}}",
        "[a]",
        None,
    ],
)
def test_a_resolution_without_a_known_shape_is_unknown(resolution: str | None) -> None:
    """Types without a fixture, broken shapes and odd URLs are ``unknown-form``, never a pass.

    Parameters
    ----------
    resolution : str | None
        The resolution as YAML flow text, or none.
    """
    assert _classify(resolution).findings == ("unknown-form",)


def test_a_relative_tarball_with_an_unknown_registry_has_an_unknown_origin() -> None:
    """With no certain registry, a relative tarball cannot be placed."""
    value = parse_workflow_yaml(
        f"r: {{integrity: {_integrity()}, tarball: 'a/-/a-1.tgz'}}\n"
    ).mapping()["r"]
    entry = classify_resolution("key", 3, "a", value, "", UNKNOWN_PNPM_REGISTRY)
    assert (entry.entry_class, entry.origin, entry.findings) == (
        "artifact-pinned",
        None,
        ("origin-unknown",),
    )


@pytest.mark.parametrize(
    ("resolution", "entry_class", "findings", "archive_commit"),
    [
        (f"{{tarball: '{CODELOAD}'}}", "unpinned", ("missing-digest",), COMMIT),
        (
            f"{{gitHosted: true, integrity: {_integrity()}, tarball: '{CODELOAD}'}}",
            "artifact-pinned",
            (),
            COMMIT,
        ),
        (
            "{tarball: 'https://codeload.github.com/o/r/tar.gz/main'}",
            "unpinned",
            ("missing-digest", "floating-ref"),
            None,
        ),
    ],
)
def test_a_git_host_archive_is_pinned_only_by_its_integrity(
    resolution: str, entry_class: str, findings: tuple[str, ...], archive_commit: str | None
) -> None:
    """Pnpm's exemption does not bind the bytes: without integrity it is ``missing-digest``.

    Parameters
    ----------
    resolution : str
        The resolution as YAML flow text.
    entry_class : str
        The expected class.
    findings : tuple[str, ...]
        The expected findings.
    archive_commit : str | None
        The commit recorded as evidence.
    """
    entry = _classify(resolution)
    assert (entry.entry_class, entry.findings, entry.archive_commit, entry.origin) == (
        entry_class,
        findings,
        archive_commit,
        "codeload.github.com",
    )


@pytest.mark.parametrize(
    ("resolution", "entry_class", "findings", "origin", "notes"),
    [
        (
            f"{{type: git, repo: 'git://127.0.0.1:19419/vcs-lib.git', commit: {COMMIT}}}",
            "commit-pinned",
            (),
            "127.0.0.1",
            {},
        ),
        (
            f"{{type: git, repo: 'https://github.com/o/r.git', commit: {COMMIT}, path: packages/a}}",
            "commit-pinned",
            (),
            "github.com",
            {"git_path": "packages/a"},
        ),
        (
            "{type: git, repo: 'git+ssh://git@host.example/r.git', commit: 'abc1234'}",
            "unpinned",
            ("floating-ref",),
            "host.example",
            {},
        ),
    ],
)
def test_a_git_clone_is_pinned_by_a_full_commit(
    resolution: str,
    entry_class: str,
    findings: tuple[str, ...],
    origin: str,
    notes: dict[str, str],
) -> None:
    """``type: git`` is a clone: a full commit pins it; ``path`` is recorded.

    Parameters
    ----------
    resolution : str
        The resolution as YAML flow text.
    entry_class : str
        The expected class.
    findings : tuple[str, ...]
        The expected findings.
    origin : str
        The repository host.
    notes : dict[str, str]
        The expected notes.
    """
    entry = _classify(resolution)
    assert (entry.entry_class, entry.findings, entry.origin, dict(entry.notes)) == (
        entry_class,
        findings,
        origin,
        notes,
    )


@pytest.mark.parametrize(
    ("resolution", "lock_dir", "entry_class", "findings"),
    [
        ("{type: directory, directory: local-lib}", "web", "local", ()),
        ("{type: directory, directory: ../../outside}", "web", "unpinned", ("path-escape",)),
        ("{type: directory, directory: /abs}", "", "unpinned", ("path-escape",)),
        (f"{{integrity: {_integrity()}, tarball: 'file:local-tgz/a-1.0.0.tgz'}}", "", "local", ()),
        ("{tarball: 'file:../outside.tgz'}", "", "unpinned", ("path-escape",)),
    ],
)
def test_local_sources_resolve_from_the_lockfile_directory(
    resolution: str, lock_dir: str, entry_class: str, findings: tuple[str, ...]
) -> None:
    """Folders and ``file:`` tarballs are local; outside the repository they escape.

    Parameters
    ----------
    resolution : str
        The resolution as YAML flow text.
    lock_dir : str
        The lockfile's directory.
    entry_class : str
        The expected class.
    findings : tuple[str, ...]
        The expected findings.
    """
    entry = _classify(resolution, lock_dir=lock_dir)
    assert (entry.entry_class, entry.findings) == (entry_class, findings)
    if "integrity" in resolution:
        assert (entry.digest_algorithms, entry.digest_scope) == (("sha512",), "artifact")


@pytest.mark.parametrize(
    "resolution",
    [
        f"{{integrity: {_integrity()}}}",
        f"{{integrity: {_integrity()}, tarball: 'https://registry.npmjs.org/a/-/a-1.tgz'}}",
        f"{{gitHosted: true, integrity: {_integrity()}, tarball: '{CODELOAD}'}}",
        f"{{type: git, repo: 'git://h/r.git', commit: {COMMIT}}}",
        "{type: directory, directory: local-lib}",
        f"{{integrity: {_integrity()}, tarball: 'a/-/a-1.tgz'}}",
    ],
)
def test_a_patch_finding_unpins_every_shape(resolution: str) -> None:
    """A patch file outside the repository unpins the patched entry, whatever it is.

    Parameters
    ----------
    resolution : str
        The resolution as YAML flow text.
    """
    entry = _classify(resolution, extra=frozenset({"path-escape"}))
    assert entry.entry_class == "unpinned"
    assert "path-escape" in entry.findings


def test_a_relative_tarball_with_an_unknown_registry_keeps_a_patch_finding() -> None:
    """The patch finding survives beside ``origin-unknown``."""
    value = parse_workflow_yaml("r: {tarball: 'a/-/a-1.tgz'}\n").mapping()["r"]
    entry = classify_resolution(
        "key", 3, "a", value, "", UNKNOWN_PNPM_REGISTRY, (), frozenset({"path-escape"})
    )
    assert entry.findings == ("missing-digest", "origin-unknown", "path-escape")


def test_a_backslash_in_a_tarball_is_unknown_because_urls_read_it_as_a_slash() -> None:
    """WHATWG URL parsing reads a backslash as a slash, so two of them start another host."""
    tarball = f"{chr(92) * 2}evil.example{chr(92)}ms.tgz"
    entry = _classify(f"{{integrity: {_integrity()}, tarball: '{tarball}'}}")
    assert entry.findings == ("unknown-form",)
