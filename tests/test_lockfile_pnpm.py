# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — pnpm lockfile classification witnesses
"""Witness pnpm classification on lockfiles pnpm 8.15.9 to 12.23.0 generated.

See each fixture's GENERATED_BY.txt. Every failing case is one recorded edit of a clean
lockfile, written out in the test that uses it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from pathlib import Path

import pytest
from lockfile_repository_support import fixture_text

from rigor_foundry.lockfile_model import LockedEntry, LockfileRefusal
from rigor_foundry.lockfile_pnpm import classify_pnpm_lockfile, dep_path_base, split_documents
from rigor_foundry.lockfile_pnpm_config import PnpmWorkspace, read_pnpm_workspace

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lockfiles"
P8 = FIXTURES / "pnpm-8.15.9-v6"
P9 = FIXTURES / "pnpm-9.15.9-v9"
P10 = FIXTURES / "pnpm-10.34.9-v9"
P11 = FIXTURES / "pnpm-11.29.0-v9"
P11_ENV = FIXTURES / "pnpm-11.29.0-env-v9"
P12_ENV = FIXTURES / "pnpm-12.23.0-env-v9"
P8_SINGLE = FIXTURES / "pnpm-8.15.9-single-v6"
P9_SINGLE = FIXTURES / "pnpm-9.15.9-single-v9"
COMMIT = "98e8ff1da1a89f93d1397a24d7413ed15421c139"
NO_WORKSPACE = PnpmWorkspace()


def _text(fixture: Path) -> str:
    """Return a clean lockfile's text."""
    return fixture_text(fixture / "pnpm-lock.yaml.gz")


def _workspace(fixture: Path) -> PnpmWorkspace:
    """Return the fixture's own ``pnpm-workspace.yaml``, read with certainty."""
    path = fixture / "pnpm-workspace.yaml.gz"
    workspace = read_pnpm_workspace(fixture_text(path)) if path.exists() else NO_WORKSPACE
    assert workspace is not None
    return workspace


def _edited(fixture: Path, old: str, new: str) -> str:
    """Return a clean lockfile with exactly one recorded edit."""
    text = _text(fixture)
    assert text.count(old) == 1, old
    return text.replace(old, new)


def _entries(
    text: str,
    workspace: PnpmWorkspace | None = NO_WORKSPACE,
    hosts: dict[str, str] | None = None,
    lock_dir: str = "",
) -> dict[str, LockedEntry]:
    """Classify a lockfile and index its entries by key."""
    _, entries = classify_pnpm_lockfile(text, lock_dir, {} if hosts is None else hosts, workspace)
    return {entry.key: entry for entry in entries}


@pytest.mark.parametrize(
    ("fixture", "version", "classes", "findings"),
    [
        (
            P8,
            "6.0",
            {"local": 5, "artifact-pinned": 4, "commit-pinned": 1, "unpinned": 2},
            {"missing-digest": 2, "origin-mismatch": 1},
        ),
        (
            P9,
            "9.0",
            {"local": 5, "artifact-pinned": 4, "commit-pinned": 1, "unpinned": 2},
            {"missing-digest": 2, "origin-mismatch": 1},
        ),
        (
            P10,
            "9.0",
            {"local": 5, "artifact-pinned": 6, "commit-pinned": 1},
            {"origin-mismatch": 1},
        ),
        (
            P11,
            "9.0",
            {"local": 5, "artifact-pinned": 6, "commit-pinned": 1},
            {"origin-mismatch": 1},
        ),
        (P11_ENV, "9.0", {"artifact-pinned": 3}, {}),
        (P12_ENV, "9.0", {"artifact-pinned": 20}, {}),
        (P8_SINGLE, "6.0", {"local": 1, "artifact-pinned": 2}, {}),
        (P9_SINGLE, "9.0", {"local": 1, "artifact-pinned": 2}, {}),
    ],
)
def test_each_clean_lockfile_classifies_as_the_rulings_say(
    fixture: Path, version: str, classes: dict[str, int], findings: dict[str, int]
) -> None:
    """Every real lockfile reads, with the classes and findings its sources call for.

    Parameters
    ----------
    fixture : Path
        The clean fixture.
    version : str
        Its ``lockfileVersion``.
    classes : dict[str, int]
        The count of each class.
    findings : dict[str, int]
        The count of each finding.
    """
    found, entries = classify_pnpm_lockfile(_text(fixture), "", {}, _workspace(fixture))
    assert found == version
    assert dict(Counter(entry.entry_class for entry in entries)) == classes
    assert dict(Counter(finding for entry in entries for finding in entry.findings)) == findings


@pytest.mark.parametrize(
    ("fixture", "patch_key", "archive_key", "tarball_key", "patch_hash"),
    [
        (
            P8,
            "/ms@2.1.2(patch_hash=y57fqylhrn67pmfdfc22sorfim)",
            f"github.com/jonschlinkert/is-number/{COMMIT}",
            "@registry.yarnpkg.com/ms/-/ms-2.0.0.tgz",
            "y57fqylhrn67pmfdfc22sorfim",
        ),
        (
            P9,
            "ms@2.1.2",
            f"is-number@https://codeload.github.com/jonschlinkert/is-number/tar.gz/{COMMIT}",
            "ms@https://registry.yarnpkg.com/ms/-/ms-2.0.0.tgz",
            "y57fqylhrn67pmfdfc22sorfim",
        ),
        (
            P11,
            "ms@2.1.2",
            f"is-number@https://codeload.github.com/jonschlinkert/is-number/tar.gz/{COMMIT}",
            "ms@https://registry.yarnpkg.com/ms/-/ms-2.0.0.tgz",
            "450cf88d3848a7314926a1615960a380cbdce2f6bff55565f815c2ce758d9ae7",
        ),
    ],
)
def test_patches_archives_and_url_tarballs_carry_their_evidence(
    fixture: Path, patch_key: str, archive_key: str, tarball_key: str, patch_hash: str
) -> None:
    """The patch hash and path, the archive commit, and the URL dependency are recorded.

    Parameters
    ----------
    fixture : Path
        The clean fixture.
    patch_key : str
        The patched package's key.
    archive_key : str
        The GitHub archive's key.
    tarball_key : str
        The URL tarball's key.
    patch_hash : str
        The patch hash pnpm wrote.
    """
    entries = _entries(_text(fixture), _workspace(fixture))
    assert dict(entries[patch_key].notes) == {
        "patch_hash": patch_hash,
        "patch_source": "patches/ms@2.1.2.patch",
    }
    assert (entries[archive_key].archive_commit, entries[archive_key].origin) == (
        COMMIT,
        "codeload.github.com",
    )
    assert dict(entries[tarball_key].notes) == {"tarball_url_dependency": "true"}
    assert entries["packages/ws-a › linked-lib"].entry_class == "local"
    assert entries[". › ws-a"].entry_class == "local"


def test_the_env_document_is_read_and_keyed_by_its_document() -> None:
    """Pnpm 12 pins itself and its platform binaries in the env document; each is an entry."""
    text = _text(P12_ENV)
    entries = _entries(text)
    lines = text.splitlines()
    env = {key for key in entries if key.startswith("env › ")}
    assert "env › ms@2.1.3" in env
    assert "env › pnpm@12.23.0" in env
    assert len([key for key in env if key.startswith("env › @pnpm/exe.")]) == 16
    assert lines[entries["env › ms@2.1.3"].line - 1] == "  ms@2.1.3:"
    assert lines[entries["debug@4.3.4"].line - 1] == "  debug@4.3.4:"
    assert entries["env › ms@2.1.3"].line < entries["debug@4.3.4"].line


def test_crlf_is_read_as_pnpm_reads_it() -> None:
    """Pnpm turns CRLF into LF before splitting the documents."""
    text = _text(P11_ENV)
    assert _entries(text.replace("\n", "\r\n")) == _entries(text)


def test_the_documents_split_as_extract_main_document_does() -> None:
    """One document, or an env document then the main one; an env document alone is refused."""
    assert split_documents("lockfileVersion: '9.0'\n") == (("lockfileVersion: '9.0'\n", 0, ""),)
    assert split_documents("---\na: 1\n---\nb: 2\n") == (("a: 1", 1, "env › "), ("b: 2\n", 3, ""))
    with pytest.raises(LockfileRefusal) as refused:
        split_documents("---\na: 1\n")
    assert refused.value.reason == "unsupported-version"


@pytest.mark.parametrize(
    ("key", "base", "patch"),
    [
        ("ms@2.1.2", "ms@2.1.2", None),
        ("ms@2.1.2(patch_hash=abc)", "ms@2.1.2", "abc"),
        ("a@1.0.0(patch_hash=abc)(b@2.0.0(c@3.0.0))", "a@1.0.0", "abc"),
        ("a@1.0.0(b@2.0.0)", "a@1.0.0", None),
        ("a)", "a)", None),
    ],
)
def test_a_dep_path_suffix_splits_as_index_of_dep_path_suffix(
    key: str, base: str, patch: str | None
) -> None:
    """Peer and patch suffixes come off the end, matching parentheses as pnpm does.

    Parameters
    ----------
    key : str
        The dependency path.
    base : str
        The path without its suffix.
    patch : str | None
        The patch hash it names.
    """
    assert dep_path_base(key) == (base, patch)


def test_pnpm_11_hash_only_patches_need_the_workspace_file() -> None:
    """Without the tracked ``pnpm-workspace.yaml`` entry, the patched package is unknown."""
    text = _text(P11)
    assert _entries(text, None)["ms@2.1.2"].findings == ("unknown-form",)
    assert _entries(text, NO_WORKSPACE)["ms@2.1.2"].findings == ("unknown-form",)


def test_a_patch_file_outside_the_repository_unpins_the_package() -> None:
    """The patch path is resolved from the lockfile's directory."""
    edited = _edited(P9, "    path: patches/ms@2.1.2.patch\n", "    path: ../outside.patch\n")
    entry = _entries(edited)["ms@2.1.2"]
    assert (entry.entry_class, entry.findings) == ("unpinned", ("path-escape",))


def test_a_6_0_lockfile_never_reads_the_workspace_registry() -> None:
    """Pnpm 8 ignores ``pnpm-workspace.yaml`` registries; ``.npmrc`` decides."""
    workspace = read_pnpm_workspace('registry: "https://elsewhere.example"\n')
    entries = _entries(_text(P8), workspace)
    assert entries["/left-pad@1.3.0"].origin == "registry.npmjs.org"
    mirrored = _entries(_text(P8), workspace, {"": "mirror.example"})
    assert (mirrored["/left-pad@1.3.0"].origin, mirrored["/left-pad@1.3.0"].findings) == (
        "mirror.example",
        (),
    )


def test_a_9_0_lockfile_with_disagreeing_files_has_unknown_origins() -> None:
    """``.npmrc`` and ``pnpm-workspace.yaml`` naming different default hosts: unknown."""
    workspace = read_pnpm_workspace('registry: "https://two.example"\n')
    entry = _entries(_text(P9), workspace, {"": "one.example"})["left-pad@1.3.0"]
    assert entry.findings == ("origin-unknown",)


@pytest.mark.parametrize(
    ("fixture", "old", "new", "key", "findings"),
    [
        (P9, "  packages/ws-a:\n", "  ../outside:\n", "../outside › linked-lib", ("path-escape",)),
        (
            P9,
            "        version: link:../../linked-lib\n",
            "        version: link:../../../x\n",
            "packages/ws-a › linked-lib",
            ("path-escape",),
        ),
        (
            P8_SINGLE,
            "    version: link:linked-lib\n",
            "    version: link:../x\n",
            ". › linked-lib",
            ("path-escape",),
        ),
    ],
)
def test_an_importer_link_must_stay_inside_the_repository(
    fixture: Path, old: str, new: str, key: str, findings: tuple[str, ...]
) -> None:
    """A link is resolved from its importer's directory, which must also stay inside.

    Parameters
    ----------
    fixture : Path
        The clean fixture.
    old : str
        The clean text edited.
    new : str
        Its replacement.
    key : str
        The link entry's key.
    findings : tuple[str, ...]
        The expected findings.
    """
    entry = _entries(_edited(fixture, old, new))[key]
    assert (entry.entry_class, entry.findings) == ("unpinned", findings)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("  left-pad@1.3.0:\n", "  'left-pad@1.3.0':\n"),
        ("  left-pad@1.3.0:\n", '  "left-pad@1.3.0":\n'),
    ],
)
def test_a_quoted_key_reads_as_its_value(old: str, new: str) -> None:
    """js-yaml may quote a key; its unquoted value is the key.

    Parameters
    ----------
    old : str
        The clean key line.
    new : str
        The quoted key line.
    """
    edited = _edited(P9, old, new)
    edited = edited.replace("  left-pad@1.3.0: {}\n", "  'left-pad@1.3.0': {}\n")
    assert _entries(edited)["left-pad@1.3.0"].entry_class == "artifact-pinned"


def test_a_key_over_1024_characters_is_read_in_the_explicit_form() -> None:
    """A long key is written after ``? `` with the ``:`` alone on the next line."""
    long_key = "/left-pad@1.3.0(" + "a" * 1100 + ")"
    edited = _edited(P8, "  /left-pad@1.3.0:\n", f"  ? {long_key}\n  :\n")
    entries = _entries(edited)
    assert entries[long_key].entry_class == "artifact-pinned"
    assert edited.splitlines()[entries[long_key].line - 1].startswith("  ? /left-pad")


@pytest.mark.parametrize(
    ("fixture", "old", "new", "reason"),
    [
        (P9, "lockfileVersion: '9.0'\n", "lockfileVersion: '6.1'\n", "unsupported-version"),
        (P9, "lockfileVersion: '9.0'\n", "lockfileVersion: '7.0'\n", "unsupported-version"),
        (P9, "lockfileVersion: '9.0'\n", "lockfileVersion: 5.4\n", "unsupported-version"),
        (P9, "lockfileVersion: '9.0'\n", "lockfileVersion: [9]\n", "unsupported-version"),
        (P9, "lockfileVersion: '9.0'\n", "", "missing-version"),
        (
            P12_ENV,
            "---\nlockfileVersion: '9.0'\n\nimporters:",
            "---\nlockfileVersion: '6.0'\n\nimporters:",
            "unsupported-version",
        ),
        (P9, "lockfileVersion: '9.0'\n", "- a\n", "unparseable"),
        (P9, "lockfileVersion: '9.0'\n", "lockfileVersion: [\n", "unparseable"),
        (P9, "\npackages:\n", "\npackages: []\nunused:\n", "unparseable"),
        (
            P9,
            "  left-pad@1.3.0:\n    resolution:",
            "  left-pad@1.3.0: x\n  unused:\n    resolution:",
            "unparseable",
        ),
        (P9, "  left-pad@1.3.0: {}\n", "  left-pad@9.9.9: {}\n", "unparseable"),
        (P9, "\nimporters:\n", "\nimporters: []\nunused:\n", "unparseable"),
        (P9_SINGLE, "\n  .:\n", "\n  .: x\n  unused:\n", "unparseable"),
        (P9_SINGLE, "        version: 4.3.4\n", "", "unparseable"),
        (
            P9_SINGLE,
            "      debug:\n        specifier: 4.3.4\n        version: 4.3.4\n",
            "      debug: x\n",
            "unparseable",
        ),
        (P9, "    hash: y57fqylhrn67pmfdfc22sorfim\n", "", "unparseable"),
        (
            P9,
            "  ms@2.1.2:\n    hash: y57fqylhrn67pmfdfc22sorfim\n    path: patches/ms@2.1.2.patch\n",
            "  ms@2.1.2: [a]\n",
            "unparseable",
        ),
        (P9, "    hash: y57fqylhrn67pmfdfc22sorfim\n", "    hash: other\n", "unparseable"),
        (P8, "  /left-pad@1.3.0:\n", "  ? /left-pad@1.3.0\n  :\n", "unparseable"),
        (
            P8,
            "  /left-pad@1.3.0:\n    resolution: {",
            "  /left-pad@1.3.0: {resolution: {",
            "unparseable",
        ),
    ],
)
def test_a_lockfile_that_cannot_be_classified_is_refused(
    fixture: Path, old: str, new: str, reason: str
) -> None:
    """Only fixture-backed versions are read, and every structural defect refuses the file.

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
    with pytest.raises(LockfileRefusal) as refused:
        classify_pnpm_lockfile(_edited(fixture, old, new), "", {}, NO_WORKSPACE)
    assert refused.value.reason == reason


def _ms_flow(text: str) -> str:
    """Rewrite the ``ms@2.1.3`` package of the pnpm 9 fixture as a flow mapping on its key line."""
    start = text.index("  ms@2.1.3:\n    resolution: ")
    end = text.index("\n", start + len("  ms@2.1.3:\n"))
    resolution = text[start + len("  ms@2.1.3:\n    resolution: ") : end]
    return text[:start] + f"  ms@2.1.3: {{resolution: {resolution}}}" + text[end:]


@pytest.mark.parametrize(
    "edit",
    [
        _ms_flow,
        lambda text: text.replace(
            "  ms@2.1.3:\n    resolution:", "  ms@2.1.3:\n    # note:\n    resolution:", 1
        ),
        lambda text: text.replace("  left-pad@1.3.0:\n", '  "left\\x2dpad@1.3.0":\n', 1),
        lambda text: "- a\n",
    ],
)
def test_a_layout_js_yaml_does_not_write_is_unparseable(edit: Callable[[str], str]) -> None:
    """A flow entry, a comment between key and fields, an escape JSON cannot read, a list.

    Parameters
    ----------
    edit : Callable[[str], str]
        The recorded edit of the clean pnpm 9 lockfile.
    """
    with pytest.raises(LockfileRefusal) as refused:
        classify_pnpm_lockfile(edit(_text(P9)), "", {}, NO_WORKSPACE)
    assert refused.value.reason == "unparseable"


def test_a_patch_declared_without_a_path_is_unknown() -> None:
    """``patchedDependencies`` with a hash and no ``path`` cannot show which patch applies."""
    edited = _edited(P9, "    path: patches/ms@2.1.2.patch\n", "")
    assert _entries(edited)["ms@2.1.2"].findings == ("unknown-form",)


def test_a_6_0_non_registry_entry_takes_its_name_from_its_name_field() -> None:
    """A 6.0 key such as ``@registry.yarnpkg.com/…`` is not a name; ``name`` picks the scope."""
    edited = _edited(P8, "    name: ms\n", "    name: '@acme/ms'\n")
    entry = _entries(edited, None, {"@acme": "registry.yarnpkg.com"})[
        "@registry.yarnpkg.com/ms/-/ms-2.0.0.tgz"
    ]
    assert entry.origin == "registry.yarnpkg.com"
    assert "origin-mismatch" not in entry.findings


def test_an_absolute_importer_path_escapes() -> None:
    """An importer outside the repository makes its links escape, however they read."""
    entry = _entries(_edited(P9, "  packages/ws-a:\n", "  /abs:\n"))["/abs › linked-lib"]
    assert (entry.entry_class, entry.findings) == ("unpinned", ("path-escape",))


def test_anchors_and_aliases_are_unparseable_in_a_lockfile() -> None:
    """The lockfile reader refuses YAML references, as unit 3 does for Yarn."""
    note = "    deprecated: use String.prototype.padStart()\n"
    edited = _edited(P9, note, "    deprecated: &note use String.prototype.padStart()\n")
    edited = edited.replace(
        "  ms@2.1.3:\n    resolution:", "  ms@2.1.3:\n    deprecated: *note\n    resolution:", 1
    )
    with pytest.raises(LockfileRefusal) as refused:
        classify_pnpm_lockfile(edited, "", {}, NO_WORKSPACE)
    assert refused.value.reason == "unparseable"


def test_a_6_0_file_with_both_top_level_groups_and_importers_is_unparseable() -> None:
    """Pnpm 8 writes a single project's groups or a workspace's importers, never both."""
    edited = _edited(P8_SINGLE, "\npackages:\n", "\nimporters:\n  .: {}\n\npackages:\n")
    with pytest.raises(LockfileRefusal) as refused:
        classify_pnpm_lockfile(edited, "", {}, NO_WORKSPACE)
    assert refused.value.reason == "unparseable"
