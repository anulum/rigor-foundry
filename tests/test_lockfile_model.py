# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — lockfile classification model witnesses
"""Witness every rule the lockfile model enforces when an entry or a file result is built."""

from __future__ import annotations

from typing import Any

import pytest

from rigor_foundry.lockfile_model import (
    ENTRY_CLASSES,
    ENTRY_FINDINGS,
    PIN_FAILURES,
    REFUSAL_REASONS,
    LockedEntry,
    LockfileRefusal,
    LockfileResult,
)

FILE_SHA256 = "a" * 64
PINNED: dict[str, Any] = {
    "key": "node_modules/left-pad",
    "line": 4,
    "entry_class": "artifact-pinned",
    "digest_algorithms": ("sha512",),
    "digest_scope": "artifact",
    "origin": "registry.npmjs.org",
}


def _entry(**changes: Any) -> LockedEntry:
    """Build an entry from the artifact-pinned baseline with the given fields changed."""
    return LockedEntry(**{**PINNED, **changes})


def test_the_class_and_reason_vocabularies_are_the_amended_v1_lists() -> None:
    """Six classes, nine findings and eight refusal reasons, as B7 v1 and its addenda name them."""
    assert ENTRY_CLASSES == (
        "artifact-pinned",
        "commit-pinned",
        "local",
        "unpinned",
        "unclassified",
        "graph-only",
    )
    assert len(ENTRY_FINDINGS) == 9
    assert {
        "missing-digest",
        "weak-digest",
        "malformed-digest",
        "floating-ref",
        "path-escape",
    } == PIN_FAILURES
    assert len(REFUSAL_REASONS) == 8


@pytest.mark.parametrize(
    "changes",
    [
        {},
        {"entry_class": "commit-pinned", "commit_hash_algorithm": "sha1", "digest_scope": None},
        {"entry_class": "local", "digest_algorithms": (), "digest_scope": None, "origin": None},
        {"entry_class": "unpinned", "form": "artifact", "findings": ("missing-digest",)},
        {
            "entry_class": "unpinned",
            "form": "vcs",
            "findings": ("floating-ref", "origin-mismatch"),
        },
        {"entry_class": "unpinned", "form": "path", "findings": ("path-escape",)},
        {"entry_class": "unclassified", "findings": ("unknown-form",)},
        {"entry_class": "graph-only", "digest_scope": None},
        {"findings": ("origin-mismatch",)},
        {"findings": ("origin-unknown",)},
        {"digest_scope": "parent-artifact", "inherited_from": "node_modules/parent"},
        {"archive_commit": "c" * 40, "commit_hash_algorithm": "sha1"},
        {"notes": (("alias", "foo"), ("patch_source", "builtin<compat/resolve>"))},
        {
            "entry_class": "unpinned",
            "form": "artifact",
            "findings": ("missing-digest",),
            "digest_algorithms": (),
            "digest_scope": None,
            "archive_commit": "c" * 64,
            "commit_hash_algorithm": "sha256",
        },
    ],
)
def test_entries_that_keep_every_rule_are_built(changes: dict[str, Any]) -> None:
    """Each class, with the findings and fields its rules require, is a valid entry.

    Parameters
    ----------
    changes : dict[str, Any]
        Fields changed from the artifact-pinned baseline.
    """
    entry = _entry(**changes)
    data = entry.to_dict()
    assert data["class"] == entry.entry_class
    assert data["findings"] == list(entry.findings)
    assert set(data) == {
        "key",
        "line",
        "class",
        "form",
        "findings",
        "digest_algorithms",
        "digest_scope",
        "commit_hash_algorithm",
        "origin",
        "inherited_from",
        "archive_commit",
        "notes",
    }


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"key": ""}, "needs a key"),
        ({"line": 0}, "1-based"),
        ({"entry_class": "pinned"}, "known class"),
        ({"findings": ("tampered",)}, "known, unique"),
        ({"findings": ("origin-unknown", "origin-mismatch")}, "fixed order"),
        ({"findings": ("origin-mismatch", "origin-mismatch")}, "unique"),
        ({"digest_algorithms": ("sha3",)}, "algorithms must be known"),
        ({"form": "artifact"}, "only an unpinned entry"),
        ({"entry_class": "unpinned", "findings": ("missing-digest",)}, "only an unpinned entry"),
        ({"entry_class": "unpinned", "form": "artifact"}, "names its pin failure"),
        (
            {"entry_class": "unpinned", "form": "vcs", "findings": ("origin-mismatch",)},
            "names its pin failure",
        ),
        ({"findings": ("weak-digest",)}, "pinned entry carries no pin failure"),
        (
            {
                "entry_class": "commit-pinned",
                "commit_hash_algorithm": "sha1",
                "findings": ("floating-ref",),
            },
            "pinned entry carries no pin failure",
        ),
        (
            {"entry_class": "local", "digest_scope": None, "findings": ("path-escape",)},
            "pinned entry carries no pin failure",
        ),
        ({"entry_class": "unclassified"}, "unclassified entries carry unknown-form"),
        (
            {
                "entry_class": "unpinned",
                "form": "artifact",
                "findings": ("missing-digest", "unknown-form"),
            },
            "unclassified entries carry unknown-form",
        ),
        ({"entry_class": "commit-pinned"}, "commit hash algorithm"),
        ({"commit_hash_algorithm": "sha1"}, "commit hash algorithm"),
        ({"archive_commit": "c" * 40}, "commit hash algorithm"),
        ({"notes": (("patch_source", "x"), ("alias", "foo"))}, "ordered by name"),
        ({"notes": (("alias", "a"), ("alias", "b"))}, "ordered by name"),
        ({"notes": (("alias", ""),)}, "non-empty"),
        ({"notes": (("", "x"),)}, "non-empty"),
        (
            {
                "entry_class": "unpinned",
                "form": "vcs",
                "findings": ("floating-ref",),
                "archive_commit": "c" * 40,
                "commit_hash_algorithm": "sha1",
            },
            "only an artifact records the commit",
        ),
        ({"digest_algorithms": ()}, "records its digests and their scope"),
        ({"digest_scope": None}, "records its digests and their scope"),
        ({"digest_scope": "parent-artifact"}, "name that parent"),
        ({"inherited_from": "node_modules/parent"}, "name that parent"),
    ],
)
def test_an_entry_that_breaks_a_rule_is_refused(changes: dict[str, Any], message: str) -> None:
    """Every model rule refuses the entry that breaks it.

    Parameters
    ----------
    changes : dict[str, Any]
        Fields changed from the artifact-pinned baseline.
    message : str
        The rule's message.
    """
    with pytest.raises(ValueError, match=message):
        _entry(**changes)


def _result(**changes: Any) -> LockfileResult:
    """Build a classified npm result from a baseline with the given fields changed."""
    baseline: dict[str, Any] = {
        "path": "package-lock.json",
        "file_sha256": FILE_SHA256,
        "kind": "npm",
        "format_version": "3",
        "refusal_reason": None,
        "entries": (_entry(), _entry(key="node_modules/z", line=9)),
    }
    return LockfileResult(**{**baseline, **changes})


def test_a_classified_and_a_refused_file_serialise_every_field() -> None:
    """A classified file lists its entries; a refused file names its reason and has none."""
    result = _result()
    classified = result.to_dict()
    assert classified["status"] == "classified"
    assert [entry.line for entry in result.entries] == [4, 9]
    assert classified["entries"] == [entry.to_dict() for entry in result.entries]
    refused = _result(
        kind=None, format_version=None, refusal_reason="ambiguous-yarn-lock", entries=()
    )
    assert refused.status == "refused"
    assert refused.to_dict() == {
        "path": "package-lock.json",
        "file_sha256": FILE_SHA256,
        "kind": None,
        "format_version": None,
        "status": "refused",
        "refusal_reason": "ambiguous-yarn-lock",
        "entries": [],
        "checksum_behavior": None,
        "unused_patches": None,
    }


def test_entries_on_one_line_are_ordered_by_key() -> None:
    """Two entries that start on one line are ordered by key."""
    result = _result(entries=(_entry(key="a", line=2), _entry(key="b", line=2)))
    assert [entry.key for entry in result.entries] == ["a", "b"]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"path": ""}, "needs its path"),
        ({"file_sha256": "A" * 64}, "lowercase SHA-256"),
        ({"file_sha256": "a" * 63}, "lowercase SHA-256"),
        ({"refusal_reason": "tampered", "entries": ()}, "known reason"),
        ({"refusal_reason": "unparseable"}, "no entry results"),
        ({"kind": None}, "may lack a kind"),
        ({"format_version": None}, "records its format version"),
        ({"entries": (_entry(line=9), _entry(key="b", line=4))}, "ordered by line"),
        ({"entries": (_entry(key="b", line=4), _entry(key="a", line=4))}, "ordered by line"),
        ({"entries": (_entry(), _entry(line=9))}, "unique"),
    ],
)
def test_a_file_result_that_breaks_a_rule_is_refused(
    changes: dict[str, Any], message: str
) -> None:
    """Every file-level rule refuses the result that breaks it.

    Parameters
    ----------
    changes : dict[str, Any]
        Fields changed from the classified baseline.
    message : str
        The rule's message.
    """
    with pytest.raises(ValueError, match=message):
        _result(**changes)


def test_a_refusal_carries_its_named_reason() -> None:
    """A refusal raised by a parser carries the reason the result will record."""
    refusal = LockfileRefusal("unsupported-version")
    assert refusal.reason == "unsupported-version"
    assert str(refusal) == "unsupported-version"


def test_an_unused_patch_count_is_never_negative() -> None:
    """A Cargo file's skipped ``[[patch.unused]]`` count is zero or more."""
    with pytest.raises(ValueError, match="never negative"):
        LockfileResult("Cargo.lock", "a" * 64, "cargo", "4", None, (), unused_patches=-1)
    assert (
        LockfileResult("Cargo.lock", "a" * 64, "cargo", "4", None, (), unused_patches=1).to_dict()[
            "unused_patches"
        ]
        == 1
    )
