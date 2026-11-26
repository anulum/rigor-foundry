# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Go lockfile classification witnesses
"""Witness go.sum classification on the files Go 1.16.15 to 1.27.4 wrote.

See each fixture's GENERATED_BY.txt: all four releases wrote byte-identical go.sum files. Every
failing case is one recorded edit of a clean go.sum or go.mod, written out in the test using it.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from lockfile_repository_support import fixture_text

from rigor_foundry.lockfile_go import EMPTY_GO_MOD_HASH, GoLockfile, classify_go_lockfile
from rigor_foundry.lockfile_gomod import parse_go_mod
from rigor_foundry.lockfile_model import LockedEntry, LockfileRefusal

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lockfiles"
GO_127 = FIXTURES / "go-1.27.4"
GO_116 = FIXTURES / "go-1.16.15-gomod"
CRLF = FIXTURES / "go-1.27.4-crlf"
BLOCKS = FIXTURES / "go-1.27.4-blocks"
REPLACE = FIXTURES / "go-1.27.4-replace"
ERRORS_H1 = "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n"
ERRORS_MOD = (
    "github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n"
)
OBJX_MOD = (
    "github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=\n"
)
LOCAL_REPLACE = "replace example.com/local => ./local\n"


def _sum(fixture: Path) -> str:
    """Return a clean go.sum's text."""
    return fixture_text(fixture / "go.sum.gz")


def _mod(fixture: Path) -> str:
    """Return a clean go.mod's text."""
    return fixture_text(fixture / "go.mod.gz")


def _edit(text: str, old: str, new: str) -> str:
    """Return a clean file with exactly one recorded edit."""
    assert text.count(old) == 1, old
    return text.replace(old, new)


def _classify(go_sum: str, go_mod: str, lock_dir: str = "") -> GoLockfile:
    """Classify one go.sum with its go.mod."""
    return classify_go_lockfile(go_sum, parse_go_mod(go_mod), lock_dir)


def _entries(go_sum: str, go_mod: str, lock_dir: str = "") -> dict[str, LockedEntry]:
    """Classify one pair and index its entries by key."""
    return {entry.key: entry for entry in _classify(go_sum, go_mod, lock_dir).entries}


def _refusal(go_sum: str, go_mod: str) -> str:
    """Return the reason a pair is refused."""
    with pytest.raises(LockfileRefusal) as refused:
        _classify(go_sum, go_mod)
    return refused.value.reason


@pytest.mark.parametrize("fixture", [GO_127, GO_116, CRLF, BLOCKS])
def test_each_clean_pair_classifies_as_the_rulings_say(fixture: Path) -> None:
    """Seven pinned modules, two pruned graph-only modules and the local replacement.

    Parameters
    ----------
    fixture : Path
        The clean fixture.
    """
    lockfile = _classify(_sum(fixture), _mod(fixture))
    classes = Counter(entry.entry_class for entry in lockfile.entries)
    assert dict(classes) == {"local": 1, "artifact-pinned": 7, "graph-only": 2}
    assert all(not entry.findings for entry in lockfile.entries)
    assert lockfile.dropped_lines == 0
    assert [entry.line for entry in lockfile.entries] == sorted(
        entry.line for entry in lockfile.entries
    )


def test_a_crlf_go_sum_reads_as_go_reads_it() -> None:
    """Go splits fields on white space, so CRLF line endings change nothing."""
    assert _classify(_sum(CRLF), _mod(CRLF)) == _classify(_sum(GO_127), _mod(GO_127))
    assert "\r\n" in _sum(CRLF)


def test_pinned_graph_only_and_local_entries_carry_their_evidence() -> None:
    """h1 pins the module tree; a /go.mod-only module is graph-only; the replacement is local."""
    entries = _entries(_sum(GO_127), _mod(GO_127))
    errors = entries["github.com/pkg/errors v0.9.1"]
    assert (errors.line, errors.entry_class, errors.origin) == (3, "artifact-pinned", "github.com")
    assert (errors.digest_algorithms, errors.digest_scope) == (("sha256",), "module-tree")
    pseudo = entries["gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c"]
    assert (pseudo.line, pseudo.entry_class, pseudo.origin) == (15, "artifact-pinned", "gopkg.in")
    assert entries["golang.org/x/text v0.3.6"].origin == "golang.org"
    objx = entries["github.com/stretchr/objx v0.1.0"]
    assert (objx.line, objx.entry_class, objx.digest_algorithms, objx.digest_scope) == (
        7,
        "graph-only",
        (),
        None,
    )
    assert objx.notes == (("go_mod_digest", "present"),)
    local = entries["example.com/local v0.0.0"]
    assert (local.line, local.entry_class, local.origin) == (1, "local", "local")
    assert local.notes == (("replaced_by", "./local"), ("required_at", "go.mod:6"))


def test_a_required_version_with_no_go_sum_line_stands_at_line_one() -> None:
    """Its note names the requirement's go.mod line."""
    go_sum = _edit(_edit(_sum(GO_127), ERRORS_H1, ""), ERRORS_MOD, "")
    errors = _entries(go_sum, _mod(GO_127))["github.com/pkg/errors v0.9.1"]
    assert (errors.line, errors.entry_class, errors.findings) == (
        1,
        "unpinned",
        ("missing-digest",),
    )
    assert (errors.form, errors.origin) == ("artifact", "github.com")
    assert errors.notes == (("required_at", "go.mod:7"),)


def test_a_required_version_needs_both_lines() -> None:
    """Without h1 or without its /go.mod line, a required version is missing its digest."""
    without_h1 = _entries(_edit(_sum(GO_127), ERRORS_H1, ""), _mod(GO_127))[
        "github.com/pkg/errors v0.9.1"
    ]
    assert (without_h1.line, without_h1.entry_class, without_h1.findings) == (
        3,
        "unpinned",
        ("missing-digest",),
    )
    assert without_h1.digest_algorithms == ()
    without_mod = _entries(_edit(_sum(GO_127), ERRORS_MOD, ""), _mod(GO_127))[
        "github.com/pkg/errors v0.9.1"
    ]
    assert (without_mod.line, without_mod.entry_class, without_mod.findings) == (
        3,
        "unpinned",
        ("missing-digest",),
    )
    assert without_mod.digest_algorithms == ("sha256",)


def test_a_graph_only_module_that_go_mod_requires_is_missing_its_digest() -> None:
    """Requiring a pruned module makes its missing h1 line a finding."""
    go_mod = _edit(
        _mod(GO_127), ")\n\nreplace", "\tgithub.com/stretchr/objx v0.1.0 // indirect\n)\n\nreplace"
    )
    objx = _entries(_sum(GO_127), go_mod)["github.com/stretchr/objx v0.1.0"]
    assert (objx.line, objx.entry_class, objx.findings, objx.notes) == (
        7,
        "unpinned",
        ("missing-digest",),
        (),
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (ERRORS_H1, ERRORS_H1 + ERRORS_H1.replace("FEBLx1", "FEBLx2")),
        (ERRORS_MOD, ERRORS_MOD + ERRORS_MOD.replace("bwawx", "bwawy")),
    ],
)
def test_two_different_hashes_of_one_line_kind_conflict(old: str, new: str) -> None:
    """Go would accept whichever matches, so the file pins neither.

    Parameters
    ----------
    old : str
        The clean line.
    new : str
        The line followed by a different hash for the same module version.
    """
    assert _refusal(_edit(_sum(GO_127), old, new), _mod(GO_127)) == "conflicting-entries"


def test_an_identical_repeated_line_is_accepted() -> None:
    """Go appends the same hash twice; it still pins."""
    go_sum = _edit(_sum(GO_127), ERRORS_H1, ERRORS_H1 + ERRORS_H1)
    errors = _entries(go_sum, _mod(GO_127))["github.com/pkg/errors v0.9.1"]
    assert (errors.line, errors.entry_class) == (3, "artifact-pinned")


def test_an_entry_stands_at_its_first_h1_line_even_after_its_go_mod_line() -> None:
    """Go writes h1 first; a file in another order still anchors the entry at h1."""
    go_sum = _edit(_sum(GO_127), ERRORS_H1 + ERRORS_MOD, ERRORS_MOD + ERRORS_H1)
    errors = _entries(go_sum, _mod(GO_127))["github.com/pkg/errors v0.9.1"]
    assert (errors.line, errors.entry_class) == (4, "artifact-pinned")


@pytest.mark.parametrize(
    "value",
    [
        "h2:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
        "FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
        "H1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
        "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTw==",
        "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4",
        "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=h1:",
    ],
)
def test_only_a_lower_case_h1_of_32_bytes_pins(value: str) -> None:
    """Another prefix, 31 bytes, missing padding or trailing text is malformed.

    Parameters
    ----------
    value : str
        The replaced hash field.
    """
    go_sum = _edit(_sum(GO_127), ERRORS_H1, f"github.com/pkg/errors v0.9.1 {value}\n")
    errors = _entries(go_sum, _mod(GO_127))["github.com/pkg/errors v0.9.1"]
    assert (errors.entry_class, errors.findings, errors.form) == (
        "unpinned",
        ("malformed-digest",),
        "artifact",
    )


def test_an_empty_go_mod_hash_line_is_dropped_and_counted() -> None:
    """Go drops these lines as an old bug; the count keeps the skip visible."""
    dropped = f"example.com/nonmodule v1.0.0/go.mod {EMPTY_GO_MOD_HASH}\n"
    lockfile = _classify(_edit(_sum(GO_127), OBJX_MOD, OBJX_MOD + dropped + dropped), _mod(GO_127))
    assert lockfile.dropped_lines == 2
    assert all(not entry.key.startswith("example.com/nonmodule") for entry in lockfile.entries)
    assert len(lockfile.entries) == 10


def test_an_excluded_version_is_classified_as_written_with_its_note() -> None:
    """Go leaves an excluded version out of the build list; its lines stay as they are."""
    go_mod = (
        _mod(GO_127)
        + "\nexclude github.com/stretchr/objx v0.1.0\nexclude golang.org/x/text v0.3.6\n"
    )
    entries = _entries(_sum(GO_127), go_mod)
    assert entries["github.com/stretchr/objx v0.1.0"].notes == (
        ("excluded_at", "go.mod:20"),
        ("go_mod_digest", "present"),
    )
    text = entries["golang.org/x/text v0.3.6"]
    assert (text.entry_class, text.findings, text.notes) == (
        "artifact-pinned",
        (),
        (("excluded_at", "go.mod:21"),),
    )


def test_a_required_and_excluded_version_with_no_line_keeps_both_notes() -> None:
    """The requirement's note and the exclusion's note are both recorded, by name."""
    go_mod = "module x\nrequire a.example/m v1.0.0\nexclude a.example/m v1.0.0\n"
    entry = _entries("", go_mod)["a.example/m v1.0.0"]
    assert entry.notes == (("excluded_at", "go.mod:3"), ("required_at", "go.mod:2"))


@pytest.mark.parametrize(
    ("lock_dir", "target", "escapes"),
    [
        ("", "../../outside", True),
        ("sub", "../../outside", True),
        ("a/b", "../../outside", False),
        ("", "/abs/local", True),
        ("", "C:/local", True),
        ("sub", "..", False),
    ],
)
def test_a_local_replacement_outside_the_repository_escapes(
    lock_dir: str, target: str, escapes: bool
) -> None:
    """The path is read from go.mod's directory, as Go reads it.

    Parameters
    ----------
    lock_dir : str
        The directory of the pair.
    target : str
        The replacement directory.
    escapes : bool
        Whether it leaves the repository.
    """
    go_mod = _edit(_mod(GO_127), LOCAL_REPLACE, f"replace example.com/local => {target}\n")
    local = _entries(_sum(GO_127), go_mod, lock_dir)["example.com/local v0.0.0"]
    expected = ("unpinned", ("path-escape",), "path") if escapes else ("local", (), None)
    assert (local.entry_class, local.findings, local.form) == expected
    assert local.notes == (("replaced_by", target), ("required_at", "go.mod:6"))


def test_the_real_module_replacement_is_classified_as_its_target() -> None:
    """pkg/errors v0.9.1 takes the class of v0.8.1, whose lines Go wrote."""
    entries = _entries(_sum(REPLACE), _mod(REPLACE))
    assert set(entries) == {"github.com/pkg/errors v0.8.1", "github.com/pkg/errors v0.9.1"}
    target = entries["github.com/pkg/errors v0.8.1"]
    replaced = entries["github.com/pkg/errors v0.9.1"]
    assert (target.line, target.entry_class, target.notes) == (1, "artifact-pinned", ())
    assert (replaced.line, replaced.entry_class, replaced.digest_scope) == (
        1,
        "artifact-pinned",
        "module-tree",
    )
    assert replaced.notes == (
        ("replaced_by", "github.com/pkg/errors v0.8.1"),
        ("required_at", "go.mod:5"),
    )


def test_a_replacement_target_without_its_lines_is_missing_its_digest() -> None:
    """The target's go.sum lines decide, so a missing h1 line is a finding on the requirement."""
    go_sum = _edit(
        _sum(REPLACE),
        "github.com/pkg/errors v0.8.1 h1:iURUrRGxPUNPdy5/HRSm+Yj6okJ6UtLINN0Q9M4+h3I=\n",
        "",
    )
    replaced = _entries(go_sum, _mod(REPLACE))["github.com/pkg/errors v0.9.1"]
    assert (replaced.entry_class, replaced.findings) == ("unpinned", ("missing-digest",))
    other = _edit(
        _mod(REPLACE), "=> github.com/pkg/errors v0.8.1", "=> gitlab.example/fork v1.0.0"
    )
    forked = _entries(_sum(REPLACE), other)["github.com/pkg/errors v0.9.1"]
    assert (forked.findings, forked.origin) == (("missing-digest",), "gitlab.example")
    assert forked.notes == (
        ("replaced_by", "gitlab.example/fork v1.0.0"),
        ("required_at", "go.mod:5"),
    )


def test_a_replacement_for_every_version_applies_to_the_required_one() -> None:
    """A left side without a version replaces whichever version is required."""
    go_mod = _edit(
        _mod(REPLACE),
        "replace github.com/pkg/errors v0.9.1 =>",
        "replace github.com/pkg/errors =>",
    )
    replaced = _entries(_sum(REPLACE), go_mod)["github.com/pkg/errors v0.9.1"]
    assert (replaced.entry_class, dict(replaced.notes)["replaced_by"]) == (
        "artifact-pinned",
        "github.com/pkg/errors v0.8.1",
    )


def test_a_required_version_with_lines_and_a_replacement_stands_at_its_line() -> None:
    """Lines Go no longer reads do not decide; the replacement does."""
    go_mod = _mod(GO_127) + "replace github.com/pkg/errors v0.9.1 => ./errors\n"
    errors = _entries(_sum(GO_127), go_mod)["github.com/pkg/errors v0.9.1"]
    assert (errors.line, errors.entry_class, errors.notes) == (
        3,
        "local",
        (("replaced_by", "./errors"), ("required_at", "go.mod:7")),
    )


@pytest.mark.parametrize(
    "line",
    [
        "github.com/pkg/errors v0.9.1\n",
        "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4= extra\n",
        "github.com/pkg/errors\x1fv0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n",
    ],
)
def test_a_line_without_three_fields_is_unparseable(line: str) -> None:
    """Go stops at such a line outside ``go mod tidy``; U+001F is not white space to Go.

    Parameters
    ----------
    line : str
        The replacement for the errors h1 line.
    """
    assert _refusal(_edit(_sum(GO_127), ERRORS_H1, line), _mod(GO_127)) == "unparseable"


def test_blank_and_white_space_lines_are_skipped_and_go_white_space_separates() -> None:
    """Lines end only at a line feed; U+00A0, U+3000 and U+2028 are white space to Go."""
    spaced = ERRORS_H1.replace(" ", "\u00a0", 1).replace(" ", "\u3000", 1)
    go_sum = _edit(_sum(GO_127), ERRORS_H1, "\n \t\n\u2028\n" + spaced)
    clean = _entries(_sum(GO_127), _mod(GO_127))
    edited = _entries(go_sum, _mod(GO_127))
    assert {key: (e.entry_class, e.findings, e.notes) for key, e in edited.items()} == {
        key: (e.entry_class, e.findings, e.notes) for key, e in clean.items()
    }
    assert edited["github.com/pkg/errors v0.9.1"].line == 6
