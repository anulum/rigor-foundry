# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — go.mod reading witnesses
"""Witness the go.mod subset on the files Go 1.16.15 and 1.27.4 wrote, and on Go's grammar.

See each fixture's GENERATED_BY.txt. The grammar cases follow ``golang.org/x/mod/modfile``
``read.go`` and ``rule.go`` as vendored in go1.27.4.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from lockfile_repository_support import fixture_text

from rigor_foundry.lockfile_gomod import GoReplacement, GoRequirement, parse_go_mod
from rigor_foundry.lockfile_model import LockfileRefusal

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lockfiles"
GO_127 = FIXTURES / "go-1.27.4" / "go.mod.gz"
GO_116 = FIXTURES / "go-1.16.15-gomod" / "go.mod.gz"
REPLACE = FIXTURES / "go-1.27.4-replace" / "go.mod.gz"
BLOCKS = FIXTURES / "go-1.27.4-blocks" / "go.mod.gz"
DIRECT = [
    GoRequirement("example.com/local", "v0.0.0", 6),
    GoRequirement("github.com/pkg/errors", "v0.9.1", 7),
    GoRequirement("github.com/stretchr/testify", "v1.7.0", 8),
    GoRequirement("golang.org/x/text", "v0.3.6", 9),
]
LOCAL = GoReplacement("example.com/local", None, "./local", None, 18)


def _refusal(text: str) -> str:
    """Return the reason a go.mod is refused."""
    with pytest.raises(LockfileRefusal) as refused:
        parse_go_mod(text)
    return refused.value.reason


def test_the_go_1_27_file_reads_both_require_blocks_and_the_local_replacement() -> None:
    """Go 1.17 and later add a block of indirect requirements; its comments are dropped."""
    module = parse_go_mod(fixture_text(GO_127))
    assert list(module.requirements) == [
        *DIRECT,
        GoRequirement("github.com/davecgh/go-spew", "v1.1.0", 13),
        GoRequirement("github.com/pmezard/go-difflib", "v1.0.0", 14),
        GoRequirement("gopkg.in/yaml.v3", "v3.0.0-20200313102051-9f266ea9e77c", 15),
    ]
    assert module.replacements == (LOCAL,)
    assert module.replacements[0].local
    assert module.exclusions == ()


@pytest.mark.parametrize("block", ["tool", "godebug", "ignore"])
def test_the_blocks_go_mod_edit_writes_are_read(block: str) -> None:
    """Go 1.27.4 wrote tool, godebug and ignore blocks; each is accepted and nothing else changes.

    Parameters
    ----------
    block : str
        One block directive the fixture holds.
    """
    text = fixture_text(BLOCKS)
    assert f"\n{block} (\n" in text
    module = parse_go_mod(text)
    assert module.requirements == parse_go_mod(fixture_text(GO_127)).requirements
    assert module.replacements == (LOCAL,)
    assert module.exclusions == ()


def test_the_go_1_16_file_names_only_the_direct_requirements() -> None:
    """Go 1.16 wrote no indirect block for this module."""
    module = parse_go_mod(fixture_text(GO_116))
    assert list(module.requirements) == DIRECT
    assert module.replacements == (GoReplacement("example.com/local", None, "./local", None, 12),)


def test_the_module_replacement_names_its_target_version() -> None:
    """The real replacement of pkg/errors v0.9.1 by v0.8.1 is not local."""
    module = parse_go_mod(fixture_text(REPLACE))
    replacement = GoReplacement(
        "github.com/pkg/errors", "v0.9.1", "github.com/pkg/errors", "v0.8.1", 7
    )
    assert module.replacements == (replacement,)
    assert not replacement.local
    assert module.replacement("github.com/pkg/errors", "v0.9.1") == replacement
    assert module.replacement("github.com/pkg/errors", "v0.9.0") is None
    assert module.replacement("github.com/other", "v0.9.1") is None


def test_an_exact_replacement_wins_over_one_for_every_version() -> None:
    """Go looks up the exact version first, then the path alone."""
    module = parse_go_mod(
        "module x\nreplace a.example/m => ./every\nreplace a.example/m v1.0.0 => ./one\n"
    )
    assert module.replacement("a.example/m", "v1.0.0") == GoReplacement(
        "a.example/m", "v1.0.0", "./one", None, 3
    )
    assert module.replacement("a.example/m", "v2.0.0") == GoReplacement(
        "a.example/m", None, "./every", None, 2
    )


def test_identical_replacements_are_one_and_different_ones_conflict() -> None:
    """Go's modload refuses two different replacements of one module version."""
    same = "module x\nreplace a.example/m => ./one\nreplace a.example/m => ./one\n"
    assert parse_go_mod(same).replacement("a.example/m", "v1.0.0") == GoReplacement(
        "a.example/m", None, "./one", None, 2
    )
    assert _refusal("module x\nreplace a.example/m => ./one\nreplace a.example/m => ./two\n") == (
        "conflicting-entries"
    )
    assert _refusal(
        "module x\nreplace a.example/m v1.0.0 => b.example/n v1.0.0\n"
        "replace a.example/m v1.0.0 => b.example/n v1.0.1\n"
    ) == ("conflicting-entries")


def test_exclusions_are_read_with_their_lines() -> None:
    """An ``exclude`` line or block names a module version."""
    module = parse_go_mod(
        "module x\nexclude a.example/m v1.0.0\nexclude (\n\tb.example/n v2.0.0\n)\n"
    )
    assert module.exclusions == (
        GoRequirement("a.example/m", "v1.0.0", 2),
        GoRequirement("b.example/n", "v2.0.0", 4),
    )
    assert module.exclusion("b.example/n", "v2.0.0") == GoRequirement("b.example/n", "v2.0.0", 4)
    assert module.exclusion("b.example/n", "v2.0.1") is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('require "a.example/m" "v1.0.0"\n', GoRequirement("a.example/m", "v1.0.0", 1)),
        ("require a.example/m v1.0.0// comment\n", GoRequirement("a.example/m", "v1.0.0", 1)),
        ("require\ta.example/m\tv1.0.0\r\n", GoRequirement("a.example/m", "v1.0.0", 1)),
        (
            "require (\r\n\ta.example/m v1.0.0\r\n) // end\r\n",
            GoRequirement("a.example/m", "v1.0.0", 2),
        ),
        (
            "// lead\n\nrequire a.example/m v1.0.0 // indirect\n",
            GoRequirement("a.example/m", "v1.0.0", 3),
        ),
    ],
)
def test_go_accepts_these_spellings_of_one_requirement(text: str, expected: GoRequirement) -> None:
    """Quoted paths, comments, tabs, CRLF and blank lines read as Go reads them.

    Parameters
    ----------
    text : str
        The go.mod text.
    expected : GoRequirement
        The one requirement it holds.
    """
    assert parse_go_mod("module x\n\n" + text).requirements == (
        GoRequirement(expected.path, expected.version, expected.line + 2),
    )


def test_the_other_directives_go_knows_are_accepted_and_not_read() -> None:
    """``retract`` intervals hold punctuation, and an empty block is a block."""
    text = (
        "module x\ngo 1.27\ntoolchain go1.27.4\ngodebug default=go1.21\n"
        "retract [v1.0.0, v1.1.0]\nretract (\n\tv0.9.0 // broken\n)\n"
        "tool golang.org/x/tools/cmd/stringer\n"
        "ignore ./node_modules\nrequire ( )\nmodule (\n)\n"
    )
    module = parse_go_mod(text)
    assert (module.requirements, module.replacements, module.exclusions) == ((), (), ())


@pytest.mark.parametrize(
    "text",
    [
        "/* block comment */\n",
        "retract v1.0.0 /* note */\n",
        "require a.example/m v1.0.0/*x*/\n",
        "require a.example/m v1.0.0\x0b\n",
        "require a.example/m ,\n",
        "require a.example/m v1.0.0 /* note */\n",
        "require `a.example/m` v1.0.0\n",
        'require a.example/"m" v1.0.0\n',
        "require 'a.example/m' v1.0.0\n",
        'require "a.example/\\u006d" v1.0.0\n',
        'require "a.example/m v1.0.0\n',
        "require a.example/m\x0bv1.0.0\n",
        "require\xa0a.example/m v1.0.0\n",
        "\ufeffrequire a.example/m v1.0.0\n",
        "requires a.example/m v1.0.0\n",
        "require a.example/m\n",
        "require a.example/m v1.0.0 extra\n",
        "require a.example/m v1.0.0,\n",
        "exclude a.example/m\n",
        "go (\n\t1.27\n)\n",
        "toolchain (\n)\n",
        "require a.example/m (\n)\n",
        "require a.example/m (\n",
        "retract v1.0.0 (\n",
        "require ( (\n)\n",
        "(\n",
        "require (\n\ta.example/m v1.0.0\n",
        "require (\n\ta.example/m v1.0.0\n) x\n",
        ")\n",
    ],
)
def test_text_outside_the_grammar_subset_is_unparseable(text: str) -> None:
    """Each case is one that Go refuses, or one this reader does not decode.

    Parameters
    ----------
    text : str
        The go.mod text after its module line.
    """
    assert _refusal("module x\n" + text) == "unparseable"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("a.example/m => ./local", GoReplacement("a.example/m", None, "./local", None, 2)),
        ("a.example/m => .", GoReplacement("a.example/m", None, ".", None, 2)),
        ("a.example/m => ..", GoReplacement("a.example/m", None, "..", None, 2)),
        ("a.example/m => ../up", GoReplacement("a.example/m", None, "../up", None, 2)),
        ("a.example/m => /abs", GoReplacement("a.example/m", None, "/abs", None, 2)),
        ("a.example/m => C:/drive", GoReplacement("a.example/m", None, "C:/drive", None, 2)),
        (
            '"a.example/m" "v1.0.0" => "./q"',
            GoReplacement("a.example/m", "v1.0.0", "./q", None, 2),
        ),
        (
            "a.example/m v1.0.0 => b.example/n v1.2.3",
            GoReplacement("a.example/m", "v1.0.0", "b.example/n", "v1.2.3", 2),
        ),
        (
            "a.example/m => b.example/n v1.2.3",
            GoReplacement("a.example/m", None, "b.example/n", "v1.2.3", 2),
        ),
    ],
)
def test_replacement_forms_go_accepts(line: str, expected: GoReplacement) -> None:
    """Directory targets are local; module targets carry their version.

    Parameters
    ----------
    line : str
        The replacement's arguments.
    expected : GoReplacement
        How it reads.
    """
    assert parse_go_mod(f"module x\nreplace {line}\n").replacements == (expected,)


@pytest.mark.parametrize(
    "line",
    [
        "a.example/m ./local",
        "a.example/m => b.example/n",
        "a.example/m => b.example/n@v1.2.3",
        "a.example/m => ./local v1.0.0",
        "a.example/m => .\\local",
        "a.example/m => .\\local v1.0.0",
        "a.example/m => \\local v1.0.0",
        "a.example/m => \\local",
        "a.example/m => ../up\\local",
        "a.example/m v1.0.0 v2.0.0 => ./local",
        "a.example/m => b.example/n v1.2.3 extra",
        'a.example/m "=>" ./local',
        "=> ./local",
        "a.example/m =>",
    ],
)
def test_replacement_forms_go_refuses(line: str) -> None:
    """Go's ``parseReplace`` refuses each of these on Linux.

    Parameters
    ----------
    line : str
        The replacement's arguments.
    """
    assert _refusal(f"module x\nreplace {line}\n") == "unparseable"
