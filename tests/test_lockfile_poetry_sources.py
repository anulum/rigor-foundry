# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Poetry declared-source witnesses
"""Witness how the sources a pyproject.toml declares are read and judged."""

from __future__ import annotations

import pytest

from rigor_foundry.lockfile_poetry_sources import (
    PoetryDeclaration,
    PoetrySource,
    read_poetry_declaration,
)

LOOP = '[[tool.poetry.source]]\nname = "loop"\nurl = "http://127.0.0.1:19431/simple/"\n'


def test_a_project_without_sources_declares_none() -> None:
    """No [tool.poetry] table, or one without sources, declares nothing; PyPI stays."""
    for text in ("", "[project]\nname = 'x'\n", "[tool.poetry]\nname = 'x'\n"):
        declaration = read_poetry_declaration(text)
        assert declaration == PoetryDeclaration(())
        assert declaration.pypi_deactivated("2.1") is False
        assert declaration.pypi_deactivated("2.0") is False


def test_a_source_is_read_with_every_key() -> None:
    """Name, URL, priority and the two 1.x flags."""
    declaration = read_poetry_declaration(
        LOOP + 'priority = "explicit"\ndefault = false\nsecondary = true\n'
    )
    assert declaration == PoetryDeclaration(
        (PoetrySource("loop", "http://127.0.0.1:19431/simple/", "explicit", False, True),)
    )


@pytest.mark.parametrize(
    "text",
    [
        None,
        "not toml = = =",
        "tool = 3\n",
        "[tool]\npoetry = 3\n",
        "[tool.poetry]\nsource = 3\n",
        "[tool.poetry]\nsource = [3]\n",
        '[[tool.poetry.source]]\nurl = "http://x/"\n',
        LOOP.replace('url = "http://127.0.0.1:19431/simple/"', "url = 3"),
        LOOP + "priority = 3\n",
        LOOP + 'default = "yes"\n',
        LOOP + "secondary = 1\n",
    ],
)
def test_a_declaration_of_any_other_shape_cannot_be_read(text: str | None) -> None:
    """Absent, non-TOML, or not the shape Poetry writes: there is nothing to compare with.

    Parameters
    ----------
    text : str | None
        The pyproject.toml text.
    """
    assert read_poetry_declaration(text) is None


def test_a_locked_index_must_match_a_declared_name_and_url() -> None:
    """Names compare without case and URLs without a trailing slash; nothing is no match."""
    declaration = read_poetry_declaration(LOOP + '[[tool.poetry.source]]\nname = "bare"\n')
    assert declaration is not None
    assert declaration.matches("Loop", "http://127.0.0.1:19431/simple")
    assert not declaration.matches("loop", "http://127.0.0.1:19431/other")
    assert not declaration.matches("other", "http://127.0.0.1:19431/simple")
    assert not declaration.matches(None, "http://127.0.0.1:19431/simple")
    assert not declaration.matches("loop", None)
    assert not declaration.matches("bare", "http://127.0.0.1:19431/simple")


@pytest.mark.parametrize(
    ("keys", "deactivated_2_0", "deactivated_2_1"),
    [
        ("", None, True),
        ('priority = "primary"\n', True, True),
        ('priority = "default"\n', True, None),
        ('priority = "secondary"\n', False, None),
        ('priority = "bogus"\n', None, None),
        ('priority = "supplemental"\n', False, False),
        ('priority = "explicit"\n', False, False),
        ("default = true\n", True, None),
        ("default = false\n", None, None),
        ("secondary = false\n", None, None),
        ("secondary = true\n", False, None),
    ],
)
def test_pypi_deactivation_follows_the_generation_that_wrote_the_lock(
    keys: str, deactivated_2_0: bool | None, deactivated_2_1: bool | None
) -> None:
    """Poetry 1.3 to 1.8 for lock-version 2.0; Poetry 2, which refuses the 1.x keys, for 2.1.

    Parameters
    ----------
    keys : str
        The source's priority keys.
    deactivated_2_0 : bool | None
        The verdict for a lock-version 2.0 file; ``None`` cannot be judged.
    deactivated_2_1 : bool | None
        The verdict for a lock-version 2.1 file; ``None`` cannot be judged.
    """
    declaration = read_poetry_declaration(LOOP + keys)
    assert declaration is not None
    assert declaration.pypi_deactivated("2.0") is deactivated_2_0
    assert declaration.pypi_deactivated("2.1") is deactivated_2_1


def test_on_lock_2_0_a_decided_source_wins_and_an_all_keyed_declaration_is_judged() -> None:
    """A default source decides beside a keyless one; sources that all carry keys are judged."""
    keyless = '[[tool.poetry.source]]\nname = "other"\nurl = "http://127.0.0.1:19433/simple/"\n'
    decided = read_poetry_declaration(LOOP + "default = true\n" + keyless)
    keyed = read_poetry_declaration(
        LOOP + 'priority = "explicit"\n' + keyless + "secondary = true\n"
    )
    assert decided is not None and keyed is not None
    assert decided.pypi_deactivated("2.0") is True
    assert keyed.pypi_deactivated("2.0") is False


def test_a_source_named_pypi_keeps_pypi_in_every_generation() -> None:
    """Declaring PyPI explicitly, in any case, keeps it beside a primary or default source."""
    pypi = '[[tool.poetry.source]]\nname = "PyPI"\n'
    primary = read_poetry_declaration(
        LOOP + 'priority = "primary"\n' + pypi + 'priority = "primary"\n'
    )
    default = read_poetry_declaration(LOOP + "default = true\n" + pypi)
    assert primary is not None and default is not None
    assert primary.pypi_deactivated("2.0") is False
    assert primary.pypi_deactivated("2.1") is False
    assert default.pypi_deactivated("2.0") is False
