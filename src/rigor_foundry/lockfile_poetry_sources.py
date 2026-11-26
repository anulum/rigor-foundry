# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the package sources a Poetry project declares
"""Read the ``[[tool.poetry.source]]`` entries of the ``pyproject.toml`` beside a ``poetry.lock``.

A locked package from an index names the source it came from by ``reference`` and records its URL,
which must match the declared source; Poetry strips a trailing slash from that URL. A package
recorded with no source came from PyPI, and whether the declaration allows PyPI depends on the
Poetry generation that wrote the lockfile:

- **lock-version 2.0 (Poetry 1.3 to 1.8):** PyPI is deactivated by a source with
  ``default = true`` (1.3.2's ``create_pool``), or with ``priority = "default"`` or ``"primary"``
  (1.8.5's), and stays beside a source with ``secondary = true`` or another priority. A source
  with none of those settings is primary to 1.8.5, which deactivates PyPI, but not to 1.3.2, which
  keeps it; lock-version 2.0 cannot tell the two writers apart, so such a source cannot be
  judged.
- **lock-version 2.1 (Poetry 2):** PyPI is deactivated by a source whose ``priority`` is
  ``"primary"`` or absent (2.5.2's ``create_pool``). Poetry 2's schema refuses ``default`` and
  ``secondary``, so a declaration using them cannot be judged.

A priority the writing generation does not know cannot be judged either.

A source named ``pypi``, in any case, keeps PyPI in every generation.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from typing import Final

_PYPI_NAME: Final = "pypi"
_LEGACY_KEYS: Final = ("default", "secondary")
# The priorities each generation accepts: 1.8.5's ``Priority`` enum, and 2.5.2's schema.
_PRIORITIES: Final = {
    "2.0": frozenset({"default", "primary", "secondary", "supplemental", "explicit"}),
    "2.1": frozenset({"primary", "supplemental", "explicit"}),
}


@dataclass(frozen=True)
class PoetrySource:
    """One declared package source.

    Parameters
    ----------
    name : str
        The source's name, which a locked package's ``reference`` names.
    url : str | None
        The source's URL.
    priority : str | None
        Its ``priority``, or ``None`` when absent.
    default : bool | None
        Its 1.x ``default`` flag, or ``None`` when absent.
    secondary : bool | None
        Its 1.x ``secondary`` flag, or ``None`` when absent.
    """

    name: str
    url: str | None
    priority: str | None
    default: bool | None
    secondary: bool | None


@dataclass(frozen=True)
class PoetryDeclaration:
    """The sources a ``pyproject.toml`` declares.

    Parameters
    ----------
    sources : tuple[PoetrySource, ...]
        The declared sources, in file order.
    """

    sources: tuple[PoetrySource, ...]

    def matches(self, reference: str | None, url: str | None) -> bool:
        """Return whether a locked index package names a declared source at its URL.

        Parameters
        ----------
        reference : str | None
            The locked ``reference``, the source's name.
        url : str | None
            The locked URL.

        Returns
        -------
        bool
            Whether a source of that name, compared without case as Poetry compares names, has
            that URL, trailing slashes ignored.
        """
        if reference is None or url is None:
            return False
        return any(
            source.name.lower() == reference.lower()
            and source.url is not None
            and source.url.rstrip("/") == url.rstrip("/")
            for source in self.sources
        )

    def pypi_deactivated(self, lock_version: str) -> bool | None:
        """Return whether the declaration deactivates PyPI for the generation that wrote the lock.

        Parameters
        ----------
        lock_version : str
            The lockfile's ``lock-version``: ``2.0`` or ``2.1``.

        Returns
        -------
        bool | None
            Whether PyPI is deactivated, or ``None`` when the generation that wrote the lockfile
            refuses the declaration: a priority it does not know, or, for Poetry 2, a
            ``default`` or ``secondary`` key.
        """
        if any(
            source.priority is not None and source.priority not in _PRIORITIES[lock_version]
            for source in self.sources
        ):
            return None
        if lock_version == "2.1" and any(
            source.default is not None or source.secondary is not None for source in self.sources
        ):
            return None
        if any(source.name.lower() == _PYPI_NAME for source in self.sources):
            return False
        if lock_version == "2.0":
            if any(
                source.default is True or source.priority in ("default", "primary")
                for source in self.sources
            ):
                return True
            if any(
                source.default is not True
                and source.secondary is not True
                and source.priority is None
                for source in self.sources
            ):
                return None
            return False
        return any(source.priority in (None, "primary") for source in self.sources)


def _source(raw: object) -> PoetrySource | None:
    """Read one source table, or ``None`` when its shape is not one Poetry writes."""
    if not isinstance(raw, dict):
        return None
    name, url, priority = raw.get("name"), raw.get("url"), raw.get("priority")
    flags = [raw.get(key) for key in _LEGACY_KEYS]
    if (
        not isinstance(name, str)
        or not isinstance(url, str | None)
        or not isinstance(priority, str | None)
        or not all(isinstance(flag, bool | None) for flag in flags)
    ):
        return None
    return PoetrySource(name, url, priority, flags[0], flags[1])


def read_poetry_declaration(text: str | None) -> PoetryDeclaration | None:
    """Read the declared sources of one ``pyproject.toml``.

    Parameters
    ----------
    text : str | None
        The file's text, or ``None`` when it is absent or cannot be read with certainty.

    Returns
    -------
    PoetryDeclaration | None
        The declaration, or ``None`` when there is no readable TOML declaration to compare with.
    """
    if text is None:
        return None
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    tool = document.get("tool", {})
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else None
    raw = poetry.get("source", []) if isinstance(poetry, dict) else None
    if not isinstance(raw, list):
        return None
    sources = [_source(item) for item in raw]
    if any(source is None for source in sources):
        return None
    return PoetryDeclaration(tuple(source for source in sources if source is not None))
