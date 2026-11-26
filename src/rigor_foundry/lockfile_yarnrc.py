# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the registry a repository declares for Yarn 1
"""Read the registry a repository declares for Yarn 1, and compare a locked origin to it.

Yarn 1 reads ``.npmrc`` and ``.yarnrc``. For each package it takes, in order, the ``.npmrc``
registry of the package's scope, the ``.yarnrc`` one, the unscoped ``.npmrc`` registry and the
unscoped ``.yarnrc`` one. It fetches every lockfile URL as written. So with nothing declared,
``registry.yarnpkg.com`` and ``registry.npmjs.org`` are the default registry; with a registry
declared, neither is a placeholder and a URL elsewhere is a mismatch. ``.yarnrc.yml`` belongs to
Yarn 2 and later and is not read. A ``.yarnrc`` line that cannot be read with certainty makes
every origin unknown, as for ``.npmrc``: ``${…}``, a ``--registry`` flag, a repeated key with a
different value, a value that is not an HTTP(S) URL, or a line that does not tokenise.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, cast

from .lockfile_model import EntryFinding
from .lockfile_npmrc import url_host

YARN_DEFAULT_HOSTS: Final = frozenset({"registry.yarnpkg.com", "registry.npmjs.org"})
_TOKEN: Final = re.compile(r'\s*("(?:[^"\\]|\\.)*"|[^\s"]+)')
_SCOPED_SUFFIX: Final = ":registry"


def _tokens(line: str) -> list[str] | None:
    """Split one ``.yarnrc`` line into unquoted tokens, or ``None`` when it does not tokenise."""
    tokens: list[str] = []
    position = 0
    while position < len(line):
        match = _TOKEN.match(line, position)
        if match is None:
            return None
        raw = match.group(1)
        if raw.startswith('"'):
            try:
                tokens.append(cast(str, json.loads(raw)))
            except ValueError:
                return None
        else:
            tokens.append(raw)
        position = match.end()
    return tokens


def yarnrc_registry_hosts(text: str) -> dict[str, str] | None:
    """Return the registry hosts one tracked ``.yarnrc`` declares, or ``None`` when uncertain.

    Parameters
    ----------
    text : str
        The file text.

    Returns
    -------
    dict[str, str] | None
        The host of each declared registry, keyed ``""`` for the default and ``@scope`` for a
        scope; empty when nothing is declared.
    """
    settings: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = _tokens(line)
        if tokens is None:
            if "registry" in line:
                return None
            continue
        key = tokens[0]
        if key.startswith("--"):
            if "registry" in key:
                return None
            continue
        if key != "registry" and not (key.startswith("@") and key.endswith(_SCOPED_SUFFIX)):
            continue
        if len(tokens) != 2 or "${" in tokens[1] or settings.get(key, tokens[1]) != tokens[1]:
            return None
        settings[key] = tokens[1]
    hosts: dict[str, str] = {}
    for key, value in settings.items():
        host = url_host(value)
        if host is None:
            return None
        hosts["" if key == "registry" else key.removesuffix(_SCOPED_SUFFIX)] = host
    return hosts


@dataclass(frozen=True)
class YarnRegistryDeclaration:
    """The registries a repository declares for Yarn 1, or the fact that they cannot be read.

    Parameters
    ----------
    known : bool
        Whether both configuration files were read with certainty.
    npmrc_hosts : Mapping[str, str]
        The ``.npmrc`` registry hosts, keyed ``""`` or ``@scope``.
    yarnrc_hosts : Mapping[str, str]
        The ``.yarnrc`` registry hosts, keyed the same way.
    """

    known: bool
    npmrc_hosts: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    yarnrc_hosts: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def declared_host(self, package_name: str) -> str | None:
        """Return the registry host Yarn 1 would use for a package, if one is declared.

        Parameters
        ----------
        package_name : str
            The package name, such as ``left-pad`` or ``@scope/tool``.

        Returns
        -------
        str | None
            The first declared host in Yarn's order, or ``None`` when nothing applies.
        """
        scope = package_name.split("/", 1)[0] if package_name.startswith("@") else ""
        for key in dict.fromkeys((scope, "")):
            host = self.npmrc_hosts.get(key) or self.yarnrc_hosts.get(key)
            if host is not None:
                return host
        return None

    def origin_finding(self, package_name: str, host: str) -> EntryFinding | None:
        """Compare one locked artifact's host with the registry declared for its package.

        Parameters
        ----------
        package_name : str
            The package name.
        host : str
            The host the artifact resolves from.

        Returns
        -------
        EntryFinding | None
            ``origin-unknown`` when the declaration is unknown, ``origin-mismatch`` when the
            host differs from the declared registry, or from the default when none is
            declared, and ``None`` when it matches.
        """
        if not self.known:
            return "origin-unknown"
        declared = self.declared_host(package_name)
        if declared is None:
            return None if host in YARN_DEFAULT_HOSTS else "origin-mismatch"
        return None if host == declared else "origin-mismatch"


UNKNOWN_YARN_REGISTRY: Final = YarnRegistryDeclaration(known=False)


def yarn_registry_declaration(
    npmrc_hosts: dict[str, str] | None, yarnrc_hosts: dict[str, str] | None
) -> YarnRegistryDeclaration:
    """Combine the two files' declarations, which are both certain or make the whole unknown.

    Parameters
    ----------
    npmrc_hosts : dict[str, str] | None
        What ``npmrc_registry_hosts`` read, ``{}`` for no file, ``None`` when uncertain.
    yarnrc_hosts : dict[str, str] | None
        What ``yarnrc_registry_hosts`` read, with the same meanings.

    Returns
    -------
    YarnRegistryDeclaration
        The declaration.
    """
    if npmrc_hosts is None or yarnrc_hosts is None:
        return UNKNOWN_YARN_REGISTRY
    return YarnRegistryDeclaration(
        known=True,
        npmrc_hosts=MappingProxyType(dict(npmrc_hosts)),
        yarnrc_hosts=MappingProxyType(dict(yarnrc_hosts)),
    )
