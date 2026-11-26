# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the npm registry a repository declares
"""Read the npm registry a repository declares, and compare a locked artifact's origin to it.

Only repository content counts: a tracked ``.npmrc`` sets ``registry=`` and, per scope,
``@scope:registry=``. Without one, the declaration is npm's documented default registry.
Where the declaration cannot be read with certainty, every origin is unknown and never a
pass: an ``.npmrc`` that is untracked or unreadable, a registry set through ``${…}``
interpolation, a ``replace-registry-host`` other than ``npmjs``, a section header, a
repeated key with a different value, or a registry that is not an HTTP(S) URL. With the
default ``replace-registry-host``, an artifact on ``registry.npmjs.org`` stands for the
configured registry, so it matches. Hosts are compared with their explicit port, and a
registry's path is not compared.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final
from urllib.parse import urlsplit

from .lockfile_model import EntryFinding

NPM_DEFAULT_REGISTRY: Final = "https://registry.npmjs.org/"
NPM_PLACEHOLDER_HOST: Final = "registry.npmjs.org"
_REGISTRY_KEY: Final = "registry"
_SCOPED_SUFFIX: Final = ":registry"
_REPLACE_HOST_KEY: Final = "replace-registry-host"
_REPLACE_HOST_DEFAULT: Final = "npmjs"


def url_host(url: str) -> str | None:
    """Return the lower-case host of an HTTP(S) URL, with an explicit port when it has one.

    Parameters
    ----------
    url : str
        The URL.

    Returns
    -------
    str | None
        ``host`` or ``host:port``; ``None`` when the text is not an HTTP(S) URL with a host.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return parts.hostname if port is None else f"{parts.hostname}:{port}"


@dataclass(frozen=True)
class NpmRegistryDeclaration:
    """The registries a repository declares for npm, or the fact that they cannot be read.

    Parameters
    ----------
    known : bool
        Whether the declaration was read with certainty.
    registry_host : str | None
        The host of the default registry, when known.
    scoped_hosts : Mapping[str, str]
        The registry host of each declared ``@scope``.
    """

    known: bool
    registry_host: str | None
    scoped_hosts: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def origin_finding(self, package_name: str, host: str) -> EntryFinding | None:
        """Compare one locked artifact's host with the registry declared for its package.

        Parameters
        ----------
        package_name : str
            The package name, such as ``left-pad`` or ``@scope/tool``.
        host : str
            The host the artifact resolves from.

        Returns
        -------
        EntryFinding | None
            ``origin-unknown`` when the declaration is unknown, ``origin-mismatch`` when the
            host differs from the declared registry, and ``None`` when it matches.
        """
        if not self.known:
            return "origin-unknown"
        if host == NPM_PLACEHOLDER_HOST:
            return None
        scope = package_name.split("/", 1)[0] if package_name.startswith("@") else ""
        declared = self.scoped_hosts.get(scope, self.registry_host)
        return None if host == declared else "origin-mismatch"


UNKNOWN_NPM_REGISTRY: Final = NpmRegistryDeclaration(known=False, registry_host=None)
DEFAULT_NPM_REGISTRY: Final = NpmRegistryDeclaration(
    known=True, registry_host=url_host(NPM_DEFAULT_REGISTRY)
)


def _value(raw: str) -> str:
    """Return one ini value with surrounding double quotes removed."""
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def read_npmrc(text: str) -> NpmRegistryDeclaration:
    """Read the registry declaration of one tracked ``.npmrc``.

    Parameters
    ----------
    text : str
        The file text.

    Returns
    -------
    NpmRegistryDeclaration
        The declared registries, or ``UNKNOWN_NPM_REGISTRY`` when any relevant line cannot
        be read with certainty.
    """
    settings: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line[0] in ";#":
            continue
        if line.startswith("["):
            return UNKNOWN_NPM_REGISTRY
        key, separator, raw_value = line.partition("=")
        key = key.strip()
        relevant = key in (_REGISTRY_KEY, _REPLACE_HOST_KEY) or (
            key.startswith("@") and key.endswith(_SCOPED_SUFFIX)
        )
        if not separator or not relevant:
            continue
        value = _value(raw_value)
        if "${" in value or settings.get(key, value) != value:
            return UNKNOWN_NPM_REGISTRY
        settings[key] = value
    if settings.pop(_REPLACE_HOST_KEY, _REPLACE_HOST_DEFAULT) != _REPLACE_HOST_DEFAULT:
        return UNKNOWN_NPM_REGISTRY
    hosts: dict[str, str] = {}
    for key, value in settings.items():
        host = url_host(value)
        if host is None:
            return UNKNOWN_NPM_REGISTRY
        hosts[key] = host
    registry_host = hosts.pop(_REGISTRY_KEY, DEFAULT_NPM_REGISTRY.registry_host)
    scoped = {key.removesuffix(_SCOPED_SUFFIX): host for key, host in hosts.items()}
    return NpmRegistryDeclaration(
        known=True, registry_host=registry_host, scoped_hosts=MappingProxyType(scoped)
    )
