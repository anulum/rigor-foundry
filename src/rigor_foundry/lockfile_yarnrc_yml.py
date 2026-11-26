# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the registry a repository declares for Yarn 2 and later
"""Read what ``.yarnrc.yml`` declares for Yarn 2 and later, and compare a locked origin to it.

Yarn 2+ reads only ``.yarnrc.yml``. Every tracked one from the repository root down to the
lockfile's directory is merged, the nearer winning per key, and ``npmScopes`` merges per scope.
``npmRegistryServer`` names the default registry, ``https://registry.yarnpkg.com`` when unset,
and ``npmScopes.<scope>.npmRegistryServer`` a scope's. A ``checksumBehavior`` of ``ignore`` or
``update`` is recorded, because it stops Yarn from refusing a checksum mismatch. A file that is
not one YAML mapping without anchors, aliases or tags, a ``${…}`` interpolation in a read value,
or a registry that is not an HTTP(S) URL makes every origin unknown.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from .lockfile_model import EntryFinding
from .lockfile_npmrc import url_host
from .lockfile_yarnrc import YARN_DEFAULT_HOSTS
from .workflow_yaml import (
    MAX_WORKFLOW_BYTES,
    MAX_WORKFLOW_EVENTS,
    WorkflowFormatError,
    WorkflowValue,
    YamlLimits,
    parse_workflow_yaml,
)

CONFIG_YAML_LIMITS: Final = YamlLimits(MAX_WORKFLOW_BYTES, MAX_WORKFLOW_EVENTS, False)
WEAKENING_CHECKSUM_BEHAVIORS: Final = frozenset({"ignore", "update"})


@dataclass(frozen=True)
class YarnrcYml:
    """What one ``.yarnrc.yml``, or a merge of several, declares.

    Parameters
    ----------
    registry_host : str | None
        The host of ``npmRegistryServer``, when declared.
    scoped_hosts : Mapping[str, str]
        The registry host of each declared scope, keyed ``@scope``.
    checksum_behavior : str | None
        The ``checksumBehavior`` value, when declared.
    """

    registry_host: str | None = None
    scoped_hosts: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    checksum_behavior: str | None = None

    def merged_under(self, nearer: YarnrcYml) -> YarnrcYml:
        """Return this file's declaration with a nearer file's keys winning.

        Parameters
        ----------
        nearer : YarnrcYml
            The declaration of a file closer to the lockfile.

        Returns
        -------
        YarnrcYml
            The merge; scopes merge per scope.
        """
        return YarnrcYml(
            registry_host=nearer.registry_host or self.registry_host,
            scoped_hosts=MappingProxyType({**self.scoped_hosts, **nearer.scoped_hosts}),
            checksum_behavior=nearer.checksum_behavior or self.checksum_behavior,
        )


def _host(value: WorkflowValue) -> str | None:
    """Return the host of a registry value, or ``None`` when it is uncertain."""
    if value.kind != "scalar" or "${" in value.text:
        return None
    return url_host(value.text)


def read_yarnrc_yml(text: str) -> YarnrcYml | None:
    """Read one tracked ``.yarnrc.yml``.

    Parameters
    ----------
    text : str
        The file text.

    Returns
    -------
    YarnrcYml | None
        The declaration, or ``None`` when any read part is uncertain.
    """
    if not text.strip():
        return YarnrcYml()
    try:
        root = parse_workflow_yaml(text, CONFIG_YAML_LIMITS)
    except WorkflowFormatError:
        return None
    if root.kind != "mapping":
        return None
    settings = root.mapping()
    registry_host: str | None = None
    if "npmRegistryServer" in settings:
        registry_host = _host(settings["npmRegistryServer"])
        if registry_host is None:
            return None
    scoped: dict[str, str] = {}
    scopes = settings.get("npmScopes")
    if scopes is not None:
        if scopes.kind != "mapping":
            return None
        for scope, declaration in scopes.pairs:
            if declaration.kind != "mapping":
                return None
            server = declaration.mapping().get("npmRegistryServer")
            if server is None:
                continue
            host = _host(server)
            if host is None:
                return None
            scoped["@" + scope.removeprefix("@")] = host
    behavior = settings.get("checksumBehavior")
    if behavior is not None and (behavior.kind != "scalar" or "${" in behavior.text):
        return None
    return YarnrcYml(
        registry_host=registry_host,
        scoped_hosts=MappingProxyType(scoped),
        checksum_behavior=None if behavior is None else behavior.text,
    )


@dataclass(frozen=True)
class BerryRegistryDeclaration:
    """The registries a repository declares for Yarn 2+, or the fact that they cannot be read.

    Parameters
    ----------
    known : bool
        Whether every configuration file was read with certainty.
    config : YarnrcYml
        The merged declaration.
    """

    known: bool
    config: YarnrcYml = field(default_factory=YarnrcYml)

    def declared_host(self, package_name: str) -> str | None:
        """Return the registry host Yarn would use for a package, if one is declared.

        Parameters
        ----------
        package_name : str
            The package name.

        Returns
        -------
        str | None
            The scope's host, else the default registry's, else ``None``.
        """
        scope = package_name.split("/", 1)[0] if package_name.startswith("@") else ""
        return self.config.scoped_hosts.get(scope) or self.config.registry_host

    def registry_origin(self, package_name: str) -> tuple[str | None, EntryFinding | None]:
        """Return the origin of an ``npm:`` resolution, which has no URL of its own.

        Parameters
        ----------
        package_name : str
            The package name.

        Returns
        -------
        tuple[str | None, EntryFinding | None]
            The declared host, Yarn's default when none is declared, and ``origin-unknown``
            when the declaration cannot be read.
        """
        if not self.known:
            return None, "origin-unknown"
        return self.declared_host(package_name) or "registry.yarnpkg.com", None

    def origin_finding(self, package_name: str, host: str) -> EntryFinding | None:
        """Compare a tarball URL's host with the registry declared for its package.

        Parameters
        ----------
        package_name : str
            The package name.
        host : str
            The host the tarball resolves from.

        Returns
        -------
        EntryFinding | None
            ``origin-unknown``, ``origin-mismatch``, or ``None`` when it matches; with nothing
            declared, Yarn's and npm's default hosts both match.
        """
        if not self.known:
            return "origin-unknown"
        declared = self.declared_host(package_name)
        if declared is None:
            return None if host in YARN_DEFAULT_HOSTS else "origin-mismatch"
        return None if host == declared else "origin-mismatch"


UNKNOWN_BERRY_REGISTRY: Final = BerryRegistryDeclaration(known=False)
