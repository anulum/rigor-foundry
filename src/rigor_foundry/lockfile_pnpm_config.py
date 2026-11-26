# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the registries and patches a repository declares for pnpm
"""Read what ``.npmrc`` and ``pnpm-workspace.yaml`` declare for pnpm, and compare a locked origin.

pnpm 8 (lockfile ``6.0``) reads its registries from ``.npmrc`` only. A ``9.0`` lockfile may be
installed by pnpm 9, 10 or 11, which differ: pnpm 10 builds its registries from its defaults and
``.npmrc`` before it reads the YAML, while pnpm 11 lets ``pnpm-workspace.yaml``'s ``registry`` and
``registries`` win; pnpm 10 and 11 route the ``@jsr`` scope to ``npm.jsr.io`` unless told
otherwise. So for ``9.0`` the two views are built, the pnpm 10 view (the defaults and ``.npmrc``)
and the pnpm 11 view (that, with the YAML over it), and every scope whose host differs between them
has an unknown origin, because the pnpm that runs decides.

``pnpm-workspace.yaml`` is read as pnpm 11 reads it: ``registries`` maps either scopes to URLs
(``default`` or ``@`` for the default registry), or registry URLs to declarations whose
``scopes`` route to them; a mix, an unknown declaration field, a scope routed twice, ``${…}`` in
a read value, or a value that is not an HTTP(S) URL is uncertain. Its ``patchedDependencies``
names the patch file of each patched package, which pnpm 11 no longer writes into the lockfile.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from .lockfile_model import EntryFinding
from .lockfile_npmrc import url_host
from .lockfile_yarnrc_yml import CONFIG_YAML_LIMITS
from .workflow_yaml import WorkflowFormatError, WorkflowValue, parse_workflow_yaml

PNPM_DEFAULT_HOST: Final = "registry.npmjs.org"
JSR_SCOPE: Final = "@jsr"
JSR_HOST: Final = "npm.jsr.io"
_DECLARATION_FIELDS: Final = frozenset({"serverType", "supportsTimeField", "scopes", "prefix"})
_DEFAULT_SCOPES: Final = frozenset({"default", "@"})


def _empty() -> Mapping[str, str]:
    """Return an empty read-only mapping."""
    return MappingProxyType({})


@dataclass(frozen=True)
class PnpmWorkspace:
    """What one ``pnpm-workspace.yaml`` declares about registries and patches.

    Parameters
    ----------
    registry_hosts : Mapping[str, str]
        The registry host of each declared scope, ``""`` for the default registry.
    patches : Mapping[str, str]
        The patch file of each ``patchedDependencies`` key, as written.
    """

    registry_hosts: Mapping[str, str] = field(default_factory=_empty)
    patches: Mapping[str, str] = field(default_factory=_empty)


def _host(value: WorkflowValue) -> str | None:
    """Return the host of a registry URL value, or ``None`` when it is uncertain."""
    if value.kind != "scalar" or "${" in value.text:
        return None
    return url_host(value.text)


def _scope(name: str) -> str:
    """Return the scope key of a routed scope, ``""`` for the default registry."""
    return "" if name in _DEFAULT_SCOPES else name


def _scope_routes(pairs: tuple[tuple[str, WorkflowValue], ...]) -> dict[str, str] | None:
    """Read the older ``registries`` shape, ``<scope>: <url>``."""
    routes: dict[str, str] = {}
    for scope, url in pairs:
        host = _host(url)
        if host is None or url_host(scope) is not None:
            return None
        routes[_scope(scope)] = host
    return routes


def _declared_routes(pairs: tuple[tuple[str, WorkflowValue], ...]) -> dict[str, str] | None:
    """Read the ``registries`` shape keyed by registry URL, inverting each ``scopes`` list."""
    routes: dict[str, str] = {}
    for url, declaration in pairs:
        host = None if "${" in url else url_host(url)
        fields = declaration.mapping()
        if host is None or not _DECLARATION_FIELDS.issuperset(fields):
            return None
        scopes = fields.get("scopes")
        if scopes is None:
            continue
        if scopes.kind != "sequence" or any(item.kind != "scalar" for item in scopes.items):
            return None
        for item in scopes.items:
            scope = _scope(item.text)
            if scope in routes:
                return None
            routes[scope] = host
    return routes


def _registries(value: WorkflowValue) -> dict[str, str] | None:
    """Read the ``registries`` setting in either of its shapes, or ``None`` when uncertain."""
    if value.kind != "mapping":
        return None
    kinds = {declaration.kind for _, declaration in value.pairs}
    if kinds <= {"scalar"}:
        return _scope_routes(value.pairs)
    if kinds == {"mapping"}:
        return _declared_routes(value.pairs)
    return None


def _patches(value: WorkflowValue) -> dict[str, str] | None:
    """Read ``patchedDependencies``: each key names a patch file path."""
    if value.kind != "mapping" or any(path.kind != "scalar" for _, path in value.pairs):
        return None
    return {key: path.text for key, path in value.pairs}


def read_pnpm_workspace(text: str) -> PnpmWorkspace | None:
    """Read one tracked ``pnpm-workspace.yaml``.

    Parameters
    ----------
    text : str
        The file text.

    Returns
    -------
    PnpmWorkspace | None
        The declaration, or ``None`` when any read part is uncertain.
    """
    if not text.strip():
        return PnpmWorkspace()
    try:
        root = parse_workflow_yaml(text, CONFIG_YAML_LIMITS)
    except WorkflowFormatError:
        return None
    if root.kind != "mapping":
        return None
    settings = root.mapping()
    hosts: dict[str, str] = {}
    registries = settings.get("registries")
    if registries is not None:
        routes = _registries(registries)
        if routes is None:
            return None
        hosts.update(routes)
    registry = settings.get("registry")
    if registry is not None:
        host = _host(registry)
        if host is None:
            return None
        hosts[""] = host
    patches: dict[str, str] = {}
    declared = settings.get("patchedDependencies")
    if declared is not None:
        read = _patches(declared)
        if read is None:
            return None
        patches = read
    return PnpmWorkspace(MappingProxyType(hosts), MappingProxyType(patches))


@dataclass(frozen=True)
class PnpmRegistryDeclaration:
    """The registries pnpm would use for one lockfile, or the fact that they cannot be read.

    Parameters
    ----------
    known : bool
        Whether every configuration file was read with certainty.
    hosts : Mapping[str, str]
        The registry host of each scope, ``""`` for the default registry.
    conflicts : frozenset[str]
        The scopes whose host differs between the pnpm 10 and pnpm 11 views.
    """

    known: bool
    hosts: Mapping[str, str] = field(default_factory=_empty)
    conflicts: frozenset[str] = frozenset()

    def registry_origin(self, package_name: str) -> tuple[str | None, EntryFinding | None]:
        """Return the registry host a package resolves from.

        Parameters
        ----------
        package_name : str
            The package name, such as ``left-pad`` or ``@scope/tool``.

        Returns
        -------
        tuple[str | None, EntryFinding | None]
            The host, or ``None`` with ``origin-unknown`` when the declaration cannot be read or
            the scope's files disagree.
        """
        if not self.known:
            return None, "origin-unknown"
        scope = package_name.split("/", 1)[0] if package_name.startswith("@") else ""
        if scope not in self.hosts and scope not in self.conflicts:
            scope = ""
        if scope in self.conflicts:
            return None, "origin-unknown"
        return self.hosts.get(scope, PNPM_DEFAULT_HOST), None

    def origin_finding(self, package_name: str, host: str) -> EntryFinding | None:
        """Compare a tarball's host with the registry declared for its package.

        Parameters
        ----------
        package_name : str
            The package name.
        host : str
            The host the tarball resolves from.

        Returns
        -------
        EntryFinding | None
            ``origin-unknown``, ``origin-mismatch``, or ``None`` when it matches.
        """
        declared, finding = self.registry_origin(package_name)
        if finding is not None:
            return finding
        return None if host == declared else "origin-mismatch"


UNKNOWN_PNPM_REGISTRY: Final = PnpmRegistryDeclaration(known=False)


def pnpm_registry_declaration(
    lockfile_version: str,
    npmrc_hosts: Mapping[str, str] | None,
    workspace: PnpmWorkspace | None,
) -> PnpmRegistryDeclaration:
    """Merge the registry declarations pnpm reads for one lockfile version.

    Parameters
    ----------
    lockfile_version : str
        ``6.0`` or ``9.0``.
    npmrc_hosts : Mapping[str, str] | None
        The hosts the ``.npmrc`` beside the lockfile declares, ``""`` for the default; ``None``
        when it cannot be read with certainty.
    workspace : PnpmWorkspace | None
        The ``pnpm-workspace.yaml`` beside the lockfile; ``None`` when it cannot be read with
        certainty. It is not read for ``6.0``.

    Returns
    -------
    PnpmRegistryDeclaration
        The pnpm 11 view, with every scope whose host the pnpm 10 view gives differently marked as
        a conflict.
    """
    if npmrc_hosts is None:
        return UNKNOWN_PNPM_REGISTRY
    if lockfile_version == "6.0":
        return PnpmRegistryDeclaration(
            True, MappingProxyType({"": PNPM_DEFAULT_HOST, **npmrc_hosts})
        )
    if workspace is None:
        return UNKNOWN_PNPM_REGISTRY
    pnpm10 = {"": PNPM_DEFAULT_HOST, JSR_SCOPE: JSR_HOST, **npmrc_hosts}
    pnpm11 = {**pnpm10, **workspace.registry_hosts}
    conflicts = {
        scope for scope in pnpm11 if pnpm10.get(scope, pnpm10[""]) != pnpm11.get(scope, pnpm11[""])
    }
    return PnpmRegistryDeclaration(True, MappingProxyType(pnpm11), frozenset(conflicts))
