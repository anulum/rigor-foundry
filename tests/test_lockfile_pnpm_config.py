# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — declared pnpm registry and patch witnesses
"""Witness ``pnpm-workspace.yaml`` reading and the pnpm origin comparison, as B7 unit 4 Q7/Q9 rule."""

from __future__ import annotations

import pytest

from rigor_foundry.lockfile_pnpm_config import (
    JSR_HOST,
    PNPM_DEFAULT_HOST,
    UNKNOWN_PNPM_REGISTRY,
    PnpmWorkspace,
    pnpm_registry_declaration,
    read_pnpm_workspace,
)


def _read(text: str) -> PnpmWorkspace:
    """Read a workspace file that must be certain."""
    workspace = read_pnpm_workspace(text)
    assert workspace is not None
    return workspace


def test_both_registries_shapes_and_registry_are_read() -> None:
    """The older scope map and the URL-keyed declarations both route scopes; ``registry`` wins."""
    older = _read(
        'packages:\n  - "a/*"\nregistries:\n  default: "https://mirror.example"\n'
        '  "@acme": "https://acme.example:8443/npm/"\n'
    )
    assert dict(older.registry_hosts) == {"": "mirror.example", "@acme": "acme.example:8443"}
    declared = _read(
        "registries:\n"
        '  "https://one.example/":\n    scopes: ["@", "@one"]\n    serverType: npm\n'
        '  "https://two.example/":\n    prefix: work\n    supportsTimeField: true\n'
        'registry: "https://main.example"\n'
    )
    assert dict(declared.registry_hosts) == {"": "main.example", "@one": "one.example"}
    assert _read("  \n") == PnpmWorkspace()
    assert _read("registries: {}\n") == PnpmWorkspace()


def test_patched_dependencies_name_patch_files() -> None:
    """Pnpm 11 keeps each patch's path here, keyed as the lockfile keys its hash."""
    workspace = _read("patchedDependencies:\n  ms@2.1.2: patches/ms@2.1.2.patch\n")
    assert dict(workspace.patches) == {"ms@2.1.2": "patches/ms@2.1.2.patch"}


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ('registry: "${REGISTRY}"\n', "interpolation"),
        ('registry: "https://${HOST}/"\n', "interpolation inside a URL"),
        ('registry: "ftp://mirror.example"\n', "not HTTP(S)"),
        ("registry: [a]\n", "not a scalar"),
        ("registries: [a]\n", "registries not a mapping"),
        (
            'registries:\n  "@a": "https://a.example"\n  "https://b.example/":\n    scopes: ["@b"]\n',
            "mixed",
        ),
        ('registries:\n  "https://a.example/": "https://a.example"\n', "a URL keyed as a scope"),
        ('registries:\n  "@a": "${A}"\n', "scoped interpolation"),
        ('registries:\n  "https://a.example/":\n    _authToken: x\n', "a secret field"),
        ('registries:\n  "https://${H}/":\n    scopes: ["@a"]\n', "an interpolated key"),
        ('registries:\n  "not a url":\n    scopes: ["@a"]\n', "a key that is not a URL"),
        ('registries:\n  "https://a.example/":\n    scopes: "@a"\n', "scopes not a list"),
        ('registries:\n  "https://a.example/":\n    scopes: [[x]]\n', "a scope not a scalar"),
        (
            'registries:\n  "https://a.example/":\n    scopes: ["@a"]\n  "https://b.example/":\n    scopes: ["@a"]\n',
            "a scope routed twice",
        ),
        ("patchedDependencies: [a]\n", "patches not a mapping"),
        ("patchedDependencies:\n  ms@2.1.2: [a]\n", "a patch path not a scalar"),
        ("- a\n", "not a mapping"),
        ("a: &x 1\nb: *x\n", "an anchor"),
        ("a: 1\na: 2\n", "a duplicate key"),
        ("a: [\n", "invalid YAML"),
    ],
)
def test_an_uncertain_workspace_file_reads_as_none(text: str, reason: str) -> None:
    """Every uncertain file gives ``None``, so its origins or patches are unknown.

    Parameters
    ----------
    text : str
        The ``pnpm-workspace.yaml`` text.
    reason : str
        Why it is uncertain, for the failure message.
    """
    assert read_pnpm_workspace(text) is None, reason


def test_a_6_0_lockfile_reads_only_npmrc() -> None:
    """Pnpm 8 ignores ``pnpm-workspace.yaml`` registries, and routes ``@jsr`` like any scope."""
    workspace = _read('registry: "https://elsewhere.example"\n')
    declaration = pnpm_registry_declaration("6.0", {"@acme": "acme.example"}, workspace)
    assert declaration.registry_origin("left-pad") == (PNPM_DEFAULT_HOST, None)
    assert declaration.registry_origin("@acme/tool") == ("acme.example", None)
    assert declaration.registry_origin("@jsr/std__path") == (PNPM_DEFAULT_HOST, None)
    assert pnpm_registry_declaration("6.0", {}, None).known


def test_a_9_0_lockfile_lets_the_yaml_win_and_a_disagreement_is_unknown() -> None:
    """Both files are read, the YAML winning per scope; a scope they disagree on is unknown."""
    workspace = _read(
        'registries:\n  "@b": "https://b-yaml.example"\n  "@c": "https://c.example"\n'
    )
    declaration = pnpm_registry_declaration(
        "9.0", {"": "registry.npmjs.org", "@b": "b-npmrc.example", "@c": "c.example"}, workspace
    )
    assert declaration.registry_origin("left-pad") == (PNPM_DEFAULT_HOST, None)
    assert declaration.registry_origin("@b/tool") == (None, "origin-unknown")
    assert declaration.registry_origin("@c/tool") == ("c.example", None)
    assert declaration.registry_origin("@jsr/std__path") == (JSR_HOST, None)
    assert declaration.origin_finding("@b/tool", "b-yaml.example") == "origin-unknown"
    assert declaration.origin_finding("@c/tool", "c.example") is None
    assert declaration.origin_finding("@c/tool", "evil.example") == "origin-mismatch"
    default = pnpm_registry_declaration(
        "9.0", {"": "one.example"}, _read('registry: "https://two.example"\n')
    )
    assert default.registry_origin("left-pad") == (None, "origin-unknown")


def test_an_uncertain_file_makes_every_origin_unknown() -> None:
    """An uncertain ``.npmrc``, or an uncertain YAML for ``9.0``, is never read as the default."""
    assert pnpm_registry_declaration("9.0", None, PnpmWorkspace()) == UNKNOWN_PNPM_REGISTRY
    assert pnpm_registry_declaration("9.0", {}, None) == UNKNOWN_PNPM_REGISTRY
    assert UNKNOWN_PNPM_REGISTRY.registry_origin("left-pad") == (None, "origin-unknown")
    assert UNKNOWN_PNPM_REGISTRY.origin_finding("left-pad", PNPM_DEFAULT_HOST) == "origin-unknown"


def test_a_yaml_only_scope_is_unknown_because_pnpm_10_would_use_the_default() -> None:
    """Pnpm 10 ignores a scope only the YAML declares; pnpm 11 follows it: the views differ."""
    workspace = _read('registries:\n  "@acme": "https://npm.acme.internal"\n')
    declaration = pnpm_registry_declaration("9.0", {}, workspace)
    assert declaration.registry_origin("@acme/tool") == (None, "origin-unknown")
    assert declaration.registry_origin("left-pad") == (PNPM_DEFAULT_HOST, None)


def test_a_yaml_only_default_makes_every_unrouted_package_unknown() -> None:
    """A YAML-only ``registry`` changes the default in pnpm 11 only; ``@jsr`` keeps its own route."""
    declaration = pnpm_registry_declaration(
        "9.0", {}, _read('registry: "https://mirror.internal"\n')
    )
    assert declaration.registry_origin("left-pad") == (None, "origin-unknown")
    assert declaration.registry_origin("@other/tool") == (None, "origin-unknown")
    assert declaration.registry_origin("@jsr/std__path") == (JSR_HOST, None)


@pytest.mark.parametrize(
    "text",
    [
        'registry: "https://registry.npmjs.org"\n',
        'registries:\n  "@acme": "https://registry.npmjs.org"\n',
    ],
)
def test_a_yaml_entry_equal_to_the_pnpm_10_view_stays_clean(text: str) -> None:
    """When both views give the same host, nothing is unknown.

    Parameters
    ----------
    text : str
        The ``pnpm-workspace.yaml`` text.
    """
    declaration = pnpm_registry_declaration("9.0", {}, _read(text))
    assert declaration.conflicts == frozenset()
    assert declaration.registry_origin("@acme/tool") == (PNPM_DEFAULT_HOST, None)
