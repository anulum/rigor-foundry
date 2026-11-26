# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — declared Yarn 1 registry witnesses
"""Witness the Yarn 1 registry declaration and origin comparison, as B7 unit 2 Q2 and Q3 rule."""

from __future__ import annotations

import pytest

from rigor_foundry.lockfile_npmrc import npmrc_registry_hosts
from rigor_foundry.lockfile_yarnrc import (
    UNKNOWN_YARN_REGISTRY,
    yarn_registry_declaration,
    yarnrc_registry_hosts,
)


def test_a_yarnrc_declares_quoted_and_bare_registries_per_scope() -> None:
    """``registry`` and ``"@scope:registry"`` lines are read; other lines are ignored."""
    text = (
        "# yarn config\n\n"
        'registry "https://npm.internal.example/"\n'
        '"@acme:registry" "https://acme.example:8443/"\n'
        "--install.frozen-lockfile true\n"
        "lastUpdateCheck 1700000000000\n"
        'yarn-path ".yarn/releases/yarn-1.22.22.cjs"\n'
        'unquoted"half\n'
        "registry https://npm.internal.example/\n"
    )
    assert yarnrc_registry_hosts(text) == {
        "": "npm.internal.example",
        "@acme": "acme.example:8443",
    }
    assert yarnrc_registry_hosts("") == {}


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ('registry "${REGISTRY}"\n', "interpolation"),
        ('registry "https://${HOST}/"\n', "interpolation inside a URL"),
        ('--registry "https://npm.internal.example/"\n', "a registry flag"),
        ('registry "https://a.example/"\nregistry "https://b.example/"\n', "a changed repeat"),
        ('registry "ftp://mirror.example/"\n', "not HTTP(S)"),
        ('registry "https://a.example/" extra\n', "three tokens"),
        ('registry "unterminated\n', "a registry line that does not tokenise"),
        ('registry "bad \\q escape"\n', "an invalid escape"),
    ],
)
def test_an_uncertain_yarnrc_line_makes_the_declaration_uncertain(text: str, reason: str) -> None:
    """Every uncertain registry line gives ``None``, never a guess.

    Parameters
    ----------
    text : str
        The ``.yarnrc`` text.
    reason : str
        Why it is uncertain, for the failure message.
    """
    assert yarnrc_registry_hosts(text) is None, reason


def test_with_nothing_declared_both_default_hosts_match_and_others_mismatch() -> None:
    """Yarn 1's own default host and npm's are both the default registry."""
    declaration = yarn_registry_declaration({}, {})
    assert declaration.known
    assert declaration.origin_finding("left-pad", "registry.yarnpkg.com") is None
    assert declaration.origin_finding("left-pad", "registry.npmjs.org") is None
    assert declaration.origin_finding("left-pad", "evil.example") == "origin-mismatch"


def test_a_declared_registry_follows_yarns_order_and_has_no_placeholder() -> None:
    """Per scope ``.npmrc`` wins over ``.yarnrc``; then the unscoped ones; no default host is a placeholder."""
    npmrc = npmrc_registry_hosts("@acme:registry=https://acme-npm.example/\n")
    yarnrc = yarnrc_registry_hosts(
        'registry "https://yarn.internal.example/"\n"@acme:registry" "https://acme-yarn.example/"\n'
    )
    declaration = yarn_registry_declaration(npmrc, yarnrc)
    assert declaration.declared_host("@acme/tool") == "acme-npm.example"
    assert declaration.declared_host("@other/tool") == "yarn.internal.example"
    assert declaration.declared_host("left-pad") == "yarn.internal.example"
    assert declaration.origin_finding("left-pad", "yarn.internal.example") is None
    assert declaration.origin_finding("left-pad", "registry.yarnpkg.com") == "origin-mismatch"
    assert declaration.origin_finding("@acme/tool", "acme-yarn.example") == "origin-mismatch"
    unscoped = yarn_registry_declaration(
        npmrc_registry_hosts("registry=https://npm.internal.example/\n"), yarnrc
    )
    assert unscoped.declared_host("left-pad") == "npm.internal.example"


@pytest.mark.parametrize(("npmrc", "yarnrc"), [(None, {}), ({}, None), (None, None)])
def test_either_uncertain_file_makes_every_origin_unknown(
    npmrc: dict[str, str] | None, yarnrc: dict[str, str] | None
) -> None:
    """An uncertain ``.npmrc`` or ``.yarnrc`` makes the whole declaration unknown.

    Parameters
    ----------
    npmrc : dict[str, str] | None
        The ``.npmrc`` reading.
    yarnrc : dict[str, str] | None
        The ``.yarnrc`` reading.
    """
    declaration = yarn_registry_declaration(npmrc, yarnrc)
    assert declaration == UNKNOWN_YARN_REGISTRY
    assert declaration.origin_finding("left-pad", "registry.yarnpkg.com") == "origin-unknown"
