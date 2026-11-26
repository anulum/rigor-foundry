# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — declared Yarn 2+ registry witnesses
"""Witness ``.yarnrc.yml`` reading and the Yarn 2+ origin comparison, as B7 unit 3 Q3 rules."""

from __future__ import annotations

import pytest

from rigor_foundry.lockfile_yarnrc_yml import (
    UNKNOWN_BERRY_REGISTRY,
    BerryRegistryDeclaration,
    YarnrcYml,
    read_yarnrc_yml,
)

CONFIG = """\
npmRegistryServer: "https://npm.internal.example"
npmScopes:
  acme:
    npmRegistryServer: "https://acme.example:8443"
  "@tools":
    npmAuthToken: secret
checksumBehavior: ignore
nodeLinker: node-modules
"""


def test_a_yarnrc_yml_declares_its_registry_scopes_and_checksum_behaviour() -> None:
    """Registry, scoped registries and ``checksumBehavior`` are read; other keys are ignored."""
    config = read_yarnrc_yml(CONFIG)
    assert config is not None
    assert config.registry_host == "npm.internal.example"
    assert dict(config.scoped_hosts) == {"@acme": "acme.example:8443"}
    assert config.checksum_behavior == "ignore"
    assert read_yarnrc_yml("  \n") == YarnrcYml()


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ('npmRegistryServer: "${REGISTRY}"\n', "interpolation"),
        ('npmRegistryServer: "ftp://mirror.example"\n', "not HTTP(S)"),
        ("npmRegistryServer: [a]\n", "not a scalar"),
        ("npmScopes: [a]\n", "scopes not a mapping"),
        ("npmScopes:\n  acme: x\n", "a scope not a mapping"),
        (
            'npmScopes:\n  acme:\n    npmRegistryServer: "https://${HOST}"\n',
            "scoped interpolation",
        ),
        ("checksumBehavior: ${BEHAVIOUR}\n", "behaviour interpolation"),
        ("checksumBehavior: [a]\n", "behaviour not a scalar"),
        ("- a\n", "not a mapping"),
        ("a: &x 1\nb: *x\n", "an anchor"),
        ("a: !!str 1\n", "a tag"),
        ("a: 1\na: 2\n", "a duplicate key"),
        ("a: [\n", "invalid YAML"),
    ],
)
def test_an_uncertain_yarnrc_yml_reads_as_none(text: str, reason: str) -> None:
    """Every uncertain file gives ``None``, so every origin is unknown.

    Parameters
    ----------
    text : str
        The ``.yarnrc.yml`` text.
    reason : str
        Why it is uncertain, for the failure message.
    """
    assert read_yarnrc_yml(text) is None, reason


def test_a_nearer_file_wins_per_key_and_scopes_merge_per_scope() -> None:
    """A nearer file declaring one scope keeps the others and its own keys win."""
    root = read_yarnrc_yml(
        'npmRegistryServer: "https://root.example"\nnpmScopes:\n  a:\n    npmRegistryServer: "https://a.example"\n'
    )
    nearer = read_yarnrc_yml(
        'npmScopes:\n  b:\n    npmRegistryServer: "https://b.example"\nchecksumBehavior: update\n'
    )
    assert root is not None and nearer is not None
    merged = root.merged_under(nearer)
    assert merged.registry_host == "root.example"
    assert dict(merged.scoped_hosts) == {"@a": "a.example", "@b": "b.example"}
    assert merged.checksum_behavior == "update"
    competing = read_yarnrc_yml('npmRegistryServer: "https://nearer.example"\n')
    assert competing is not None
    assert root.merged_under(competing).registry_host == "nearer.example"


def test_npm_resolutions_take_the_declared_registry_and_tarballs_are_compared() -> None:
    """With nothing declared Yarn's default applies; a declared registry has no placeholder."""
    default = BerryRegistryDeclaration(known=True)
    assert default.registry_origin("debug") == ("registry.yarnpkg.com", None)
    assert default.origin_finding("debug", "registry.npmjs.org") is None
    assert default.origin_finding("debug", "evil.example") == "origin-mismatch"
    config = read_yarnrc_yml(CONFIG)
    assert config is not None
    declared = BerryRegistryDeclaration(known=True, config=config)
    assert declared.registry_origin("@acme/tool") == ("acme.example:8443", None)
    assert declared.registry_origin("debug") == ("npm.internal.example", None)
    assert declared.origin_finding("debug", "registry.yarnpkg.com") == "origin-mismatch"
    assert declared.origin_finding("debug", "npm.internal.example") is None
    assert UNKNOWN_BERRY_REGISTRY.registry_origin("debug") == (None, "origin-unknown")
    assert (
        UNKNOWN_BERRY_REGISTRY.origin_finding("debug", "registry.yarnpkg.com") == "origin-unknown"
    )
