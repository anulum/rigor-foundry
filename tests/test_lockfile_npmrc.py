# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — declared npm registry witnesses
"""Witness the npm registry declaration and the origin comparison B7 Q5 rules on."""

from __future__ import annotations

import pytest

from rigor_foundry.lockfile_npmrc import (
    DEFAULT_NPM_REGISTRY,
    UNKNOWN_NPM_REGISTRY,
    read_npmrc,
    url_host,
)


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://registry.npmjs.org/", "registry.npmjs.org"),
        ("https://NPM.Internal.Example:8443/npm/", "npm.internal.example:8443"),
        ("http://mirror.example/x.tgz", "mirror.example"),
        ("git+ssh://git@github.com/a/b.git", None),
        ("file:../x.tgz", None),
        ("https://", None),
        ("https://host:notaport/", None),
    ],
)
def test_a_url_host_keeps_an_explicit_port_and_needs_http(url: str, host: str | None) -> None:
    """Only an HTTP(S) URL with a host has a comparable host.

    Parameters
    ----------
    url : str
        The URL.
    host : str | None
        The expected comparable host.
    """
    assert url_host(url) == host


def test_no_npmrc_declares_the_documented_default_registry() -> None:
    """The default registry matches itself, and any other host is a mismatch."""
    assert DEFAULT_NPM_REGISTRY.known
    assert DEFAULT_NPM_REGISTRY.origin_finding("left-pad", "registry.npmjs.org") is None
    assert DEFAULT_NPM_REGISTRY.origin_finding("left-pad", "evil.example") == "origin-mismatch"
    assert read_npmrc("") == DEFAULT_NPM_REGISTRY
    assert read_npmrc("; comment\n# comment\n\nsave-exact=true\nnot an assignment\n") == (
        DEFAULT_NPM_REGISTRY
    )


def test_a_declared_registry_and_scope_are_compared_and_the_placeholder_matches() -> None:
    """The placeholder host stands for the configured registry; other hosts compare literally."""
    declared = read_npmrc(
        'registry = "https://npm.internal.example/"\n'
        "@acme:registry=https://acme.example:8443/\n"
        "replace-registry-host=npmjs\n"
        "//npm.internal.example/:_authToken=${TOKEN}\n"
    )
    assert declared.known
    assert declared.origin_finding("left-pad", "npm.internal.example") is None
    assert declared.origin_finding("left-pad", "registry.npmjs.org") is None
    assert declared.origin_finding("left-pad", "registry.yarnpkg.com") == "origin-mismatch"
    assert declared.origin_finding("@acme/tool", "acme.example:8443") is None
    assert declared.origin_finding("@acme/tool", "npm.internal.example") == "origin-mismatch"
    assert declared.origin_finding("@other/tool", "npm.internal.example") is None


def test_a_repeated_key_with_the_same_value_is_read() -> None:
    """Repeating a registry line unchanged leaves the declaration certain."""
    text = "registry=https://npm.internal.example/\nregistry=https://npm.internal.example/\n"
    assert read_npmrc(text).registry_host == "npm.internal.example"


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("registry=${NPM_REGISTRY}\n", "registry interpolation"),
        ("@acme:registry=https://${HOST}/\n", "scoped interpolation"),
        ("replace-registry-host=always\n", "the placeholder no longer means the registry"),
        ("replace-registry-host=npm.internal.example\n", "a replaced host"),
        ("[section]\nregistry=https://x.example/\n", "a section header"),
        (
            "registry=https://a.example/\nregistry=https://b.example/\n",
            "a repeated key with a different value",
        ),
        ("registry=ftp://mirror.example/\n", "a registry that is not HTTP(S)"),
        ("@acme:registry=not-a-url\n", "a scoped registry that is not a URL"),
    ],
)
def test_an_uncertain_declaration_makes_every_origin_unknown(text: str, reason: str) -> None:
    """Every uncertain declaration gives ``origin-unknown`` for every host, never a pass.

    Parameters
    ----------
    text : str
        The ``.npmrc`` text.
    reason : str
        Why it is uncertain, for the failure message.
    """
    declared = read_npmrc(text)
    assert declared == UNKNOWN_NPM_REGISTRY, reason
    assert declared.origin_finding("left-pad", "registry.npmjs.org") == "origin-unknown"
