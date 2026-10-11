# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — canonical target rendering tests
"""Exercise exact extracted target rendering used by admission consumers."""

from __future__ import annotations

import pytest

from rigor_foundry.effect_target_render_v2 import render_target_v2


@pytest.mark.parametrize(
    ("target_ref", "kind", "rendered"),
    [
        (
            {"form": "path", "value": "/srv/rigor/result"},
            "filesystem-path",
            "path:/srv/rigor/result",
        ),
        (
            {"form": "remote", "value": "https://example.test/r"},
            "repository",
            "remote:https://example.test/r",
        ),
        ({"form": "endpoint", "value": "smtp:owner"}, "send-channel", "endpoint:smtp:owner"),
        ({"form": "endpoint", "value": "host:ml350"}, "compute-host", "host:ml350"),
    ],
)
def test_exact_target_rendering(target_ref: dict[str, str], kind: str, rendered: str) -> None:
    """Each consumer sees the same selector text for a validated target."""
    assert render_target_v2(target_ref, kind) == rendered


@pytest.mark.parametrize(
    ("target_ref", "kind", "reason"),
    [
        ({"form": "path", "value": "/srv/../other"}, "filesystem-path", "canonical"),
        ({"form": "endpoint", "value": "host:ml350"}, "send-channel", "wrong kind"),
        ({"form": "endpoint", "value": "smtp:owner"}, "compute-host", "host form"),
        ({"form": "path", "value": "/srv/rigor"}, "compute-host", "host form"),
        ({"form": "endpoint", "value": "host:ML350"}, "compute-host", "malformed"),
    ],
)
def test_malformed_or_misclassified_target_refuses(
    target_ref: dict[str, str], kind: str, reason: str
) -> None:
    """A caller cannot smuggle host spelling into a different target kind."""
    with pytest.raises(ValueError, match=reason):
        render_target_v2(target_ref, kind)


@pytest.mark.parametrize(
    "uri",
    [
        "https://example.test/path?public=1",
        "https://example.test:443/path",
        "https://[::1]/path",
        "https://[2001:db8::1]:443/path",
        "https://[fe80::1%eth0]/path",
        "https://[v1.future]/path",
        "https://example\u00e9.test/path",
        "custom+v2.1://example.test/path",
        "https://example.test/path@name?value=%40",
    ],
)
def test_remote_target_identity_survives_consumer_rendering(uri: str) -> None:
    """Preserve a valid remote identity through the public admission consumer.

    Parameters
    ----------
    uri
        URI covering DNS, Unicode, bracketed address, port or opaque suffix syntax.
    """
    assert render_target_v2({"form": "remote", "value": uri}, "repository") == f"remote:{uri}"


@pytest.mark.parametrize(
    "uri",
    [
        "http:example.test",
        "HTTPS://example.test/",
        "1https://example.test/",
        "https://",
        "https:///path",
        "https://?query",
        "https://user@example.test/",
        "https://user%40example.test/",
        "https://example.test/#",
        "https://example.test/a b",
        "https://example.test/\tpath",
        "https://example\uff0ftest/",
        "https://example\uff1ftest/",
        "https://example\uff03test/",
        "https://example\uff20test/",
        "https://example\uff1atest/",
        "https://[::1/",
        "https://::1]/",
        "https://prefix[::1]/",
        "https://[::1]suffix/",
        "https://[::1]:443]/",
        "https://[127.0.0.1]/",
        "https://[invalid]/",
        "https://[v.future]/",
        "https://[v1.]/",
    ],
)
def test_malformed_remote_identity_refuses_consumer_rendering(uri: str) -> None:
    """Reject malformed remote identities before admission selectors are emitted.

    Parameters
    ----------
    uri
        URI with a malformed scheme or authority, forbidden field or ambiguous delimiter.
    """
    with pytest.raises(ValueError, match="remote"):
        render_target_v2({"form": "remote", "value": uri}, "repository")
