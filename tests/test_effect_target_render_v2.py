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
