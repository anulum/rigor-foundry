# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — extracted target overlap tests
"""Exercise component-wise path overlap and exact non-path matching."""

from __future__ import annotations

import pytest

from rigor_foundry.effect_target_overlap_v2 import parsed_effect_targets_overlap_v2


def _target(form: str, value: str) -> dict[str, str]:
    """Construct a target-ref body accepted by the journal wire."""
    return {"form": form, "value": value}


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("/a", "/a", True),
        ("/a", "/a/b", True),
        ("/a/b", "/a", True),
        ("/", "/a", True),
        ("/a", "/", True),
        ("/a", "/ab", False),
        ("/a/b", "/a/c", False),
    ],
)
def test_path_overlap_uses_components(left: str, right: str, expected: bool) -> None:
    """A sibling or common text prefix cannot be mistaken for ancestry."""
    assert (
        parsed_effect_targets_overlap_v2(_target("path", left), _target("path", right)) is expected
    )


def test_nonpath_targets_use_exact_form_and_value() -> None:
    """A remote, endpoint or project overlaps only its own exact reference."""
    assert parsed_effect_targets_overlap_v2(
        _target("remote", "https://example.org/a"),
        _target("remote", "https://example.org/a"),
    )
    assert not parsed_effect_targets_overlap_v2(
        _target("remote", "https://example.org/a"),
        _target("remote", "https://example.org/a/b"),
    )
    assert not parsed_effect_targets_overlap_v2(_target("path", "/a"), _target("project", "a"))
    assert parsed_effect_targets_overlap_v2(
        _target("endpoint", "svc:resource"), _target("endpoint", "svc:resource")
    )


def test_invalid_target_ref_refuses_before_comparison() -> None:
    """A malformed path cannot bypass blocking through text comparison."""
    with pytest.raises(ValueError):
        parsed_effect_targets_overlap_v2(_target("path", "/a/../b"), _target("path", "/a"))
