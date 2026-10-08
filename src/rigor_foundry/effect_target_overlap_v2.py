# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — extracted effect target overlap
"""Compare extracted target references independently of effect class."""

from __future__ import annotations

from .effect_journal_records_v2 import parse_effect_target_ref_v2

TargetKeyV2 = tuple[str, str]


def _effect_targets_overlap_v2(left: TargetKeyV2, right: TargetKeyV2) -> bool:
    """Compare already validated target keys by component ancestry or equality."""
    left_form, left_value = left
    right_form, right_value = right
    if left_form != right_form:
        return False
    if left_form != "path":
        return left_value == right_value
    return (
        left_value == right_value
        or left_value == "/"
        or right_value == "/"
        or left_value.startswith(right_value + "/")
        or right_value.startswith(left_value + "/")
    )


def parsed_effect_targets_overlap_v2(left: object, right: object) -> bool:
    """Validate extracted targets before comparing component ancestry.

    Parameters
    ----------
    left, right
        Closed target mappings with exact form and value.

    Returns
    -------
    bool
        Whether paths share ancestry or non-path targets have equal identity.

    Raises
    ------
    ValueError
        If either target fails the shared public target parser.
    """
    return _effect_targets_overlap_v2(
        parse_effect_target_ref_v2(left), parse_effect_target_ref_v2(right)
    )
