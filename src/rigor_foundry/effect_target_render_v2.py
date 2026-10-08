# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — canonical extracted target rendering
"""Render one validated extracted target for v2 admission comparisons."""

from __future__ import annotations

from .effect_journal_records_v2 import parse_effect_target_ref_v2


def render_target_v2(target_ref: object, target_kind: str) -> str:
    """Render a target identically for permit, owner authorization and clause matching.

    Compute hosts use the selector's ``host:<id>`` spelling. Every other
    target uses ``form:value``. The closed target-ref parser is shared with
    the effect journal, so malformed caller text cannot gain another form.

    Parameters
    ----------
    target_ref
        Closed extracted target mapping with exact form and value.
    target_kind
        Consumer's target classification; compute hosts require host endpoints.

    Returns
    -------
    str
        Exact selector spelling without normalising the original identity.

    Raises
    ------
    ValueError
        If target syntax or the compute-host classification differs.
    """
    form, value = parse_effect_target_ref_v2(target_ref)
    if target_kind == "compute-host":
        if form != "endpoint" or not value.startswith("host:"):
            raise ValueError("compute host action target must use host form")
        return value
    if form == "endpoint" and value.startswith("host:"):
        raise ValueError("host action target has the wrong kind")
    return f"{form}:{value}"
