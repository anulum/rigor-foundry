# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed pre-effect refusal tests
"""Require structured failure codes before handler journal wiring."""

from __future__ import annotations

import pytest

from rigor_foundry.tier0_builtin.atomic_replace_refusal_v2 import (
    PRE_EFFECT_CODES_V2,
    PreEffectRefusalV2,
)


def test_pre_effect_refusal_carries_only_registered_codes() -> None:
    """A handler can use the code field without reading diagnostic prose."""
    refusal = PreEffectRefusalV2("sample-identity-drift", "detail can change")
    assert refusal.code in PRE_EFFECT_CODES_V2
    assert refusal.code == "sample-identity-drift"
    assert str(refusal) == "detail can change"
    with pytest.raises(ValueError, match="not registered"):
        PreEffectRefusalV2("unknown", "unreviewed")
