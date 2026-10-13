# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed first-operation failure codes
"""Carry pinned first-operation code domains without parsing diagnostic text."""

from __future__ import annotations

from typing import Final

PRE_EFFECT_CODES_V2: Final = frozenset(
    {
        "descent-refused",
        "not-regular",
        "pre-state-too-large",
        "foreign-acl-entries",
        "acl-unreadable",
        "sample-identity-drift",
        "cancelled-before-effect-intent",
        "killed-before-effect-intent",
        "pre-state-unreadable",
        "ended-before-effect-intent",
        "foreign-owner",
        "owner-access-undeterminable",
    }
)

PRE_RENAME_CODES_V2: Final = frozenset(
    {
        "target-drift",
        "parent-moved",
        "root-moved",
        "unregistered-ancestor-repository",
        "temporary-create-failed",
        "temporary-write-failed",
        "temporary-access-failed",
        "temporary-link-failed",
        "temporary-identity-mismatch",
        "noreplace-unsupported",
        "rename-failed",
        "cancelled",
    }
)


class PreEffectRefusalV2(PermissionError):
    """Carry a closed failure code before durable effect intent.

    Parameters
    ----------
    code : str
        Member of PRE_EFFECT_CODES_V2; arbitrary diagnostic text cannot define a new code.
    detail : str
        Readable diagnostic text retained in the exception message.

    Attributes
    ----------
    code : str
        Validated stable failure code for structured refusal handling.

    Raises
    ------
    ValueError
        The code is outside the registered pre-effect domain.
    """

    def __init__(self, code: str, detail: str) -> None:
        """Require a registered code while retaining readable diagnostic text."""
        if code not in PRE_EFFECT_CODES_V2:
            raise ValueError("Tier-0 pre-effect refusal code is not registered")
        self.code = code
        super().__init__(detail)
