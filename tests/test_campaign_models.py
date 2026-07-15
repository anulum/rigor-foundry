# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — audit campaign protocol model tests
"""Verify toolchain identity and content-addressed campaign record integrity."""

from __future__ import annotations

from rigor_foundry.campaign_models import ToolchainIdentity


def test_toolchain_identity_round_trip_binds_the_runtime_executable() -> None:
    """Runtime identity survives round-trip and rejects altered executable evidence."""
    identity = ToolchainIdentity.current()

    assert ToolchainIdentity.from_dict(identity.to_dict()) == identity
    assert len(identity.executable_digest) == 64
    assert len(identity.identity_digest) == 64

    changed = identity.to_dict()
    changed["executable_digest"] = "0" * 64
    try:
        ToolchainIdentity.from_dict(changed)
    except ValueError as exc:
        assert "identity digest" in str(exc)
    else:
        raise AssertionError("altered toolchain evidence was accepted")
