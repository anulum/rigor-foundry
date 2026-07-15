# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Commit attribution guard tests
"""Verify conventional subjects and vendor-neutral seat attribution."""

from tools.check_commit_message import AUTHORSHIP, commit_message_errors


def test_agent_commit_requires_canonical_authorship_and_vendor_neutral_seat() -> None:
    """Agent attribution survives rebases without exposing a provider identity."""
    for seat in ("4184931", "r715"):
        valid = f"feat(core): add evidence lock\n\nSeat: {seat}\n\n{AUTHORSHIP}\n"
        assert commit_message_errors(valid) == []

    invalid_seat = "co" + "dex-4184931"
    invalid = f"feat(core): add evidence lock\n\nSeat: {invalid_seat}\n\n{AUTHORSHIP}\n"
    errors = commit_message_errors(invalid)
    assert "public commit message contains a vendor or model identity" in errors
    assert "Seat trailer must contain only the alphanumeric seat suffix" in errors


def test_human_conventional_commit_needs_no_internal_trailers() -> None:
    """External human commits remain compatible with the public hook."""
    assert commit_message_errors("docs: clarify installation\n") == []
