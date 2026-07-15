# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Release tag guard tests
"""Verify tag and package version equality."""

from tools.check_release_tag import release_tag_errors


def test_release_tag_matches_the_single_package_version() -> None:
    """Release automation rejects aliases and metadata drift."""
    assert release_tag_errors("v0.1.0") == []
    assert release_tag_errors("0.1.0") == ["release tag '0.1.0' does not match 'v0.1.0'"]
