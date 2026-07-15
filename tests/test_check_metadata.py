# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Distribution metadata guard tests
"""Verify package, citation, archive, and licence metadata agree."""

from tools.check_metadata import metadata_errors


def test_release_metadata_is_consistent_across_public_surfaces() -> None:
    """The production repository has one package identity and version."""
    assert metadata_errors() == []
