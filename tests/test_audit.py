# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Repository conformance audit tests
"""Exercise the production repository through its composed audit boundary."""

from tools.audit import audit_errors


def test_repository_passes_portable_conformance_audit() -> None:
    """All required surfaces and nested guards agree on the worktree."""
    assert audit_errors() == []
