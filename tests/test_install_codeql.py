# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified CodeQL bundle installer tests
"""Verify the CodeQL checksum relation and public installer contract."""

from __future__ import annotations

import pytest

from tools.install_codeql import (
    CODEQL_BUNDLE_DIGEST,
    CODEQL_BUNDLE_NAME,
    CODEQL_CHECKSUM_DIGEST,
    CODEQL_VERSION,
    main,
    verify_checksum_document,
)


def test_official_codeql_checksum_document_matches_both_release_pins() -> None:
    """The retained official manifest bytes bind the exact bundle identity."""
    payload = f"{CODEQL_BUNDLE_DIGEST}  {CODEQL_BUNDLE_NAME}\n".encode()
    verify_checksum_document(payload)
    assert len(CODEQL_CHECKSUM_DIGEST) == 64
    assert CODEQL_VERSION == "2.26.0"


def test_codeql_installer_cli_and_digest_failure_are_fail_closed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The public installer documents its destination and rejects altered manifests."""
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
    assert "--destination" in capsys.readouterr().out
    with pytest.raises(ValueError, match="checksum document digest"):
        verify_checksum_document(b"untrusted checksum document")
