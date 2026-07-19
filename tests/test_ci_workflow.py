# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CI workflow contract tests
"""Verify the hosted CI coverage publication boundary."""

from pathlib import Path


def test_codecov_upload_is_exact_oidc_and_fail_closed() -> None:
    """Require isolated OIDC upload of the existing Python 3.12 report."""
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    coverage_job = workflow.split("\n  coverage:\n", maxsplit=1)[1].split(
        "\n  distribution:\n", maxsplit=1
    )[0]
    assert "needs: test" in coverage_job
    assert "permissions:\n      contents: read\n      id-token: write" in coverage_job
    assert "persist-credentials: false" in coverage_job
    assert "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in coverage_job
    assert "codecov/codecov-action@fb8b3582c8e4def4969c97caa2f19720cb33a72f" in coverage_job
    assert "use_oidc: true" in coverage_job
    assert "files: coverage.xml" in coverage_job
    assert "disable_search: true" in coverage_job
    assert "fail_ci_if_error: true" in coverage_job
    assert "CODECOV_TOKEN" not in coverage_job
