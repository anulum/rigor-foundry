# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Redaction-safe secret guard tests
"""Verify secret reporting never returns candidate credential values."""

from __future__ import annotations

import subprocess
from pathlib import Path

from tools.check_secrets import secret_errors


def test_secret_guard_redacts_value_and_reports_only_rule_location(tmp_path: Path) -> None:
    """Secret findings expose a rule and line, never the candidate value."""
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    value = "deliberately" + "-sensitive-value"
    (tmp_path / "settings.toml").write_text(f'password = "{value}"\n', encoding="utf-8")
    errors = secret_errors(tmp_path)
    assert errors == ["settings.toml:1: credential-assignment"]
    assert value not in "\n".join(errors)


def test_secret_provider_reference_is_not_treated_as_a_value(tmp_path: Path) -> None:
    """A provider expression remains valid configuration evidence."""
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    (tmp_path / "workflow.yml").write_text(
        "password: ${{ secrets.RELEASE_TOKEN }}\n", encoding="utf-8"
    )
    assert secret_errors(tmp_path) == []
