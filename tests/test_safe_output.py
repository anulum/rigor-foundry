# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exclusive output writer tests
"""Prove explicit output creation never overwrites or follows adopter paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from rigor_foundry.safe_output import write_new_output


def test_write_new_output_creates_one_new_file_and_rejects_overwrite(tmp_path: Path) -> None:
    """The public writer creates once and preserves the first result."""
    output = tmp_path / "report.json"

    write_new_output(output, "first\n")
    with pytest.raises(ValueError, match="already exists"):
        write_new_output(output, "second\n")

    assert output.read_text(encoding="utf-8") == "first\n"


def test_write_new_output_rejects_late_symlink_without_touching_victim(tmp_path: Path) -> None:
    """A symlink introduced after any earlier validation cannot redirect the write."""
    parent = tmp_path / "reports"
    parent.mkdir()
    victim = tmp_path / "victim.json"
    victim.write_text("preserve\n", encoding="utf-8")
    output = parent / "report.json"
    output.symlink_to(victim)

    with pytest.raises(ValueError, match="already exists"):
        write_new_output(output, "replacement\n")

    assert output.is_symlink()
    assert victim.read_text(encoding="utf-8") == "preserve\n"


def test_write_new_output_rejects_symlinked_parent(tmp_path: Path) -> None:
    """Every parent component is bound without following directory links."""
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="no-follow directory"):
        write_new_output(linked_parent / "report.json", "unsafe\n")

    assert not (real_parent / "report.json").exists()
