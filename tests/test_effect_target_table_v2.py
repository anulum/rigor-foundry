# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — effect target table tests
"""Exercise the exact v2 target table through its public parser and queries."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.effect_target_table_v2 import (
    EFFECT_TARGET_TABLE_DIGEST_V2,
    EffectTargetTableV2,
)
from rigor_foundry.effect_vocabulary_v2 import EFFECT_CLASSES_V2, EffectVocabularyV2


def test_exact_table_reproduces_reviewed_digest_and_covers_each_class() -> None:
    """The pinned body has the reviewed digest and no class is uncovered."""
    table = EffectTargetTableV2.build()
    assert EffectTargetTableV2.from_bytes(table.body_bytes) == table
    assert table.table_digest == EFFECT_TARGET_TABLE_DIGEST_V2
    body = json.loads(table.body_bytes)
    assert len(body["rows"]) == 15
    assert body["vocabulary_digest"] == EffectVocabularyV2.build().vocabulary_digest
    assert {row["effect_class"] for row in body["rows"]} == set(EFFECT_CLASSES_V2)
    assert table.allows("shared-storage-write", "filesystem-path", "path")
    assert table.allows("shared-storage-write", "remote-location", "remote")
    assert table.triples_for_class("shared-storage-write") == (
        ("filesystem-path", "path"),
        ("remote-location", "remote"),
    )
    assert not table.allows("package-or-model-upload", "service-endpoint", "remote")
    assert not table.allows("unknown", "filesystem-path", "path")
    assert table.triples_for_class("unknown") == ()


@pytest.mark.parametrize("change", ["extra", "missing", "reordered", "wrong_form"])
def test_changed_table_refuses(change: str) -> None:
    """A changed target mapping needs a new reviewed table version.

    Parameters
    ----------
    change : str
        Named mutation of the canonical target table.
    """
    body = json.loads(EffectTargetTableV2.build().body_bytes)
    if change == "extra":
        body["unexpected"] = True
    elif change == "missing":
        body["rows"].pop()
    elif change == "reordered":
        body["rows"][0], body["rows"][1] = body["rows"][1], body["rows"][0]
    else:
        body["rows"][9]["forms"] = ["remote"]
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="content differs"):
        EffectTargetTableV2.from_bytes(payload)


def test_noncanonical_and_nonbytes_table_refuse() -> None:
    """Only exact canonical bytes are accepted at the selection boundary."""
    payload = EffectTargetTableV2.build().body_bytes
    with pytest.raises(ValueError, match="not canonical"):
        EffectTargetTableV2.from_bytes(payload + b" ")
    with pytest.raises(ValueError, match="not strict JSON"):
        EffectTargetTableV2.from_bytes(b"{broken")
    with pytest.raises(ValueError, match="must be bytes"):
        EffectTargetTableV2.from_bytes(cast(bytes, "not bytes"))


def test_same_version_refuses_code_drift_from_reviewed_digest(tmp_path: Path) -> None:
    """Load actual changed source in a child and refuse its unchanged v2 pin.

    The unchanged compiled constants always match their reviewed digest. This
    real source-drift test reaches the guard in a separately loaded copy; it
    does not cover that line in unchanged canonical source or prove protected
    host admission. Coverage keeps the altered copies separate.

    Parameters
    ----------
        tmp_path : Path
            Isolated directory for loading changed package source in a child.
    """
    source_package = Path(__file__).resolve().parents[1] / "src" / "rigor_foundry"
    copied_package = tmp_path / "rigor_foundry"
    shutil.copytree(source_package, copied_package, ignore=shutil.ignore_patterns("__pycache__"))
    source = copied_package / "effect_target_table_v2.py"
    original = source.read_text()
    before = '    ("read", "filesystem-path", ("path",)),'
    after = '    ("read", "filesystem-path", ("path",)),\n    ("read", "repository", ("path",)),'
    assert original.count(before) == 1
    source.write_text(original.replace(before, after))
    child = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from rigor_foundry import effect_target_table_v2 as module
assert Path(module.__file__).resolve() == Path(sys.argv[2]).resolve()
try:
    module.EffectTargetTableV2.build()
except ValueError as exc:
    assert str(exc) == "effect target table v2 reviewed digest differs", str(exc)
else:
    raise AssertionError("changed source was accepted under the reviewed v2 pin")
print("changed source refused")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", child, str(tmp_path), str(source)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "changed source refused"
    assert source_package.joinpath("effect_target_table_v2.py").read_text() == original
