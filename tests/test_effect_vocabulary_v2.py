# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — effect vocabulary wire tests
"""Reproduce the reviewed digest vector and reject changes to the closed v2 class list."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.effect_vocabulary_v2 import (
    EFFECT_CLASSES_V2,
    EFFECT_VOCABULARY_DIGEST_V2,
    EFFECT_VOCABULARY_SCHEMA_V2,
    EffectVocabularyV2,
)
from rigor_foundry.models import canonical_digest

_VECTOR = "1f116c17442687a3cb00e6b574c8306da57ff2fc902039ea2890bb396de0d563"


def _wire(classes: list[str], **extra: object) -> bytes:
    """Encode one candidate through the same canonical JSON boundary."""
    return canonical_journal_json_v2(
        {"schema": EFFECT_VOCABULARY_SCHEMA_V2, "classes": classes, **extra}
    )


def test_exact_closed_vocabulary_reproduces_reviewed_vector() -> None:
    """The local canonical digest matches the independently computed design."""
    vocabulary = EffectVocabularyV2.build()
    assert vocabulary.vocabulary_digest == _VECTOR
    assert vocabulary.vocabulary_digest == EFFECT_VOCABULARY_DIGEST_V2
    assert vocabulary.body_bytes == _wire(list(EFFECT_CLASSES_V2))
    assert EffectVocabularyV2.from_bytes(vocabulary.body_bytes) == vocabulary
    assert all(vocabulary.contains(item) for item in EFFECT_CLASSES_V2)
    assert not vocabulary.contains("local-write")


@pytest.mark.parametrize(
    "classes",
    [
        list(EFFECT_CLASSES_V2[:-1]),
        [*EFFECT_CLASSES_V2, "other"],
        [*EFFECT_CLASSES_V2[:-1], EFFECT_CLASSES_V2[-2]],
        list(reversed(EFFECT_CLASSES_V2)),
    ],
)
def test_changed_v2_class_list_refuses_even_with_new_digest(classes: list[str]) -> None:
    """Selection cannot admit a changed v2 class list by merely repinning it.

    Parameters
    ----------
    classes : list[str]
        Candidate class list differing from the fixed vocabulary.
    """
    assert canonical_digest({"schema": EFFECT_VOCABULARY_SCHEMA_V2, "classes": classes}) != _VECTOR
    with pytest.raises(ValueError, match="v2 content differs"):
        EffectVocabularyV2.from_bytes(_wire(classes))


def test_unknown_key_schema_alias_and_noncanonical_wire_refuse() -> None:
    """A second spelling or JSON encoding does not create a valid vocabulary."""
    with pytest.raises(ValueError, match="fields differ"):
        EffectVocabularyV2.from_bytes(_wire(list(EFFECT_CLASSES_V2), alias="read"))
    with pytest.raises(ValueError, match="v2 content differs"):
        EffectVocabularyV2.from_bytes(
            canonical_journal_json_v2(
                {"schema": "rigor.effect-class-vocabulary.v3", "classes": list(EFFECT_CLASSES_V2)}
            )
        )
    with pytest.raises(ValueError, match="not canonical"):
        EffectVocabularyV2.from_bytes(EffectVocabularyV2.build().body_bytes + b"\n")
    with pytest.raises(ValueError, match="strict JSON"):
        EffectVocabularyV2.from_bytes(b'{"schema":"v2","schema":"other"}')
    with pytest.raises(ValueError, match="must be bytes"):
        EffectVocabularyV2.from_bytes(cast(bytes, "not bytes"))


def test_same_version_refuses_compiled_class_drift(tmp_path: Path) -> None:
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
    source = copied_package / "effect_vocabulary_v2.py"
    original = source.read_text()
    before = '    "shared-storage-write",\n)'
    after = '    "shared-storage-write",\n    "other",\n)'
    assert original.count(before) == 1
    source.write_text(original.replace(before, after))
    child = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from rigor_foundry import effect_vocabulary_v2 as module
assert Path(module.__file__).resolve() == Path(sys.argv[2]).resolve()
try:
    module.EffectVocabularyV2.build()
except ValueError as exc:
    assert str(exc) == "effect vocabulary v2 reviewed digest differs", str(exc)
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
    assert source_package.joinpath("effect_vocabulary_v2.py").read_text() == original
