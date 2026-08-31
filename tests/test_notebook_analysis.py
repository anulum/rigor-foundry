# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Jupyter notebook analysis tests
"""Verify bounded notebook parsing and exact Git-blob candidate anchors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.git_inventory import MAX_TEXT_BYTES
from rigor_foundry.scanner import scan_repository


def _notebook(
    sources: list[str | list[str]],
    *,
    language: str | None = "python",
) -> str:
    """Return one deterministic nbformat-4 notebook fixture."""
    metadata: dict[str, object] = {}
    if language is not None:
        metadata = {
            "kernelspec": {"display_name": language, "language": language, "name": language},
            "language_info": {"name": language},
        }
    document = {
        "cells": [
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": source,
            }
            for source in sources
        ],
        "metadata": metadata,
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _repository(tmp_path: Path) -> GitRepository:
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy()
    return repository


def _raw_document(**overrides: object) -> str:
    """Return a minimal valid notebook with selected top-level replacements."""
    document = cast(dict[str, object], json.loads(_notebook([])))
    document.update(overrides)
    return json.dumps(document, separators=(",", ":"))


def test_python_cells_route_applicable_rules_without_execution_or_mutation(
    tmp_path: Path,
) -> None:
    """Universal and production AST rules retain exact notebook blob custody."""
    repository = _repository(tmp_path)
    marker = repository.root / "KERNEL_MUST_NOT_RUN"
    vulnerable = _notebook(
        [
            [
                "import pathlib\n",
                f"pathlib.Path({str(marker)!r}).write_text('executed')\n",
                "api_token = 'live-value-for-review'\n",
                "def risky(items=[]):\n",
                "    try:\n",
                "        print(api_token)\n",
                "        eval('1 + 1')\n",
                "    except:\n",
                "        return items\n",
            ]
        ]
    )
    safe = _notebook(
        [["def safe(items=None):\n", "    return [] if items is None else list(items)\n"]]
    )
    vulnerable_path = repository.write_text("src/pkg/vulnerable.ipynb", vulnerable)
    repository.write_text("src/pkg/safe.ipynb", safe)
    repository.commit()
    before_bytes = vulnerable_path.read_bytes()
    before_stat = vulnerable_path.stat()

    first = scan_repository(repository.root)
    second = scan_repository(repository.root)
    candidates = tuple(
        item for item in first.candidates if item.path == "src/pkg/vulnerable.ipynb"
    )

    assert {item.rule_id for item in candidates} == {
        "AS001-dynamic-code-execution",
        "DP001-hardcoded-credential",
        "OP001-print-in-library-code",
        "RL001-bare-except",
        "RL002-mutable-default-argument",
    }
    assert not [item for item in first.candidates if item.path == "src/pkg/safe.ipynb"]
    assert first.report_digest == second.report_digest
    assert tuple(item.candidate_id for item in first.candidates) == tuple(
        item.candidate_id for item in second.candidates
    )
    assert all("cell_index=0" in item.evidence for item in candidates)
    assert all("live-value-for-review" not in item.evidence for item in candidates)
    assert all(item.anchor.kind == "tracked-blob" for item in candidates)
    assert vulnerable_path.read_bytes() == before_bytes
    assert vulnerable_path.stat() == before_stat
    assert not marker.exists()


def test_string_and_fragmented_sources_map_to_physical_json_lines(tmp_path: Path) -> None:
    """Logical lines retain exact spans for both notebook source encodings."""
    repository = _repository(tmp_path)
    string_notebook = _notebook(["eval('first')\nexec('second')\n"])
    fragmented_notebook = _notebook([["eval(", "'fragmented'", ")\n"]])
    repository.write_text("notebooks/string.ipynb", string_notebook)
    repository.write_text("notebooks/fragments.ipynb", fragmented_notebook)
    repository.commit()

    report = scan_repository(repository.root)
    string_candidates = tuple(
        item
        for item in report.candidates
        if item.path == "notebooks/string.ipynb" and item.rule_id.startswith("AS001-")
    )
    fragmented = next(
        item
        for item in report.candidates
        if item.path == "notebooks/fragments.ipynb" and item.rule_id.startswith("AS001-")
    )

    assert len(string_candidates) == 2
    assert len({item.anchor.line_start for item in string_candidates}) == 1
    fragment_lines = fragmented_notebook.splitlines()
    expected_start = next(
        index for index, line in enumerate(fragment_lines, start=1) if '"eval("' in line
    )
    expected_end = next(
        index for index, line in enumerate(fragment_lines, start=1) if '")\\n"' in line
    )
    assert (fragmented.anchor.line_start, fragmented.anchor.line_end) == (
        expected_start,
        expected_end,
    )


def test_test_root_cells_receive_test_only_python_ast_rules(tmp_path: Path) -> None:
    """Scientific, performance, and authenticity rules preserve path applicability."""
    repository = _repository(tmp_path)
    repository.write_text("src/pkg/__init__.py", "def _private():\n    return 1\n")
    repository.write_text(
        "tests/analysis.ipynb",
        _notebook(
            [
                [
                    "import time\n",
                    "from pkg import _private\n",
                    "def test_float():\n",
                    "    assert 1.0 == 1.0\n",
                    "def test_clock():\n",
                    "    assert time.time() >= 0\n",
                    "def test_smoke():\n",
                    "    value = _private\n",
                ]
            ]
        ),
    )
    repository.commit()

    rules = {
        item.rule_id
        for item in scan_repository(repository.root).candidates
        if item.path == "tests/analysis.ipynb"
    }
    assert {
        "PR001-wall-clock-in-test",
        "SN001-exact-float-equality-in-test",
        "TA010-smoke-only-test",
        "TA011-private-production-surface",
    } <= rules
    assert "OP001-print-in-library-code" not in rules


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        pytest.param("", "unexpected-json-end", id="empty-json"),
        pytest.param("{\n", "invalid-json-object-key", id="missing-object-key"),
        pytest.param("@", "invalid-json", id="invalid-value"),
        pytest.param("NaN", "invalid-json", id="non-standard-number"),
        pytest.param('"unterminated', "invalid-json-string", id="invalid-string"),
        pytest.param('{"a" 1}', "invalid-json-delimiter", id="missing-colon"),
        pytest.param("{} trailing", "trailing-json-content", id="trailing-content"),
        pytest.param(
            '{"cells":[],"metadata":{"language_info":{"name":"python"}},'
            '"nbformat":4,"nbformat":4}',
            "duplicate-json-key",
            id="duplicate-key",
        ),
        pytest.param("[]", "invalid-notebook-root", id="array-root"),
        pytest.param(
            _raw_document(nbformat=3),
            "unsupported-notebook-schema",
            id="old-schema",
        ),
        pytest.param(
            _notebook([], language=None),
            "missing-notebook-language",
            id="missing-language",
        ),
        pytest.param(
            _raw_document(metadata=[]),
            "invalid-notebook-metadata",
            id="invalid-metadata",
        ),
        pytest.param(
            _raw_document(metadata={"language_info": []}),
            "invalid-notebook-language-metadata",
            id="invalid-language-metadata",
        ),
        pytest.param(
            _raw_document(metadata={"language_info": {}, "kernelspec": {}}),
            "missing-notebook-language",
            id="missing-language-name",
        ),
        pytest.param(
            _raw_document(metadata={"language_info": {"name": 3}}),
            "invalid-notebook-language",
            id="invalid-language-name",
        ),
        pytest.param(
            _raw_document(
                metadata={
                    "language_info": {"name": "python"},
                    "kernelspec": {"language": "julia"},
                }
            ),
            "conflicting-notebook-language",
            id="conflicting-language",
        ),
        pytest.param(
            _notebook([], language="julia"),
            "unsupported-notebook-language",
            id="unsupported-language",
        ),
        pytest.param(
            _raw_document(cells={}),
            "invalid-notebook-cells",
            id="invalid-cells",
        ),
        pytest.param(
            _notebook([""] * 1_025),
            "notebook-cell-limit",
            id="cell-limit",
        ),
        pytest.param(
            _raw_document(cells=[3]),
            "invalid-notebook-cell",
            id="invalid-cell",
        ),
        pytest.param(
            _raw_document(cells=[{"cell_type": 3, "source": []}]),
            "invalid-notebook-cell-type",
            id="invalid-cell-type",
        ),
        pytest.param(
            json.dumps(
                {
                    "cells": [{"cell_type": "code", "source": 42}],
                    "metadata": {"language_info": {"name": "python"}},
                    "nbformat": 4,
                }
            ),
            "invalid-code-cell-source",
            id="invalid-source-scalar",
        ),
        pytest.param(
            _raw_document(cells=[{"cell_type": "code", "source": [42]}]),
            "invalid-code-cell-source",
            id="invalid-source-member",
        ),
        pytest.param(
            "[" * 66 + "0" + "]" * 66,
            "json-depth-limit",
            id="depth-limit",
        ),
    ],
)
def test_malformed_or_unsupported_notebooks_fail_closed(
    tmp_path: Path,
    payload: str,
    reason: str,
) -> None:
    """Invalid notebook states produce one explicit governance candidate."""
    repository = _repository(tmp_path)
    repository.write_text("notebooks/invalid.ipynb", payload)
    repository.commit()

    candidates = tuple(
        item
        for item in scan_repository(repository.root).candidates
        if item.path == "notebooks/invalid.ipynb"
    )
    assert len(candidates) == 1
    assert candidates[0].rule_id == "GV005-unscanned-jupyter-notebook"
    assert candidates[0].symbol == reason
    assert f"reason={reason}" in candidates[0].evidence


def test_markdown_and_empty_code_cells_are_non_executable_noops(tmp_path: Path) -> None:
    """Non-code content and empty Python source do not fabricate candidates."""
    repository = _repository(tmp_path)
    document = cast(dict[str, object], json.loads(_notebook([])))
    document["cells"] = [
        {"cell_type": "markdown", "metadata": {}, "source": ["eval('not code')\n"]},
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [],
        },
    ]
    repository.write_text("notebooks/empty.ipynb", json.dumps(document, indent=2) + "\n")
    repository.commit()

    assert not [
        item
        for item in scan_repository(repository.root).candidates
        if item.path == "notebooks/empty.ipynb"
    ]


def test_unparseable_cell_does_not_hide_candidates_from_valid_cells(tmp_path: Path) -> None:
    """Partial Python syntax failure is explicit while other cells remain scanned."""
    repository = _repository(tmp_path)
    repository.write_text(
        "notebooks/mixed.ipynb",
        _notebook([["def broken(:\n"], ["\ud800"], ["eval('still scanned')\n"]]),
    )
    repository.commit()

    candidates = tuple(
        item
        for item in scan_repository(repository.root).candidates
        if item.path == "notebooks/mixed.ipynb"
    )
    assert {item.rule_id for item in candidates} == {
        "AS001-dynamic-code-execution",
        "GV005-unscanned-jupyter-notebook",
    }
    failures = tuple(item for item in candidates if item.rule_id.startswith("GV005-"))
    assert len(failures) == 2
    assert {item.symbol for item in failures} == {"unparseable-python-cell"}


@pytest.mark.parametrize(
    ("payload", "kind"),
    [
        (b" " * (MAX_TEXT_BYTES + 1), "oversize"),
        (b"\xff\xfe\x00", "binary"),
    ],
    ids=("oversize", "binary"),
)
def test_unreadable_notebook_content_uses_existing_scope_failure(
    tmp_path: Path,
    payload: bytes,
    kind: str,
) -> None:
    """Inventory-level notebook failures remain explicit without a parser fallback."""
    repository = _repository(tmp_path)
    repository.write_bytes("notebooks/unreadable.ipynb", payload)
    repository.commit()

    candidate = next(
        item
        for item in scan_repository(repository.root).candidates
        if item.path == "notebooks/unreadable.ipynb"
    )
    assert candidate.rule_id == "GV002-unscanned-tracked-code"
    assert candidate.symbol == kind
