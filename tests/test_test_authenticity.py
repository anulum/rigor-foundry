# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — test authenticity scanner tests
"""Exercise authenticity rules over real tracked source and test files."""

from __future__ import annotations

import json
from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy
from rigor_foundry.test_authenticity import scan_test_authenticity


def test_authenticity_scanner_reports_every_registered_signal(tmp_path: Path) -> None:
    """Tracked audit inputs expose doubles, exclusions, bypasses, and weak contracts."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/core.py",
        "def public() -> int:\n    return 1\n\ndef _hidden() -> int:\n    return 2\n",
    )
    lines = [
        "import unittest." + "mock",
        "import sys",
        "from pkg.core import _hidden",
        "",
        "# pragma:" + " no cover",
        "RIGOR_SENTINEL_5ab7d641 = 'private'  # no" + "qa: E501",
        "value: int = 'x'  # type:" + " ignore[assignment]",
        "sys." + "modules['pkg.optional'] = object()",
        "record = " + "fa" + "ke_record",
        "",
        "def test_without_contract() -> None:",
        "    _hidden()",
        "",
        "@pytest.mark." + "skip(reason='boundary')",
        "def test_skipped() -> None:",
        "    assert True",
    ]
    repository.write_text("tests/test_coverage.py", "\n".join(lines) + "\n")
    repository.write_text("tests/test_broken.py", "def test_broken(:\n")
    repository.write_text(
        "tests/test_public.py",
        "from pkg.core import public\n\ndef test_public() -> None:\n    assert public() == 1\n",
    )
    policy_path = repository.write_policy()
    repository.commit()

    policy = AuditPolicy.from_path(policy_path)
    candidates = scan_test_authenticity(load_git_inventory(repository.root), policy)
    rule_ids = {item.rule_id for item in candidates}
    assert {
        "TA001-test-double",
        "TA002-synthetic-fixture",
        "TA003-skip-or-xfail",
        "TA004-coverage-exclusion",
        "TA005-lint-suppression",
        "TA006-type-suppression",
        "TA007-module-injection",
        "TA008-coverage-bucket-name",
        "TA009-unparseable-python-test",
        "TA010-smoke-only-test",
        "TA011-private-production-surface",
    }.issubset(rule_ids)
    private = [item for item in candidates if item.rule_id == "TA011-private-production-surface"]
    assert any(item.symbol.startswith("_hidden;") for item in private)
    assert not any(item.path == "tests/test_public.py" for item in candidates)
    serialised = json.dumps([item.to_dict() for item in candidates], sort_keys=True)
    assert "RIGOR_SENTINEL_5ab7d641" not in serialised
    exempt = {"TA008-coverage-bucket-name", "TA009-unparseable-python-test"}
    assert all(
        "line_sha256=" in item.evidence for item in candidates if item.rule_id not in exempt
    )


def test_authenticity_scanner_accepts_real_observable_contract_forms(tmp_path: Path) -> None:
    """Assertions and explicit exception contracts do not become smoke-only candidates."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "def divide() -> None:\n    raise ValueError('x')\n")
    repository.write_text(
        "tests/test_core.py",
        "import pytest\nfrom pkg.core import divide\n\n"
        "def test_divide() -> None:\n    with pytest.raises(ValueError):\n        divide()\n",
    )
    policy_path = repository.write_policy()
    repository.commit()
    candidates = scan_test_authenticity(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )
    assert not any(item.rule_id == "TA010-smoke-only-test" for item in candidates)
