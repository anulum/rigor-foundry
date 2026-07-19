# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — scientific and numerical correctness scanner tests
"""Verify precise numerical-test candidates over real tracked repositories."""

from __future__ import annotations

import collections
from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy, Candidate
from rigor_foundry.scanner import scan_repository
from rigor_foundry.scientific import scan_scientific


def test_public_scan_finds_exact_float_and_unseeded_stochastic_tests(tmp_path: Path) -> None:
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/core.py",
        "# SPDX-License-" + "Identifier: Apache-2.0\nVALUE = 1\n",
    )
    repository.write_text(
        "tests/test_numeric.py",
        "import math\nimport random as rng\nimport numpy as np\n"
        "from random import uniform as draw\n\n"
        "def test_exact(value):\n"
        "    assert value == 0.3\n"
        "    assert value != -0.2\n\n"
        "def test_approx(value):\n"
        "    assert value == approx(0.3)\n"
        "    assert math.isclose(value, 0.3)\n"
        "    assert value == 3\n\n"
        "def test_random():\n"
        "    assert rng.random() >= 0.0\n"
        "    rng.seed(7)\n"
        "    assert rng.random() >= 0.0\n\n"
        "def test_numpy():\n"
        "    generator = np.random.default_rng()\n"
        "    assert generator is not None\n\n"
        "def test_imported():\n"
        "    assert draw(0, 1) >= 0\n\n"
        "def test_seeded():\n"
        "    rng.seed(7)\n"
        "    np.random.seed(seed=9)\n"
        "    assert rng.random() >= 0\n"
        "    assert np.random.normal() >= -100\n"
        "    assert rng.Random(3).random() >= 0\n"
        "    assert np.random.default_rng(4) is not None\n",
    )
    repository.write_policy(required_domains=frozenset({"scientific-numerical-correctness"}))
    repository.commit()

    report = scan_repository(repository.root)
    candidates = tuple(item for item in report.candidates if item.rule_id.startswith("SN"))
    assert collections.Counter(item.rule_id for item in candidates) == {
        "SN001-exact-float-equality-in-test": 1,
        "SN002-unseeded-stochastic-test": 3,
    }
    exact = candidates[0]
    assert exact.category == "scientific"
    assert exact.symbol == "test_exact"
    assert exact.confidence == "high"
    assert isinstance(exact.anchor, TrackedBlobAnchor)
    assert "occurrences=2" in exact.evidence
    assert Candidate.from_dict(exact.to_dict()) == exact
    assert not any(
        item.rule_id == "GV004-uncontrolled-required-domain"
        and item.symbol == "scientific-numerical-correctness"
        for item in report.candidates
    )


def test_scanner_requires_python_test_scope_and_parseable_text(tmp_path: Path) -> None:
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/module.py", "def helper(value):\n    return value == 0.5\n")
    repository.write_text("scripts/test_like.py", "def helper(value):\n    return value == 0.5\n")
    repository.write_text("tests/test_broken.py", "def test_value(:\n")
    repository.write_bytes("tests/test_binary.py", b"\xff\xfe")
    policy_path = repository.write_policy()
    repository.commit()
    assert (
        scan_scientific(load_git_inventory(repository.root), AuditPolicy.from_path(policy_path))
        == ()
    )


def test_import_aliases_seed_order_none_and_class_tests_are_bounded(tmp_path: Path) -> None:
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "tests/test_aliases.py",
        "import os\nimport numpy\nimport numpy.random\nimport numpy.random as npr\n"
        "from pathlib import Path\n"
        "from numpy import array, random as numpy_random\n"
        "from numpy.random import Generator, default_rng, seed as np_seed\n"
        "from numpy.random import normal as sample\n"
        "from random import Random, SystemRandom, random, seed\n\n"
        "class TestNumbers:\n"
        "    def test_late_seed(self):\n"
        "        assert random() >= 0\n"
        "        seed(5)\n\n"
        "    async def test_none_seed(self):\n"
        "        seed(None)\n"
        "        assert random() >= 0\n\n"
        "def test_numpy_alias():\n"
        "    assert npr.normal() >= 0\n\n"
        "def test_imported_numpy():\n"
        "    assert sample() >= 0\n\n"
        "def test_constructors():\n"
        "    assert Random() is not None\n"
        "    assert npr.default_rng(seed=None) is not None\n\n"
        "def test_safe_constructors():\n"
        "    assert Random(3) is not None\n"
        "    assert npr.default_rng(3) is not None\n"
        "    assert default_rng(4) is not None\n"
        "    np_seed(4)\n"
        "    assert sample() >= 0\n"
        "    numpy.random.seed(5)\n"
        "    assert numpy.random.normal() >= 0\n"
        "    numpy_random.seed(6)\n"
        "    assert numpy_random.normal() >= 0\n",
    )
    policy_path = repository.write_policy()
    repository.commit()
    candidates = scan_scientific(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [item.symbol for item in candidates] == [
        "test_late_seed",
        "test_none_seed",
        "test_numpy_alias",
        "test_imported_numpy",
        "test_constructors",
    ]
    assert all(item.rule_id == "SN002-unseeded-stochastic-test" for item in candidates)
