# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — consumer Action and pre-commit distribution contracts
"""Verify adopter integrations stay pinned, explicit, and read-only."""

from __future__ import annotations

import re

from tools._repository import ROOT
from tools.check_action_pins import action_metadata_errors


def test_consumer_action_is_hash_locked_explicit_and_read_only() -> None:
    """The composite action installs exact source and never receives write authority."""
    action_path = ROOT / "action.yml"
    action = action_path.read_text(encoding="utf-8")

    for required_input in (
        "repository-root",
        "policy-path",
        "report-path",
        "gate-report-path",
    ):
        block = re.search(
            rf"^  {required_input}:\n(?P<body>(?:    .+\n)+)",
            action,
            re.MULTILINE,
        )
        assert block is not None
        assert "required: true" in block.group("body")
    assert "default: observe" in action
    assert "observe|ratchet|zero" in action
    assert "default: full" in action
    assert "staged|full" in action
    assert "maturity-path is required for ratchet and zero modes" in action
    assert "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1" in action
    assert 'python-version: "3.12.11"' in action
    assert "--require-hashes" in action
    assert 'requirements/build.txt"' in action
    assert 'requirements/runtime.txt"' in action
    assert "--no-build-isolation --no-deps" in action
    assert '"$environment_root/venv/bin/rigor" scan' in action
    assert '"$environment_root/venv/bin/rigor" gate' in action
    assert action_metadata_errors(action_path) == []
    assert "promote" not in action
    assert "--apply" not in action


def test_distributable_hook_pins_runtime_and_defaults_to_passive_staged_gate() -> None:
    """The published hook self-installs exact runtime versions and defaults to observe."""
    manifest = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")

    assert "- id: rigor-foundry" in manifest
    assert "entry: rigor" in manifest
    assert re.search(r"^    - observe$", manifest, re.MULTILINE)
    assert re.search(r"^    - staged$", manifest, re.MULTILINE)
    assert "pass_filenames: false" in manifest
    assert "always_run: true" in manifest
    assert "require_serial: true" in manifest
    dependencies = re.findall(r"^    - ([a-z0-9_-]+==[^\s]+)$", manifest, re.MULTILINE)
    assert dependencies == [
        "cryptography==49.0.0",
        "cffi==2.1.0",
        "pycparser==3.0",
    ]
    assert "--allow-native-audits" not in manifest
    assert "promote" not in manifest
    assert "--apply" not in manifest


def test_ci_installs_both_integrations_in_one_external_fixture() -> None:
    """Distribution CI runs the local Action and cloned hook outside the source tree."""
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "Run consumer action against external fixture" in workflow
    assert "uses: ./" in workflow
    assert "repository-root: /tmp/rigor-adopter" in workflow
    assert "report-path: /tmp/rigor-adopter/reports/action-report.json" in workflow
    assert "gate-report-path: /tmp/rigor-adopter/reports/action-gate.json" in workflow
    assert 'allow-native-audits: "false"' in workflow
    assert "Install and run distributable hook in external fixture" in workflow
    assert '"  - repo: file://${SOURCE_REPOSITORY}"' in workflow
    assert '"    rev: ${SOURCE_REVISION}"' in workflow
    for argument in ("gate", "--root", "--policy", "--mode", "--scope", "--output"):
        assert f"'          - {argument}'" in workflow
    assert "python -m pre_commit run --all-files" in workflow
    for output in (
        "reports/pre-commit-gate.json",
        "reports/action-report.json",
        "reports/action-gate.json",
    ):
        assert f"test -s {output}" in workflow
    assert "/tmp/rigor-adopter/reports/*.json" in workflow
