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

_INTEGRATION_REVISION = "cd7a06d6c2e6c1258006ade83aff5e94d5fb1cb2"


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
    assert "Tracked policy path relative to repository-root." in action
    assert "absolute or relative to repository-root" not in action
    assert "--require-hashes" in action
    assert 'requirements/build.txt"' in action
    assert 'requirements/runtime.txt"' in action
    assert "--no-build-isolation --no-deps" in action
    assert 'python "$RF_ACTION_PATH/tools/check_consumer_outputs.py"' in action
    assert '"$environment_root/venv/bin/rigor" scan' in action
    assert '"$environment_root/venv/bin/rigor" gate' in action
    assert action_metadata_errors(action_path) == []
    assert "promote" not in action
    assert "--apply" not in action


def test_distributable_hook_requires_locked_runtime_and_defaults_to_passive_gate() -> None:
    """The published hook uses the caller's locked runtime and defaults to observe."""
    manifest = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")

    assert "- id: rigor-foundry" in manifest
    assert "entry: rigor" in manifest
    assert re.search(r"^    - observe$", manifest, re.MULTILINE)
    assert re.search(r"^    - staged$", manifest, re.MULTILINE)
    assert "pass_filenames: false" in manifest
    assert "always_run: true" in manifest
    assert "require_serial: true" in manifest
    assert "language: system" in manifest
    assert "additional_dependencies:" not in manifest
    guide = (ROOT / "docs/integrations.md").read_text(encoding="utf-8")
    assert "entry: .rigor/rigor-venv/bin/rigor" in guide
    assert "--require-hashes" in guide
    assert "--allow-native-audits" not in manifest
    assert "promote" not in manifest
    assert "--apply" not in manifest


def test_ci_installs_both_integrations_in_one_external_fixture() -> None:
    """Distribution CI runs the local Action and cloned hook outside the source tree."""
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    match = re.search(
        r"^  distribution:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        workflow,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    distribution = match.group("body")

    bind = distribution.index("Bind distribution Python before nested Actions")
    action = distribution.index("Run consumer action against external fixture")
    hook = distribution.index("Install and run distributable hook in external fixture")
    assert bind < action < hook
    assert "uses: ./" in distribution
    assert "repository-root: /tmp/rigor-adopter" in distribution
    assert "'docs/internal/' 'reports/' > /tmp/rigor-adopter/.gitignore" in distribution
    assert "report-path: /tmp/rigor-adopter/reports/action-report.json" in distribution
    assert "gate-report-path: /tmp/rigor-adopter/reports/action-gate.json" in distribution
    assert 'allow-native-audits: "false"' in distribution
    assert "RF_DISTRIBUTION_PYTHON=%s" in distribution
    assert '"$RF_DISTRIBUTION_PYTHON" -m pre_commit run' in distribution
    assert 'PATH="/tmp/rigor-wheel/bin:$PATH"' in distribution
    assert '"  - repo: file://${SOURCE_REPOSITORY}"' in distribution
    assert '"    rev: ${SOURCE_REVISION}"' in distribution
    for argument in ("gate", "--root", "--policy", "--mode", "--scope", "--output"):
        assert f"'          - {argument}'" in distribution
    assert '"$RF_DISTRIBUTION_PYTHON" -m pre_commit run --all-files' in distribution
    for output in (
        "reports/pre-commit-gate.json",
        "reports/action-report.json",
        "reports/action-gate.json",
    ):
        assert f"test -s {output}" in distribution
    assert "/tmp/rigor-adopter/reports/*.json" in distribution


def test_public_integration_examples_use_the_immutable_successor_revision() -> None:
    """Adopter examples never recommend a mutable action or hook revision."""
    guide = (ROOT / "docs/integrations.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    navigation = (ROOT / "mkdocs.yml").read_text(encoding="utf-8")

    assert f"anulum/RIGOR-FOUNDRY@{_INTEGRATION_REVISION}" in guide
    assert f"rev: {_INTEGRATION_REVISION}" in guide
    assert "anulum/RIGOR-FOUNDRY@main" not in guide
    assert "anulum/RIGOR-FOUNDRY@v" not in guide
    assert re.search(r"rev:\s+(?:main|v\d|HEAD)", guide) is None
    assert "consumer integration guide](docs/integrations.md)" in readme
    assert "Consumer integrations: integrations.md" in navigation
