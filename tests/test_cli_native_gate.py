# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native gate CLI boundary tests
"""Verify explicit native-execution consent through a real repository CLI."""

from __future__ import annotations

import json
from pathlib import Path

from repository_audit_git_repository import GitRepository

_POLICY = "rigor-foundry-policy.json"


def test_native_gate_requires_consent_and_never_serialises_command_output(
    tmp_path: Path,
) -> None:
    """CLI consent is explicit and native output remains digest-only evidence."""
    sentinel = "RIGOR_NATIVE_SENTINEL_891fcd6a"
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text("controls/native.py", f"print('{sentinel}')\n")
    repository.write_policy(
        native_audits=[
            {
                "name": "native-boundary",
                "command": ["{python}", "controls/native.py"],
                "timeout_seconds": 10,
                "scope": "full",
                "working_directory": ".",
                "required": True,
                "domains": ["application-security"],
            }
        ]
    )
    repository.commit()
    arguments = (
        "gate",
        "--root",
        ".",
        "--policy",
        _POLICY,
        "--mode",
        "observe",
    )
    refused = repository.run_audit(*arguments)
    assert refused.returncode == 2
    assert "explicit trusted consent" in refused.stderr
    allowed = repository.run_audit(*arguments, "--allow-native-audits")
    assert allowed.returncode == 0, allowed.stderr
    assert sentinel not in allowed.stdout
    assert sentinel not in allowed.stderr
    evidence = json.loads(allowed.stdout)["adapter_results"][0]
    assert "command" not in evidence
    assert "output" not in evidence
    assert len(evidence["command_digest"]) == 64
