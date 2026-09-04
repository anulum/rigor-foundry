# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry cutover CLI tests
"""Exercise explicit plan validation and application through the operator CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_project_registry_cutover import REGISTRY_PATH, filesystem
from test_project_registry_models import registry

from rigor_foundry.project_registry_views import build_registry_consumer_outputs
from tools.project_registry_cutover import main


def arguments(tmp_path: Path) -> tuple[list[str], Path]:
    """Write a complete initial candidate bundle and return CLI arguments."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    candidate_path = bundle / "registry.json"
    candidate_path.write_bytes(candidate.to_bytes())
    argv = [
        str(root),
        REGISTRY_PATH,
        str(candidate_path),
        str(transactions),
        "--expected-current",
        "ABSENT",
    ]
    for index, output in enumerate(build_registry_consumer_outputs(candidate, {})):
        path = bundle / f"consumer-{index}.json"
        path.write_bytes(output.to_bytes())
        argv.extend(["--consumer-output", str(path)])
        argv.extend(["--expected-consumer", f"{output.consumer_id}=ABSENT"])
    return argv, root


def test_cutover_cli_validates_complete_plan_without_mutation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Default invocation validates but leaves the monorepo unchanged."""
    argv, root = arguments(tmp_path)
    assert main(argv) == 0
    assert capsys.readouterr().out == "project-registry-cutover: VALID\n"
    assert not (root / REGISTRY_PATH).exists()


def test_cutover_cli_applies_only_with_explicit_flag(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The explicit apply flag commits the complete candidate bundle."""
    argv, root = arguments(tmp_path)
    assert main([*argv, "--apply"]) == 0
    assert capsys.readouterr().out == "project-registry-cutover: COMMITTED\n"
    assert (root / REGISTRY_PATH).is_file()


def test_cutover_cli_rejects_incomplete_and_duplicate_inputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Missing and repeated consumer identity contracts emit one failure line."""
    argv, _ = arguments(tmp_path)
    truncated = argv[:-2]
    assert main(truncated) == 1
    assert capsys.readouterr().out == "project-registry-cutover: FAIL\n"

    output_index = argv.index("--consumer-output")
    repeated = [*argv, "--consumer-output", argv[output_index + 1]]
    assert main(repeated) == 1
    assert capsys.readouterr().out == "project-registry-cutover: FAIL\n"

    malformed = [*argv, "--expected-consumer", "not-a-pair"]
    assert main(malformed) == 1
    assert capsys.readouterr().out == "project-registry-cutover: FAIL\n"
