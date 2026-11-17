# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Editor native artifact workflow contract
"""Require native construction, every supported host and the complete source coverage union."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools._repository import ROOT

EDITOR_NATIVE_BUILD_JOB = {
    "runs-on": "windows-2025",
    "timeout-minutes": 20,
    "env": {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.autocrlf",
        "GIT_CONFIG_VALUE_0": "false",
    },
    "steps": [
        {
            "uses": "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            "with": {"persist-credentials": False},
        },
        {
            "uses": "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1",
            "with": {
                "node-version": "22.23.3",
                "cache": "npm",
                "cache-dependency-path": "editors/vscode/package-lock.json",
            },
        },
        {
            "name": "Install locked native compiler sources",
            "run": "npm ci --ignore-scripts --engine-strict --prefix editors/vscode",
        },
        {
            "name": "Audit locked extension dependencies",
            "run": "npm audit --prefix editors/vscode",
        },
        {
            "name": "Build and bind fresh Windows native artifact",
            "env": {
                "TEMP": "${{ runner.temp }}",
                "TMP": "${{ runner.temp }}",
                "NODE_V8_COVERAGE": "${{ runner.temp }}/rigor-native-profile/v8",
            },
            "run": "node editors/vscode/scripts/native-artifact.mjs build "
            '"$env:RUNNER_TEMP/rigor-editor-native" --github',
        },
        {
            "name": "Record actual native producer source and coverage identity",
            "env": {"NODE_V8_COVERAGE": "${{ runner.temp }}/rigor-native-profile/v8"},
            "run": 'node --input-type=module -e "import {recordNativeBuild} from '
            "'./editors/vscode/scripts/editor-profile-inputs.mjs'; await "
            'recordNativeBuild(process.argv[1], process.argv[2], process.argv[3]);" '
            '"$env:GITHUB_WORKSPACE/editors/vscode" '
            '"$env:RUNNER_TEMP/rigor-native-profile" '
            '"$env:RUNNER_TEMP/rigor-editor-native"',
        },
        {
            "name": "Seal closed native producer files",
            "run": 'node --input-type=module -e "import {sealProfileFiles} from '
            "'./editors/vscode/scripts/editor-profile-inputs.mjs'; await "
            'sealProfileFiles(process.argv[1]);" "$env:RUNNER_TEMP/rigor-native-profile"',
            "if": "${{ always() }}",
        },
        {
            "uses": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
            "with": {
                "name": "vscode-native-${{ github.sha }}-${{ github.run_id }}-${{ "
                "github.run_attempt }}",
                "path": "${{ runner.temp }}/rigor-editor-native/",
                "if-no-files-found": "error",
                "retention-days": 14,
            },
        },
        {
            "uses": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
            "with": {
                "name": "vscode-profile-native-build-${{ github.sha }}-${{ github.run_id "
                "}}-${{ github.run_attempt }}",
                "path": "${{ runner.temp }}/rigor-native-profile/",
                "include-hidden-files": True,
                "if-no-files-found": "error",
                "retention-days": 14,
            },
            "if": "${{ always() }}",
        },
        {
            "name": "Retain original native build diagnostics",
            "if": "${{ always() }}",
            "uses": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
            "with": {
                "name": "vscode-native-diagnostics-${{ github.sha }}-${{ github.run_id "
                "}}-${{ github.run_attempt }}",
                "path": "${{ runner.temp }}/rigor-native-*/*.json\n"
                "${{ runner.temp }}/rigor-native-*/*.stdout\n"
                "${{ runner.temp }}/rigor-native-*/*.stderr\n"
                "${{ runner.temp }}/rigor-native-*/*.cmd\n",
                "if-no-files-found": "error",
                "retention-days": 14,
            },
        },
    ],
}

EDITOR_NATIVE_DOWNLOAD = {
    "uses": "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
    "with": {
        "name": "vscode-native-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
        "path": "${{ runner.temp }}/rigor-editor-native",
    },
}

EDITOR_NATIVE_ADMISSION = {
    "name": "Admit exact source and run native artifact",
    "shell": "bash",
    "run": "node editors/vscode/scripts/native-artifact.mjs verify "
    '"$RUNNER_TEMP/rigor-editor-native" --github',
}

EDITOR_NODE_SETUP = {
    "uses": "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1",
    "with": {
        "node-version": "22.23.3",
        "cache": "npm",
        "cache-dependency-path": "editors/vscode/package-lock.json",
    },
}

EDITOR_HOST_INSTALL = {
    "uses": "./.github/actions/install-editor-host",
    "with": {
        "archive-url": "${{ matrix.archiveUrl }}",
        "archive-sha256": "${{ matrix.archiveSha256 }}",
    },
}

EDITOR_HOST_EXECUTION = {
    "name": "Execute complete real supported host profile",
    "shell": "bash",
    "env": {
        "RF_HOST_VERSION": "${{ matrix.version }}",
        "NODE_V8_COVERAGE": "${{ runner.temp }}/rigor-editor-profile/v8",
    },
    "run": "set -euo pipefail\n"
    'if [ "$RUNNER_OS" = Linux ]; then\n'
    '  xvfb-run -a node editors/vscode/scripts/run-editor-profile.mjs "$RF_HOST_VERSION" '
    '"$RUNNER_TEMP/rigor-editor-profile"\n'
    "else\n"
    '  node editors/vscode/scripts/run-editor-profile.mjs "$RF_HOST_VERSION" '
    '"$RUNNER_TEMP/rigor-editor-profile"\n'
    "fi\n",
}

EDITOR_UNION_ADMISSION = {
    "name": "Admit every original supported editor producer",
    "env": {"NODE_V8_COVERAGE": "${{ runner.temp }}/editor-consumer-v8"},
    "run": 'node editors/vscode/scripts/combine-editor-profiles.mjs "$RUNNER_TEMP/editor-producers" '
    '"$RUNNER_TEMP/editor-union"',
}

EDITOR_UNION_GATE = {
    "name": "Require complete whole-owner editor coverage",
    "shell": "bash",
    "run": "set -euo pipefail\n"
    'node --input-type=module -e "import {sealProfileFiles,admitProfileFiles} from '
    "'./scripts/editor-profile-inputs.mjs'; await sealProfileFiles(process.argv[1]); await "
    'admitProfileFiles(process.argv[1]);" "$RUNNER_TEMP/editor-consumer-v8"\n'
    'cp "$RUNNER_TEMP/editor-consumer-v8"/coverage-*.json "$RUNNER_TEMP/editor-union/v8/"\n'
    "node node_modules/c8/bin/c8.js report --config c8.config.json --temp-directory "
    '"$RUNNER_TEMP/editor-union/v8" --reports-dir "$RUNNER_TEMP/editor-union/report"\n'
    'node --input-type=module -e "import {editorInputs} from '
    "'./scripts/editor-profile-inputs.mjs'; import {requireEditorOwnerCoverage} from "
    "'./scripts/editor-coverage.mjs'; await requireEditorOwnerCoverage(process.argv[1], "
    'process.argv[2], (await editorInputs(process.argv[1])).owners);" '
    '"$GITHUB_WORKSPACE/editors/vscode" '
    '"$RUNNER_TEMP/editor-union/report/coverage-summary.json"\n',
    "working-directory": "editors/vscode",
}

EDITOR_PACKAGING = {
    "name": "Package both qualified platform extensions",
    "run": "npm run package --prefix editors/vscode\n"
    "npm run package:windows --prefix editors/vscode\n",
}


def check_editor_jobs(jobs: dict[str, Any], root: Path = ROOT) -> None:
    """Require all declared native/host producers before the strict complete-source gate.

    Parameters
    ----------
    jobs : dict[str, Any]
        Actual parsed same-revision editor workflow jobs.
    root : Path
        Actual source checkout with the versioned host definitions.

    Raises
    ------
    ValueError
        Required roles, supported profile matrix, admission order or final gates differ.
    """
    if jobs.get("vscode-native") != EDITOR_NATIVE_BUILD_JOB:
        raise ValueError("invalid editor native build producer")
    definitions = json.loads((root / "editors/vscode/native/editor-hosts.json").read_text())
    if (
        not isinstance(definitions, dict)
        or type(definitions.get("schema")) is not int
        or definitions.get("schema") != 1
        or definitions.get("architecture") != "x64"
    ):
        raise ValueError("invalid editor host definitions")
    profiles = definitions.get("profiles")
    if (
        not isinstance(profiles, list)
        or len(profiles) != 4
        or not all(isinstance(p, dict) for p in profiles)
    ):
        raise ValueError("all four supported OS/version profiles are required")
    if any(
        not isinstance(p.get("version"), str) or not isinstance(p.get("platform"), str)
        for p in profiles
    ):
        raise ValueError("invalid editor profile identity")
    versions = {p.get("version") for p in profiles}
    if len({p.get("id") for p in profiles}) != 4:
        raise ValueError("duplicate editor artifact profile identity")
    if len(versions) != 2 or {(p.get("platform"), p.get("version")) for p in profiles} != {
        (os, version) for os in ("linux", "win32") for version in versions
    }:
        raise ValueError("supported editor platform/version matrix is incomplete")
    execution = jobs.get("vscode-host")
    if not isinstance(execution, dict) or execution.get("needs") != ["vscode-native"]:
        raise ValueError("editor tests require native build success")
    if execution.get("strategy") != {"fail-fast": False, "matrix": {"include": profiles}}:
        raise ValueError("supported editor host matrix differs")
    consumer = jobs.get("vscode")
    if not isinstance(consumer, dict) or consumer.get("needs") != ["vscode-native", "vscode-host"]:
        raise ValueError("complete editor union requires every producer")
    for job, required in [
        (
            execution,
            [
                EDITOR_NODE_SETUP,
                EDITOR_NATIVE_DOWNLOAD,
                EDITOR_NATIVE_ADMISSION,
                EDITOR_HOST_INSTALL,
                EDITOR_HOST_EXECUTION,
            ],
        ),
        (
            consumer,
            [
                EDITOR_NODE_SETUP,
                EDITOR_NATIVE_DOWNLOAD,
                EDITOR_NATIVE_ADMISSION,
                EDITOR_UNION_ADMISSION,
                EDITOR_UNION_GATE,
                EDITOR_PACKAGING,
            ],
        ),
    ]:
        if set(job).intersection({"if", "continue-on-error"}):
            raise ValueError("editor acceptance jobs cannot be optional")
        steps = job.get("steps")
        if not isinstance(steps, list) or not all(isinstance(step, dict) for step in steps):
            raise ValueError("invalid editor execution steps")
        if any(steps.count(step) != 1 for step in required):
            raise ValueError("editor admission, execution or gate is absent, repeated or changed")
        indices = [steps.index(step) for step in required]
        if indices != sorted(indices):
            raise ValueError("editor native/host/coverage/package order differs")
