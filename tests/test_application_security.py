# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — application-security scanner tests
"""Verify bounded, precise application-security candidates over tracked Python."""

from __future__ import annotations

import ast
import collections
from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.application_security import (
    _call_target,
    _is_unbounded_yaml,
    _line_evidence,
    scan_application_security,
)
from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy, Candidate

_VULNERABLE = (
    "import subprocess, os, pickle, yaml, hashlib, tempfile\n\n"
    "def handle(cmd, data, stream):\n"
    "    eval(cmd)\n"
    "    exec(cmd)\n"
    "    subprocess.run(cmd, shell=True)\n"
    "    os.system(cmd)\n"
    "    os.popen(cmd)\n"
    "    pickle.loads(data)\n"
    "    pickle.load(stream)\n"
    "    yaml.load(stream)\n"
    "    hashlib.md5(data)\n"
    "    hashlib.sha1(data)\n"
    "    tempfile.mktemp()\n"
)

_SAFE = (
    "import subprocess, yaml, hashlib, tempfile, json\n\n"
    "def handle(cmd, data, stream):\n"
    "    subprocess.run([cmd], shell=False)\n"
    "    yaml.safe_load(stream)\n"
    "    yaml.load(stream, Loader=yaml.SafeLoader)\n"
    "    hashlib.sha256(data)\n"
    "    tempfile.mkstemp()\n"
    "    json.loads(data)\n"
)


def _scan(repository: GitRepository, policy_path: Path) -> tuple[Candidate, ...]:
    return scan_application_security(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )


def test_scanner_flags_each_vulnerable_pattern_and_ignores_safe(tmp_path: Path) -> None:
    """Every declared insecure surface is a candidate; hardened equivalents are not."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/vuln.py", _VULNERABLE)
    repository.write_text("src/pkg/safe.py", _SAFE)
    policy_path = repository.write_policy()
    repository.commit()

    candidates = _scan(repository, policy_path)
    by_file = collections.Counter(
        item.rule_id for item in candidates if item.anchor.path == "src/pkg/vuln.py"
    )
    assert by_file == {
        "AS001-dynamic-code-execution": 2,
        "AS002-shell-command-execution": 3,
        "AS003-unsafe-deserialization": 3,
        "AS004-weak-hash-primitive": 2,
        "AS005-insecure-temporary-file": 1,
    }
    assert not [item for item in candidates if item.anchor.path == "src/pkg/safe.py"]
    sample = next(item for item in candidates if item.rule_id == "AS005-insecure-temporary-file")
    assert sample.category == "application-security"
    assert sample.confidence == "high"
    assert sample.symbol == "tempfile.mktemp"
    assert isinstance(sample.anchor, TrackedBlobAnchor)
    assert sample.evidence.startswith("file_sha256=")
    weak = next(item for item in candidates if item.rule_id == "AS004-weak-hash-primitive")
    assert weak.confidence == "low"


def test_scanner_skips_non_python_unparseable_and_binary(tmp_path: Path) -> None:
    """Non-Python, syntactically broken, and undecodable files yield no candidates."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("docs/notes.txt", "eval(danger)\n")
    repository.write_text("src/pkg/broken.py", "def f(:\n")
    repository.write_bytes("src/pkg/binary.py", b"\xff\xfe eval(x)\x00")
    policy_path = repository.write_policy()
    repository.commit()

    assert _scan(repository, policy_path) == ()


def _call(source: str) -> ast.Call:
    """Return the single call expression parsed from ``source``."""
    statement = ast.parse(source).body[0]
    assert isinstance(statement, ast.Expr)
    assert isinstance(statement.value, ast.Call)
    return statement.value


def test_call_target_and_unbounded_yaml_and_evidence_edges(tmp_path: Path) -> None:
    """The helper branches for exotic call shapes and evidence bounds hold."""
    assert _call_target(_call("eval(x)").func) == "eval"
    assert _call_target(_call("os.system(x)").func) == "os.system"
    # A call whose target is neither a Name nor an Attribute resolves to a placeholder.
    assert _call_target(_call("registry[key]()").func) == "<expr>"
    assert _is_unbounded_yaml(_call("yaml.load(s)")) is True
    assert _is_unbounded_yaml(_call("yaml.load(s, Loader=L)")) is False
    assert _is_unbounded_yaml(_call("yaml.load(s, L)")) is False

    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    item = next(
        item for item in load_git_inventory(repository.root).files if item.text is not None
    )
    # A line beyond the file still yields content-addressed evidence for an empty line.
    assert _line_evidence(item, 9999).startswith("file_sha256=")
