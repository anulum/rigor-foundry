# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Public policy-check diagnostics
"""Exercise policy diagnostics through the real command and scoped files."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from rigor_foundry.cli import main
from rigor_foundry.cra_policy import CraPolicy
from rigor_foundry.policy_models import AuditPolicy

_POLICY = "rigor-foundry-policy.json"


def _write(root: Path, body: dict[str, object], name: str = _POLICY) -> Path:
    """Write a real bounded user-side policy document."""
    target = root / name
    target.write_text(json.dumps(body), encoding="utf-8")
    return target


def _pointers(output: str) -> list[str]:
    """Read the escaped JSON Pointer from each diagnostic line."""
    decoder = json.JSONDecoder()
    result = []
    for line in output.splitlines():
        pointer, end = decoder.raw_decode(line)
        assert isinstance(pointer, str)
        assert line[end:].strip()
        result.append(pointer)
    return result


def _required_cra() -> CraPolicy:
    """Create the current strict owner record for a required CRA fixture."""
    return CraPolicy.build(
        applicability="required",
        rationale="Observed product",
        product_key="sample",
        disclosure_policy_path="SECURITY.md",
        state_evidence_id="cra-state",
    )


def test_policy_check_accepts_valid_drafts_without_execution(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Lint current legacy and CRA schemas without creating files or running tools."""
    body = AuditPolicy().to_dict()
    body["native_audits"] = [
        {
            "name": "local verifier",
            "command": ["{python}", "-c", "from pathlib import Path; Path('unexpected').touch()"],
        }
    ]
    target = _write(tmp_path, body, "draft.json")
    original = target.read_bytes()
    monkeypatch.chdir(tmp_path)
    assert main(["policy-check", "--root", ".", "--policy", "draft.json"]) == 0
    outcome = capsys.readouterr()
    assert outcome.out == "policy check: PASS\n" and not outcome.err
    assert target.read_bytes() == original
    assert [item.name for item in tmp_path.iterdir()] == ["draft.json"]

    body = AuditPolicy(cra=_required_cra()).to_dict()
    body["ignored_inventory"] = [
        {"evidence_id": "cra-state", "path": ".rigor/cra", "capture": "directory-sha256"}
    ]
    assert AuditPolicy.from_dict(body).cra == _required_cra()
    _write(tmp_path, body)
    assert main(["policy-check", "--root", "."]) == 0
    assert capsys.readouterr().out == "policy check: PASS\n"


def test_policy_check_reports_independent_fields_and_indexed_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One malformed row cannot hide unrelated scalar or nested defects."""
    body = AuditPolicy().to_dict()
    body.update(
        source_line_threshold=False,
        test_line_threshold=0,
        source_roots=["src", "../escape", 5],
        test_roots=["C:/outside", "."],
        canonical_todo="../other/secret-note",
        module_size_registries=["."],
        enforcement_mode="zero",
        audit_domains=[
            {"name": "architecture-and-wiring", "applicability": "unknown-value", "rationale": ""},
            {
                "name": "architecture-and-wiring",
                "applicability": "required",
                "rationale": "duplicate",
            },
            4,
        ],
        native_audits=[
            {
                "name": "",
                "command": ["tool", 4],
                "scope": "wrong-mode",
                "timeout_seconds": 0,
                "required": 0,
                "working_directory": "../outside",
            },
            {
                "name": "profile",
                "profile": "trivy-repository-json-v1",
                "configuration_path": "C:/rules",
                "target_paths": ["../outside", 3],
                "timeout_seconds": 1,
                "scope": "both",
                "working_directory": "src",
                "required": True,
            },
        ],
        ignored_inventory=[
            {"evidence_id": "with spaces", "path": "/bad", "capture": "invalid-mode"},
            {"evidence_id": "note", "path": ".rigor/one", "capture": "presence"},
            {"evidence_id": "note", "path": ".rigor/one", "capture": "presence"},
        ],
    )
    body["unexpected/~key"] = "confidential-input"
    del body["review_ledger"]
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    result = capsys.readouterr()
    pointers = _pointers(result.out)
    assert not result.err
    assert len(pointers) == len(set(pointers))
    assert sorted(pointers) == pointers
    assert set(pointers) == {
        "/source_line_threshold",
        "/test_line_threshold",
        "/source_roots/1",
        "/source_roots/2",
        "/test_roots/0",
        "/canonical_todo",
        "/review_ledger",
        "/module_size_registries/0",
        "/maturity_policy_digest",
        "/audit_domains/0/applicability",
        "/audit_domains/0/rationale",
        "/audit_domains/1/name",
        "/audit_domains/2",
        "/native_audits/0/name",
        "/native_audits/0/command/1",
        "/native_audits/0/scope",
        "/native_audits/0/timeout_seconds",
        "/native_audits/0/required",
        "/native_audits/0/working_directory",
        "/native_audits/1/configuration_path",
        "/native_audits/1/target_paths/0",
        "/native_audits/1/target_paths/1",
        "/native_audits/1/working_directory",
        "/ignored_inventory/0/evidence_id",
        "/ignored_inventory/0/path",
        "/ignored_inventory/0/capture",
        "/ignored_inventory/2/evidence_id",
        "/ignored_inventory/2/path",
        "/unexpected~1~0key",
    }
    assert "positive integer" in result.out and "Bind a reviewed maturity" in result.out
    for value in ("secret-note", "confidential-input", "wrong-mode", "unknown-value"):
        assert value not in result.out


def test_policy_check_identifies_actual_cra_and_profile_contradictions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Point to the conflicting evidence and enforce the profile's full grammar."""
    body = AuditPolicy(cra=_required_cra()).to_dict()
    body["ignored_inventory"] = [
        {"evidence_id": "cra-state", "path": ".rigor/not-cra", "capture": "presence"}
    ]
    profile: dict[str, object] = {
        "name": "profile",
        "profile": "trivy-repository-json-v1",
        "configuration_path": "rules.yml",
        "target_paths": ["src", "tools"],
        "timeout_seconds": 1,
        "scope": "both",
        "working_directory": ".",
        "required": True,
    }
    body["native_audits"] = [profile]
    path = _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    result = capsys.readouterr()
    assert set(_pointers(result.out)) == {
        "/ignored_inventory/0/path",
        "/ignored_inventory/0/capture",
        "/native_audits/0/target_paths",
    }
    assert "Set this member to .rigor/cra" in result.out

    body["ignored_inventory"] = [
        {"evidence_id": "cra-state", "path": ".rigor/cra", "capture": "directory-sha256"}
    ]
    profile["timeout_seconds"] = 0
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    assert _pointers(capsys.readouterr().out) == [
        "/native_audits/0/target_paths",
        "/native_audits/0/timeout_seconds",
    ]

    profile["configuration_path"] = "../outside"
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    assert _pointers(capsys.readouterr().out) == [
        "/native_audits/0/configuration_path",
        "/native_audits/0/target_paths",
        "/native_audits/0/timeout_seconds",
    ]

    profile.update(configuration_path="rules.yml", target_paths=["src"], timeout_seconds=1)
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 0
    assert capsys.readouterr().out == "policy check: PASS\n"
    body["ignored_inventory"] = []
    body["native_audits"] = []
    path.write_text(json.dumps(body), encoding="utf-8")
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    assert _pointers(capsys.readouterr().out) == ["/cra/state_evidence_id"]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b'{"broken": }', "Invalid JSON at line 1, column 12."),
        (b'{"duplicate":1,"duplicate":2}', "Invalid policy document."),
        (b'{"value":NaN}', "Invalid policy document."),
        (b'{"value":"\xff"}', "Invalid policy document."),
        (b"[" * 33 + b"]" * 33, "Invalid policy document."),
        (b"[]", "Expected an object."),
    ],
)
def test_policy_check_reports_unusable_documents(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], payload: bytes, message: str
) -> None:
    """Report bounded syntax or shape failures without printing input contents."""
    (tmp_path / _POLICY).write_bytes(payload)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    result = capsys.readouterr()
    assert _pointers(result.out) == [""]
    assert message in result.out
    assert not result.err


@pytest.mark.parametrize(
    "location", ["../policy.json", "/policy.json", "C:/policy.json", "a\\b.json", ".", ""]
)
def test_policy_check_refuses_unscoped_arguments(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], location: str
) -> None:
    """Reject Windows and POSIX escapes before trying to read a policy."""
    assert main(["policy-check", "--root", str(tmp_path), "--policy", location]) == 2
    result = capsys.readouterr()
    assert not result.out and "relative to the declared root" in result.err


def test_policy_check_refuses_missing_nonregular_and_oversized_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Use the native bounded reader to refuse unsuitable inputs."""
    args = ["policy-check", "--root", str(tmp_path)]
    assert main(args) == 2
    target = tmp_path / _POLICY
    target.mkdir()
    assert main(args) == 2
    target.rmdir()
    with target.open("wb") as file:
        file.truncate(1024 * 1024 + 1)
    assert main(args) == 2
    assert main(["policy-check", "--root", str(target)]) == 2
    result = capsys.readouterr()
    assert not result.out
    assert result.err.count("cannot read a bounded regular policy") == 4


def test_policy_check_refuses_file_aliases(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Refuse real file aliases and symlink directories under a supplied root."""
    scoped = tmp_path / "scope"
    scoped.mkdir()
    outside = _write(tmp_path, AuditPolicy().to_dict())
    target = scoped / _POLICY
    os.link(outside, target)
    args = ["policy-check", "--root", str(scoped)]
    assert main(args) == 2
    assert "cannot read" in capsys.readouterr().err
    target.unlink()
    if os.name == "posix":
        target.symlink_to(outside)
        assert main(args) == 2
        assert "cannot read" in capsys.readouterr().err
        (scoped / "external").symlink_to(tmp_path, target_is_directory=True)
        assert main([*args, "--policy", "external/" + _POLICY]) == 2
        assert "cannot read" in capsys.readouterr().err


def test_policy_check_reports_unsupported_shapes_without_cascading(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Report unsupported versions and independent malformed container shapes."""
    body = AuditPolicy(cra=_required_cra()).to_dict()
    body.update(
        schema_version=["unsupported-version"],
        source_roots="src",
        audit_domains=4,
        ignored_inventory="unavailable",
        cra={},
        canonical_todo="note\u0001.md",
    )
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    result = capsys.readouterr()
    assert {
        "/schema_version",
        "/source_roots",
        "/audit_domains",
        "/ignored_inventory",
        "/cra",
        "/canonical_todo",
        "/cra/rationale",
    }.issubset(_pointers(result.out))
    assert "unsupported-version" not in result.out
    assert not result.err

    body = AuditPolicy(cra=_required_cra()).to_dict()
    body["cra"] = False
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    assert _pointers(capsys.readouterr().out) == ["/cra"]

    del body["cra"]
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    assert _pointers(capsys.readouterr().out) == ["/cra"]

    body = AuditPolicy().to_dict()
    del body["native_audits"]
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    assert _pointers(capsys.readouterr().out) == ["/native_audits"]


def test_policy_check_locates_array_items_and_ignored_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Differentiate invalid and repeated values within adaptor arrays."""
    body = AuditPolicy().to_dict()
    body["native_audits"] = [
        {
            "name": "generic",
            "command": ["tool", ""],
            "domains": ["application-security", "unknown", "application-security", True],
        },
        {
            "name": "profile",
            "profile": "semgrep-local-json-v1",
            "configuration_path": "rules.yml",
            "target_paths": ["src", "src"],
            "timeout_seconds": 1,
            "scope": "both",
            "working_directory": ".",
            "required": True,
        },
    ]
    body["ignored_inventory"] = [
        {"evidence_id": "z-state", "path": ".rigor/z", "capture": "presence"},
        {"evidence_id": "a-state", "path": ".rigor/a", "capture": "presence"},
    ]
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    result = capsys.readouterr()
    assert set(_pointers(result.out)) == {
        "/ignored_inventory",
        "/native_audits/0/command/1",
        "/native_audits/0/domains/1",
        "/native_audits/0/domains/2",
        "/native_audits/0/domains/3",
        "/native_audits/1/target_paths/1",
    }
    assert "Sort ignored declarations" in result.out
    assert "Duplicate adapter array item" in result.out


def test_policy_check_preserves_cra_version_scope_and_digest_failures(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Point to disallowed evidence, escaped paths, and a stale actual digest."""
    not_applicable = CraPolicy.build(
        applicability="not-applicable",
        rationale="Excluded fixture",
        product_key=None,
        disclosure_policy_path=None,
        state_evidence_id=None,
    )
    body = AuditPolicy(cra=not_applicable).to_dict()
    raw = not_applicable.to_dict()
    raw["product_key"] = "contradictory product"
    body["cra"] = raw
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    assert _pointers(capsys.readouterr().out) == ["/cra/product_key"]

    raw = _required_cra().to_dict()
    raw["disclosure_policy_path"] = "C:/outside"
    raw["state_evidence_id"] = 4
    body["cra"] = raw
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    assert set(_pointers(capsys.readouterr().out)) == {
        "/cra/disclosure_policy_path",
        "/cra/state_evidence_id",
    }

    raw = _required_cra().to_dict()
    raw["cra_policy_digest"] = "0" * 64
    body["cra"] = raw
    body["ignored_inventory"] = [
        {"evidence_id": "cra-state", "path": ".rigor/cra", "capture": "directory-sha256"}
    ]
    _write(tmp_path, body)
    assert main(["policy-check", "--root", str(tmp_path)]) == 1
    assert _pointers(capsys.readouterr().out) == ["/cra/cra_policy_digest"]
