# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — discovery progress replay tests
"""Exercise immutable replay and refusal through real files and the public API."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.discovery_progress import ProgressLimits, replay_discovery_progress


def write_json(root: Path, name: str, value: object) -> None:
    """Write one synthetic input using a stable test serializer."""
    (root / name).write_text(json.dumps(value), encoding="utf-8")


def packet(root: Path) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Create a two-candidate base and independently specified successor."""
    base: dict[str, object] = {
        "records": [
            {"candidate_id": "rule-a", "source_receipt": None, "text": "retain"},
            {"candidate_id": "rule-b", "source_receipt": None},
        ],
        "receipts": {},
    }
    body = {"promotable": False, "assertion_class": "declared-snapshot-integrity-only"}
    receipt = {**body, "receipt_digest": canonical_digest(body)}
    descriptor = {"receipt_digest": receipt["receipt_digest"]}
    expected: dict[str, object] = {
        "records": [
            {"candidate_id": "rule-a", "source_receipt": "proof", "text": "retain"},
            {"candidate_id": "rule-b", "source_receipt": None},
        ],
        "receipts": {"proof": descriptor},
    }
    transaction: dict[str, object] = {
        "schema_version": "discovery-progress-change.v1",
        "parent_sha256": canonical_digest(base),
        "result_sha256": canonical_digest(expected),
        "additions": [{"key": "proof", "descriptor": descriptor, "capture": "receipt.json"}],
        "changes": [{"candidate_id": "rule-a", "before": None, "after": "proof"}],
    }
    for name, value in [
        ("base.json", base),
        ("change.json", transaction),
        ("receipt.json", receipt),
    ]:
        write_json(root, name, value)
    return base, transaction, expected


def replay(
    root: Path, base: dict[str, object], names: tuple[str, ...] = ("change.json",)
) -> dict[str, object]:
    """Call the public replay with explicit small fixture budgets."""
    return replay_discovery_progress(
        root,
        "base.json",
        names,
        base_sha256=canonical_digest(base),
        limits=ProgressLimits(10000, 5000, 2, 2, 2),
    )


def test_replay_preserves_inputs_and_opaque_metadata(tmp_path: Path) -> None:
    """Reconstruct the full expected state twice without modifying any input."""
    base, _, expected = packet(tmp_path)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    result = replay(tmp_path, base)
    assert result == replay(tmp_path, base)
    assert result == {
        "state": expected,
        "state_sha256": canonical_digest(expected),
        "total": 2,
        "bound": 1,
        "pending": 1,
        "promotable": False,
    }
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert replay(tmp_path, base, ())["pending"] == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "active"),
        ("parent_sha256", "0" * 64),
        ("result_sha256", "0" * 64),
        ("changes", []),
        ("additions", {}),
        ("additions", [{}, {}, {}]),
        ("extra", True),
        ("changes", [{"candidate_id": "missing", "before": None, "after": "proof"}]),
        ("changes", [{"candidate_id": "rule-a", "before": "wrong", "after": "proof"}]),
        ("changes", [{"candidate_id": "rule-a", "before": None, "after": "missing"}]),
        ("changes", [{"candidate_id": "rule-a", "before": None, "after": "proof"}] * 2),
    ],
)
def test_invalid_transaction_refuses(tmp_path: Path, field: str, value: object) -> None:
    """Refuse malformed, reordered, duplicate, unbound and miscounted changes."""
    base, transaction, _ = packet(tmp_path)
    transaction[field] = value
    write_json(tmp_path, "change.json", transaction)
    with pytest.raises(ValueError):
        replay(tmp_path, base)


@pytest.mark.parametrize("case", ["digest", "promotion", "class", "descriptor"])
def test_receipt_integrity_and_no_promotion(tmp_path: Path, case: str) -> None:
    """Reject tampered or authority-promoting receipts even when JSON parses."""
    base, transaction, _ = packet(tmp_path)
    receipt = json.loads((tmp_path / "receipt.json").read_text())
    if case == "descriptor":
        transaction["additions"] = [
            {"key": "proof", "descriptor": {"receipt_digest": "0" * 64}, "capture": "receipt.json"}
        ]
        write_json(tmp_path, "change.json", transaction)
    else:
        receipt[
            {"digest": "receipt_digest", "promotion": "promotable", "class": "assertion_class"}[
                case
            ]
        ] = True
        if case != "digest":
            receipt["receipt_digest"] = canonical_digest(
                {k: v for k, v in receipt.items() if k != "receipt_digest"}
            )
            transaction["additions"] = [
                {
                    "key": "proof",
                    "descriptor": {"receipt_digest": receipt["receipt_digest"]},
                    "capture": "receipt.json",
                }
            ]
            write_json(tmp_path, "change.json", transaction)
        write_json(tmp_path, "receipt.json", receipt)
    with pytest.raises(ValueError):
        replay(tmp_path, base)


@pytest.mark.parametrize("case", ["duplicate", "missing", "unknown"])
def test_invalid_base_refuses(tmp_path: Path, case: str) -> None:
    """Reject duplicate identities and missing or dangling receipt bindings."""
    base, _, _ = packet(tmp_path)
    rows = [{"candidate_id": "rule-a", "source_receipt": None}]
    if case == "duplicate":
        rows.append(deepcopy(rows[0]))
    elif case == "missing":
        rows[0].pop("source_receipt")
    else:
        rows[0]["source_receipt"] = "missing"
    base["records"] = rows
    write_json(tmp_path, "base.json", base)
    with pytest.raises(ValueError):
        replay(tmp_path, base)


@pytest.mark.parametrize("case", ["symlink", "hardlink", "truncated", "duplicate-json", "pin"])
def test_file_and_base_pin_refusal(tmp_path: Path, case: str) -> None:
    """Refuse aliasing, damaged JSON and a changed base without writing inputs."""
    base, _, _ = packet(tmp_path)
    target = tmp_path / "base.json"
    if case == "symlink":
        target.rename(tmp_path / "real.json")
        target.symlink_to(tmp_path / "real.json")
    elif case == "hardlink":
        (tmp_path / "alias.json").hardlink_to(target)
    elif case == "truncated":
        target.write_bytes(b'{"records":')
    elif case == "duplicate-json":
        target.write_bytes(b'{"records": [], "records": [], "receipts": {}}')
    else:
        write_json(
            tmp_path, "base.json", {**base, "receipts": {"other": {"receipt_digest": "0" * 64}}}
        )
    with pytest.raises((ValueError, OSError, RuntimeError)):
        replay(tmp_path, base)


@pytest.mark.parametrize("value", [True, 0, -1, 2**31])
def test_invalid_limits(value: int) -> None:
    """Reject boolean, nonpositive and oversized limits before file access."""
    with pytest.raises(ValueError):
        ProgressLimits(value, 1, 1, 1, 1)


@pytest.mark.parametrize(
    "case", ["relative", "traversal", "duplicate", "long-chain", "file-budget", "total-budget"]
)
def test_path_chain_and_budget_boundaries(tmp_path: Path, case: str) -> None:
    """Reject unsafe roots, repeated transactions and exhausted byte allowances."""
    base, _, _ = packet(tmp_path)
    root = {"relative": Path("relative"), "traversal": tmp_path / ".."}.get(case, tmp_path)
    names = {
        "duplicate": ("change.json", "change.json"),
        "long-chain": ("one.json", "two.json", "three.json"),
    }.get(case, ("change.json",))
    limits = ProgressLimits(10000, 5000, 2, 2, 2)
    if case == "file-budget":
        limits = replace(limits, file_bytes=1)
    elif case == "total-budget":
        limits = replace(limits, total_bytes=(tmp_path / "base.json").stat().st_size + 1)
    with pytest.raises((ValueError, OSError, RuntimeError)):
        replay_discovery_progress(
            root, "base.json", names, base_sha256=canonical_digest(base), limits=limits
        )


@pytest.mark.parametrize("case", ["duplicate", "unused"])
def test_receipt_additions_must_be_new_and_used(tmp_path: Path, case: str) -> None:
    """Refuse repeated receipt registration and evidence unrelated to any change."""
    base, transaction, expected = packet(tmp_path)
    if case == "duplicate":
        additions = transaction["additions"]
        assert isinstance(additions, list)
        transaction["additions"] = additions * 2
    else:
        base["receipts"] = expected["receipts"]
        transaction["parent_sha256"] = canonical_digest(base)
        descriptor = {
            "receipt_digest": canonical_digest(
                {"promotable": False, "assertion_class": "declared-snapshot-integrity-only"}
            )
        }
        transaction["additions"] = [
            {"key": "unused", "descriptor": descriptor, "capture": "receipt.json"}
        ]
        write_json(tmp_path, "base.json", base)
    write_json(tmp_path, "change.json", transaction)
    with pytest.raises(ValueError):
        replay(tmp_path, base)


def test_existing_envelope_and_two_ordered_transactions(tmp_path: Path) -> None:
    """Reuse a retained envelope and reconstruct both successive complete states."""
    base, _, first = packet(tmp_path)
    base["legacy_metadata"] = {"kept": "opaque historical evidence"}
    write_json(tmp_path, "base.json", base)
    final = deepcopy(first)
    rows = final["records"]
    assert isinstance(rows, list)
    rows[1]["source_receipt"] = "proof"
    second = {
        "schema_version": "discovery-progress-change.v1",
        "parent_sha256": canonical_digest(first),
        "result_sha256": canonical_digest(final),
        "additions": [],
        "changes": [{"candidate_id": "rule-b", "before": None, "after": "proof"}],
    }
    write_json(tmp_path, "second.json", second)
    limits = ProgressLimits(10000, 5000, 2, 2, 2)
    result = replay_discovery_progress(
        tmp_path,
        "base.json",
        ("change.json", "second.json"),
        base_sha256=canonical_digest(base),
        limits=limits,
        base_metadata_fields=("legacy_metadata",),
    )
    assert result["state"] == final
    assert result["pending"] == 0
    for names in [("second.json", "change.json"), ("second.json",)]:
        with pytest.raises(ValueError, match="parent-mismatch"):
            replay_discovery_progress(
                tmp_path,
                "base.json",
                names,
                base_sha256=canonical_digest(base),
                limits=limits,
                base_metadata_fields=("legacy_metadata",),
            )
    with pytest.raises(ValueError, match="invalid-fields"):
        replay(tmp_path, base)
