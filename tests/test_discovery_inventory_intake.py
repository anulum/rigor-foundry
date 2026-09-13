# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — append-only discovery inventory intake
"""Exercise ordered intake and binding lineage through immutable real captures."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.discovery_progress import (
    ProgressLimits,
    replay_discovery_lineage,
    replay_discovery_progress,
)


def _write(root: Path, name: str, value: object) -> None:
    """Write one deterministic JSON fixture without changing it during replay."""
    (root / name).write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _fixture(
    root: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    """Create one retained base, source capture, intake and expected complete state."""
    base: dict[str, object] = {
        "records": [{"candidate_id": "legacy-rule", "source_receipt": None, "legacy": True}],
        "receipts": {},
    }
    capture_body: dict[str, object] = {
        "assertion_class": "discovery-source-capture-only",
        "promotable": False,
        "source_kind": "owner-direction",
        "source_locator": "retained-capture-1",
        "content_sha256": "3" * 64,
    }
    capture = {**capture_body, "capture_digest": canonical_digest(capture_body)}
    descriptor = {"capture_digest": capture["capture_digest"]}
    expected = deepcopy(base)
    expected["captures"] = {"capture-one": descriptor}
    records = expected["records"]
    assert isinstance(records, list)
    records.append(
        {
            "candidate_id": "review-batching-direction",
            "source_receipt": None,
            "source_capture": "capture-one",
            "semantic_status": "unreviewed",
            "promotable": False,
        }
    )
    intake: dict[str, object] = {
        "schema_version": "discovery-inventory-intake.v1",
        "parent_sha256": canonical_digest(base),
        "result_sha256": canonical_digest(expected),
        "additions": [
            {
                "candidate_id": "review-batching-direction",
                "capture_key": "capture-one",
                "descriptor": descriptor,
                "capture": "capture.json",
            }
        ],
    }
    for name, value in (
        ("base.json", base),
        ("capture.json", capture),
        ("intake.json", intake),
    ):
        _write(root, name, value)
    return base, capture, intake, expected


def _limits(**changes: int) -> ProgressLimits:
    """Return small explicit fixture bounds with selected replacements."""
    return replace(
        ProgressLimits(20_000, 5_000, 4, 4, 4),
        **changes,
    )


def _replay(
    root: Path,
    base: dict[str, object],
    names: tuple[str, ...] = ("intake.json",),
    *,
    limits: ProgressLimits | None = None,
) -> dict[str, object]:
    """Invoke the unified public entrypoint with a pinned retained base."""
    return replay_discovery_lineage(
        root,
        "base.json",
        names,
        base_sha256=canonical_digest(base),
        limits=limits or _limits(),
    )


def test_intake_replays_twice_and_preserves_every_input_byte(tmp_path: Path) -> None:
    """A new source-captured record is appended deterministically without writes."""
    base, _, _, expected = _fixture(tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    result = _replay(tmp_path, base)
    assert result == _replay(tmp_path, base)
    assert result == {
        "state": expected,
        "state_sha256": canonical_digest(expected),
        "total": 2,
        "bound": 0,
        "pending": 2,
        "intake_pending": 1,
        "promotable": False,
    }
    assert before == {path.name: path.read_bytes() for path in tmp_path.iterdir()}


def test_mixed_intake_then_binding_preserves_lineage_and_old_records(tmp_path: Path) -> None:
    """An ordered v1 binding may attach evidence after intake without replacing records."""
    base, _, _, intake_state = _fixture(tmp_path)
    receipt_body = {
        "promotable": False,
        "assertion_class": "declared-snapshot-integrity-only",
    }
    receipt = {**receipt_body, "receipt_digest": canonical_digest(receipt_body)}
    descriptor = {"receipt_digest": receipt["receipt_digest"]}
    bound_state = deepcopy(intake_state)
    records = bound_state["records"]
    assert isinstance(records, list)
    candidate = records[1]
    assert isinstance(candidate, dict)
    candidate["source_receipt"] = "receipt-one"
    receipts = bound_state["receipts"]
    assert isinstance(receipts, dict)
    receipts["receipt-one"] = descriptor
    binding = {
        "schema_version": "discovery-progress-change.v1",
        "parent_sha256": canonical_digest(intake_state),
        "result_sha256": canonical_digest(bound_state),
        "additions": [{"key": "receipt-one", "descriptor": descriptor, "capture": "receipt.json"}],
        "changes": [
            {
                "candidate_id": "review-batching-direction",
                "before": None,
                "after": "receipt-one",
            }
        ],
    }
    _write(tmp_path, "receipt.json", receipt)
    _write(tmp_path, "binding.json", binding)
    result = _replay(tmp_path, base, ("intake.json", "binding.json"))
    assert result["state"] == bound_state
    assert (
        result["total"],
        result["bound"],
        result["pending"],
        result["intake_pending"],
    ) == (
        2,
        1,
        1,
        0,
    )
    with pytest.raises(ValueError, match="parent-mismatch"):
        _replay(tmp_path, base, ("binding.json", "intake.json"))


@pytest.mark.parametrize(
    "case",
    [
        "schema",
        "base-pin",
        "parent",
        "result",
        "empty",
        "extra",
        "duplicate-candidate",
        "duplicate-capture",
        "claimed-capture",
        "record-limit",
    ],
)
def test_invalid_intake_envelope_refuses_without_partial_state(tmp_path: Path, case: str) -> None:
    """Malformed, stale, duplicate and over-limit intake never returns partial output."""
    base, _, intake, _ = _fixture(tmp_path)
    limits = _limits()
    if case == "schema":
        intake["schema_version"] = "unknown.v1"
    elif case == "base-pin":
        _write(tmp_path, "base.json", {**base, "receipts": {"changed": {}}})
    elif case == "parent":
        intake["parent_sha256"] = "0" * 64
    elif case == "result":
        intake["result_sha256"] = "0" * 64
    elif case == "empty":
        intake["additions"] = []
    elif case == "extra":
        intake["unexpected"] = True
    elif case == "record-limit":
        limits = _limits(records=1)
    elif case == "claimed-capture":
        records = base["records"]
        assert isinstance(records, list)
        record = records[0]
        assert isinstance(record, dict)
        record["source_capture"] = "capture-one"
        intake["parent_sha256"] = canonical_digest(base)
        _write(tmp_path, "base.json", base)
    else:
        additions = intake["additions"]
        assert isinstance(additions, list)
        duplicate = deepcopy(additions[0])
        assert isinstance(duplicate, dict)
        if case == "duplicate-candidate":
            duplicate["capture_key"] = "capture-two"
        else:
            duplicate["candidate_id"] = "another-candidate"
        additions.append(duplicate)
    _write(tmp_path, "intake.json", intake)
    with pytest.raises(ValueError):
        _replay(tmp_path, base, limits=limits)


@pytest.mark.parametrize("case", ["digest", "descriptor", "promotion", "class"])
def test_source_capture_integrity_and_nonpromotion_are_mandatory(
    tmp_path: Path, case: str
) -> None:
    """Tampered, mismatched or authority-promoting provenance captures refuse."""
    base, capture, intake, _ = _fixture(tmp_path)
    if case == "descriptor":
        additions = intake["additions"]
        assert isinstance(additions, list)
        addition = additions[0]
        assert isinstance(addition, dict)
        addition["descriptor"] = {"capture_digest": "0" * 64}
    else:
        field = {
            "digest": "capture_digest",
            "promotion": "promotable",
            "class": "assertion_class",
        }[case]
        capture[field] = "0" * 64 if case == "digest" else True
        if case != "digest":
            capture["capture_digest"] = canonical_digest(
                {key: value for key, value in capture.items() if key != "capture_digest"}
            )
    _write(tmp_path, "capture.json", capture)
    _write(tmp_path, "intake.json", intake)
    with pytest.raises(ValueError, match="capture-mismatch"):
        _replay(tmp_path, base)


def test_binding_v1_parser_remains_intake_incompatible(tmp_path: Path) -> None:
    """The old public parser rejects the new envelope instead of relaxing v1."""
    base, _, _, _ = _fixture(tmp_path)
    with pytest.raises(ValueError, match="invalid-fields"):
        replay_discovery_progress(
            tmp_path,
            "base.json",
            ("intake.json",),
            base_sha256=canonical_digest(base),
            limits=_limits(),
        )


@pytest.mark.parametrize(
    "case",
    ["relative", "traversal", "duplicate-chain", "long-chain", "symlink", "hardlink", "budget"],
)
def test_lineage_path_link_chain_and_budget_boundaries(tmp_path: Path, case: str) -> None:
    """Actual filesystem aliases, unsafe roots and exhausted budgets fail closed."""
    base, _, _, _ = _fixture(tmp_path)
    root = {"relative": Path("relative"), "traversal": tmp_path / ".."}.get(case, tmp_path)
    names = {
        "duplicate-chain": ("intake.json", "intake.json"),
        "long-chain": ("one.json", "two.json", "three.json", "four.json", "five.json"),
    }.get(case, ("intake.json",))
    limits = _limits(total_bytes=1) if case == "budget" else _limits()
    capture = tmp_path / "capture.json"
    if case == "symlink":
        capture.rename(tmp_path / "real-capture.json")
        capture.symlink_to(tmp_path / "real-capture.json")
    elif case == "hardlink":
        (tmp_path / "capture-alias.json").hardlink_to(capture)
    with pytest.raises((ValueError, OSError, RuntimeError)):
        _replay(root, base, names, limits=limits)
