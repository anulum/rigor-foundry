# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — composed selected dispatch applicability tests
"""Exercise actual selected leases, signed clauses and filesystem invocation extraction."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from selected_applicability_support import applicability_fixture, evaluate_applicability
from test_selected_clause_semantics_host_v2 import _state

from rigor_foundry.constraint_evaluators_v2 import EvaluatorContextV2, PreconditionContextV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.instruction_dispatch import DispatchRequest
from rigor_foundry.instruction_scope import ActionScope
from rigor_foundry.selected_clause_semantics_host_v2 import (
    HostSelectedClauseSemanticsStateV2,
    HostSelectedClauseSemanticsVerifierV2,
)
from rigor_foundry.selected_dispatch_applicability_v2 import (
    evaluate_selected_dispatch_applicability_v2,
)
from rigor_foundry.selected_rule_chain_host_v2 import (
    HostSelectedRuleChainStateV2,
    HostSelectedRuleChainVerifierV2,
)


def test_composed_request_uses_same_held_chain_and_closes_sources(tmp_path: Path) -> None:
    """Single-entry providers retain exact real fixtures through extraction and evaluation."""
    project = tmp_path / (
        "03_CODE/AGENTIC-COORDINATION-ASSURANCE-AND-CONTINUITY-SYSTEMS/repositories/RIGOR-FOUNDRY"
    )
    project.mkdir(parents=True)
    target = project / "report.txt"
    target.write_bytes(b"original\n")
    original = target.read_bytes()
    counts = {"semantics": 0, "chain": 0}
    held = {"semantics": False, "chain": False}

    def scope(_number: int, entry: dict[str, object]) -> None:
        """Sign the actual target's project directory into each fixture clause scope."""
        cast(dict[str, object], entry["scope"])["targets"] = [f"path:{project}"]

    def no_context(_digest: str, _subject: str) -> EvaluatorContextV2:
        """Refuse an unexpected context request from an all-admit rule set."""
        raise AssertionError("all-admit fixture requested constraint context")

    with _state(tmp_path, first_atomic=True, entry_mutator=scope) as initial:
        original_chain = initial.chain

        @contextmanager
        def chain_provider() -> Iterator[HostSelectedRuleChainStateV2]:
            """Retain the actual signed fixture chain and reject provider reentry."""
            assert not held["chain"]
            counts["chain"] += 1
            held["chain"] = True
            try:
                with original_chain.state() as chain:
                    yield chain
            finally:
                held["chain"] = False

        selected = replace(initial, chain=HostSelectedRuleChainVerifierV2(chain_provider))

        @contextmanager
        def semantics_provider() -> Iterator[HostSelectedClauseSemanticsStateV2]:
            """Retain real semantic source fixtures and reject provider reentry."""
            assert not held["semantics"]
            counts["semantics"] += 1
            held["semantics"] = True
            try:
                yield selected
            finally:
                held["semantics"] = False

        with original_chain.state() as chain:
            payload = canonical_journal_json_v2(
                {
                    "operation_id": "local-file-write.atomic-replace",
                    "path": str(target),
                    "content_b64": "cmVwb3J0Cg==",
                    "declared": {
                        "target_ref": {"form": "path", "value": str(target)},
                        "byte_count": 7,
                        "operation_variant": "replace-or-create",
                    },
                }
            )
            action = ActionScope(
                "RIGOR-FOUNDRY/fixture",
                "fixture-runtime",
                "RIGOR-FOUNDRY",
                "write-report",
                "local-file-write",
                f"path:{target}",
                *("no-route",) * 4,
            )
            request = DispatchRequest(
                (action,), chain.current_adapters[0], *("no-route",) * 4, payload
            )
            lock, projection = chain.lock.lock_digest, chain.lock.rule_projection_digest
        result = evaluate_selected_dispatch_applicability_v2(
            request,
            verifier=HostSelectedClauseSemanticsVerifierV2(semantics_provider),
            observed_lock_digest=lock,
            observed_projection_digest=projection,
            context_for=no_context,
        )
        assert counts == {"semantics": 1, "chain": 1}
        assert held == {"semantics": False, "chain": False}
        assert target.read_bytes() == original
        assert result.guard_admissible is False
        assert result.extraction.parts[0].target_ref == {"form": "path", "value": str(target)}
        assert result.results[0].to_dict()["admitting_clause_digests"] == list(
            result.semantics_proof.binding.active_admit_clause_digests
        )


@pytest.mark.parametrize("subject", ["veto", "route"])
def test_signed_veto_and_unregistered_route_refuse_before_context_io(
    tmp_path: Path, subject: str
) -> None:
    """Signed applicable refusal rules cannot be replaced by an installed success callback."""
    observed: list[str] = []

    def installed(_digest: str, checked_subject: str) -> EvaluatorContextV2:
        """Observe whether a refusing rule attempts installed evidence IO."""
        observed.append(checked_subject)
        raise AssertionError("refusing rule reached installed evidence reader")

    with applicability_fixture(tmp_path, subject=subject, context_for=installed) as fixture:
        before = fixture.target.read_bytes()
        expected = "covering veto" if subject == "veto" else "context is unavailable"
        with pytest.raises(PermissionError, match=expected) as caught:
            evaluate_applicability(fixture)
        if subject == "route":
            assert isinstance(caught.value.__cause__, PermissionError)
            assert "registered route extractor" in str(caught.value.__cause__)
        assert observed == []
        assert fixture.target.read_bytes() == before


def test_actual_precondition_evidence_is_read_for_each_request(tmp_path: Path) -> None:
    """A cooperative physical check passes only while its actual owned evidence passes."""
    from hashlib import sha256

    evidence = tmp_path / "verification-result"
    evidence.write_bytes(b"passed")

    def installed(_digest: str, subject: str) -> EvaluatorContextV2:
        """Read actual fixture bytes afresh without claiming enforced host qualification."""
        assert subject == "precondition"
        actual = evidence.read_bytes()
        return PreconditionContextV2(
            "verify-passed", actual == b"passed", sha256(actual).hexdigest(), "cooperative"
        )

    with applicability_fixture(tmp_path, subject="precondition", context_for=installed) as fixture:
        before = fixture.target.read_bytes()
        result = evaluate_applicability(fixture)
        assert result.guard_admissible is False
        constraints = cast(list[dict[str, str]], result.results[0].to_dict()["constraint_results"])
        assert len(constraints) == 1 and constraints[0]["subject"] == "precondition"
        assert constraints[0]["result"] == "pass"
        evidence.write_bytes(b"failed")
        with pytest.raises(PermissionError, match="applicable constraint refuses"):
            evaluate_applicability(fixture)
        assert fixture.target.read_bytes() == before


@pytest.mark.parametrize("pin", ["lock", "projection"])
def test_request_refuses_different_observed_boot_identity(tmp_path: Path, pin: str) -> None:
    """A valid source selection cannot repair a task's changed observed boot identity."""
    with applicability_fixture(tmp_path) as fixture:
        before = fixture.target.read_bytes()
        with pytest.raises(PermissionError):
            evaluate_selected_dispatch_applicability_v2(
                fixture.request,
                verifier=fixture.verifier,
                observed_lock_digest="b" * 64
                if pin == "lock"
                else fixture.chain_proof.lock_digest,
                observed_projection_digest=(
                    "b" * 64 if pin == "projection" else fixture.chain_proof.rule_projection_digest
                ),
                context_for=fixture.context_for,
            )
        assert fixture.target.read_bytes() == before
