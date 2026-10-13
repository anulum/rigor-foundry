# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — canonical lock projection owner tests
"""Exercise separated projection validation through the unchanged public lock."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from test_rule_chain_lock_v2 import _case, _lock

from rigor_foundry.models import canonical_digest
from rigor_foundry.rule_chain_lock_v2 import EffectiveProfileLockV2


def test_public_lock_binds_every_resolved_projection_component(tmp_path: Path) -> None:
    """The real signed lock retains all selected projection fields after the split."""
    with _case(tmp_path) as case:
        wire = case.lock.to_dict()
        projection = {
            "authority_clauses": [item.to_dict() for item in case.lock.authority_clauses],
            "successor_clause_digests": list(case.lock.successor_clause_digests),
            "freshness_policies": [item.to_dict() for item in case.lock.freshness_policies],
            "local_constraint_digests": list(case.lock.local_constraint_digests),
            "excluded_clause_ids": list(case.lock.excluded_clause_ids),
            "adapter_custody": [item.to_dict() for item in case.lock.adapter_custody],
            "issuer_order": list(case.lock.issuer_order),
            "grantor_classes": list(case.lock.grantor_classes),
        }
        assert wire["rule_projection_digest"] == canonical_digest(projection)
        assert all(wire[name] == value for name, value in projection.items())
        assert EffectiveProfileLockV2.from_dict(wire) == case.lock


def test_public_projection_refuses_duplicate_successor_identity(tmp_path: Path) -> None:
    """Four copies of one successor never substitute for four selected successors."""
    with _case(tmp_path) as case:
        report = replace(
            case.report, successor_clause_digests=(case.report.successor_clause_digests[0],) * 4
        )
        with pytest.raises(ValueError, match="four selected successor"):
            _lock(report, case.pack, case.profile, case.source, case.adapters)


def test_public_projection_refuses_selecting_an_excluded_clause(tmp_path: Path) -> None:
    """A selected clause cannot also be excluded in the canonical signed projection."""
    with _case(tmp_path) as case:
        profile = replace(
            case.profile, excluded_clause_ids=(case.pack.authority_clauses[0].clause_id,)
        )
        with pytest.raises(ValueError, match="select an excluded authority clause"):
            _lock(case.report, case.pack, profile, case.source, case.adapters)
