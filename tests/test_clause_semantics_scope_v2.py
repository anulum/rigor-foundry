# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — clause scope validation tests
"""Exercise scope syntax and registry group binding through the public APIs."""

import pytest

from rigor_foundry.clause_semantics_scope_v2 import (
    bind_clause_scope_groups_v2,
    validate_clause_scope_v2,
)


def test_group_binding_requires_current_owning_group() -> None:
    """A retired owning group cannot make a signed selector active."""
    scope = {
        "schema": "rigor.clause-scope-selector.v2",
        "targets": ["path:/tmp"],
        "exclusions": [],
    }
    with pytest.raises(PermissionError, match="owning group is absent"):
        bind_clause_scope_groups_v2(
            scope,
            owning_group_id="GROUP-A",
            registered_group_ids=frozenset({"GROUP-B"}),
        )


def test_public_scope_validator_rejects_non_array_and_non_text() -> None:
    """Host callers cannot bypass the scope parser by passing Python objects."""
    with pytest.raises(ValueError, match="must be arrays"):
        validate_clause_scope_v2(
            {"targets": "path:/tmp", "exclusions": []},
            subject="admit",
            effect_class="local-file-write",
            project_id="RIGOR-FOUNDRY",
        )
    with pytest.raises(ValueError, match="must be text"):
        validate_clause_scope_v2(
            {"targets": [42], "exclusions": []},
            subject="admit",
            effect_class="local-file-write",
            project_id="RIGOR-FOUNDRY",
        )


def test_public_group_binding_requires_selected_registry_groups() -> None:
    """Resolved group forms cannot use a foreign owner or same-group inbox."""
    group = "AGENTIC-COORDINATION-ASSURANCE-AND-CONTINUITY-SYSTEMS"
    foreign = "SCPN-REACTOR-SYSTEMS"
    scope: dict[str, object] = {
        "targets": [f"group-workspace:{group}/RIGOR-FOUNDRY", f"group-exchange-inbox:{foreign}"],
        "exclusions": [],
    }
    bind_clause_scope_groups_v2(
        scope, owning_group_id=group, registered_group_ids=frozenset({group, foreign})
    )
    with pytest.raises(ValueError, match="text arrays"):
        bind_clause_scope_groups_v2(
            {"targets": [42], "exclusions": []},
            owning_group_id=group,
            registered_group_ids=frozenset({group, foreign}),
        )


@pytest.mark.parametrize(
    "target",
    [
        "group-workspace:GROUP-B/PROJECT",
        "group-exchange-inbox:GROUP-A",
        "group-exchange-inbox:MISSING",
    ],
)
def test_group_binding_refuses_foreign_owner_and_unregistered_inboxes(target: str) -> None:
    """A syntax-valid selector cannot borrow another owner or an invalid inbox.

    Parameters
    ----------
    target : str
        Candidate selector tested against its clause or registry role.
    """
    with pytest.raises(PermissionError):
        bind_clause_scope_groups_v2(
            {"targets": [target], "exclusions": []},
            owning_group_id="GROUP-A",
            registered_group_ids=frozenset({"GROUP-A", "GROUP-B"}),
        )
