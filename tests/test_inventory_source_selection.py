# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual retained inventory selection tests
"""Compare every configured root through original domain, registry and contract bytes."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from test_inventory_source_observations import selection

from rigor_foundry.context_owner_implementation import OwnerImplementationSnapshot
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.inventory_source_selection import read_inventory_domain_selection


def test_complete_selection_reads_original_sources_and_all_declared_roots(tmp_path: Path) -> None:
    """An actual complete declaration survives its exact fixed owning comparison."""
    with selection(tmp_path / "selection") as chosen:
        args = chosen.arguments
        result = read_inventory_domain_selection(
            args["domain_source"],
            args["registry_source"],
            args["contract_source"],
            args["implementation"],
        )
        assert tuple(root.root_id for root in result.roots) == ("core", "private")
        assert result.reference() == chosen.references[0].to_dict()
        assert result == args["domain_source"].read()
        with pytest.raises(ValueError, match="actual retained"):
            read_inventory_domain_selection(
                cast(RetainedContextSource, {}),
                args["registry_source"],
                args["contract_source"],
                args["implementation"],
            )
        with pytest.raises(ValueError, match="complete inventory implementation"):
            read_inventory_domain_selection(
                args["domain_source"],
                args["registry_source"],
                args["contract_source"],
                cast(OwnerImplementationSnapshot, {}),
            )


@pytest.mark.parametrize(
    "fault",
    (
        "missing-project",
        "outside-project",
        "binding-group",
        "binding-path",
        "binding-scope",
        "binding-set",
        "binding-extra",
        "missing-domain-format",
        "registry-format",
        "contract-role",
        "contract-code",
        "source-kind",
    ),
)
def test_actual_selection_refuses_wrong_complete_source_relationships(
    tmp_path: Path, fault: str
) -> None:
    """No source format, omitted root, alternate role or foreign owner can fall back."""
    with selection(tmp_path / "selection", fault=fault) as chosen:
        args = chosen.arguments
        with pytest.raises(ValueError):
            read_inventory_domain_selection(
                args["domain_source"],
                args["registry_source"],
                args["contract_source"],
                args["implementation"],
            )
