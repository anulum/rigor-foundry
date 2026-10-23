# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — retained inventory domain source selection
"""Compare exact domain, registry and fixed inventory-contract source preimages."""

from __future__ import annotations

from pathlib import PurePosixPath

from .context_owner_implementation import OwnerImplementationSnapshot
from .context_producer_contract import ContextProducerContract1
from .context_source_lease import RetainedContextSource
from .inventory_domain import InventoryDomain1
from .project_registry_models import ProjectRegistry


def read_inventory_domain_selection(
    domain_source: RetainedContextSource,
    registry_source: RetainedContextSource,
    contract_source: RetainedContextSource,
    implementation: OwnerImplementationSnapshot,
) -> InventoryDomain1:
    """Compare the complete declared root set with actual retained source selections.

    Parameters
    ----------
    domain_source, registry_source, contract_source:
        Borrowed actual source leases; this function reads each original source.
    implementation:
        Complete code/interpreter observation verified by the enclosing owner.

    Returns
    -------
    InventoryDomain1
        Revalidated complete declared roots and rules. This comparison neither
        observes package code itself nor grants source or installed authority.
    """
    if any(
        type(source) is not RetainedContextSource
        for source in (domain_source, registry_source, contract_source)
    ):
        raise ValueError("actual retained inventory source selections are required")
    if type(implementation) is not OwnerImplementationSnapshot:
        raise ValueError("complete inventory implementation observation is required")
    implementation.__post_init__()
    domain, registry, contract = (
        source.read() for source in (domain_source, registry_source, contract_source)
    )
    if (
        type(domain) is not InventoryDomain1
        or type(registry) is not ProjectRegistry
        or type(contract) is not ContextProducerContract1
    ):
        raise ValueError("inventory source kind differs from its fixed owning role")
    if (contract.owner_class, contract.implementation_id, contract.implementation_digest) != (
        "inventory",
        "builtin.maintained-inventory.v1",
        implementation.implementation_digest,
    ):
        raise ValueError("inventory contract differs from the fixed actual implementation")
    for source in (domain_source, registry_source):
        ref = source.reference
        if (ref.kind, ref.format_version) not in contract.source_formats:
            raise ValueError("inventory contract excludes the actual selected source format")
    project = next(
        (item for item in registry.projects if item.project_id == domain.project_id), None
    )
    if project is None:
        raise ValueError("inventory project is absent from the selected registry")
    bindings = {
        root.root_id: root
        for root in contract.root_bindings
        if root.project_id == domain.project_id
    }
    if set(bindings) != {root.root_id for root in domain.roots}:
        raise ValueError("configured inventory roots differ from the complete contract selection")
    for root in domain.roots:
        binding = bindings[root.root_id]
        if (
            binding.group_id != project.owning_group_id
            or binding.canonical_path != root.canonical_path
            or binding.configured_scope_digest != domain.domain_digest
            or not PurePosixPath(root.canonical_path).is_relative_to(
                PurePosixPath(project.canonical_path)
            )
        ):
            raise ValueError(
                "configured inventory root differs from actual registry ownership or scope"
            )
    return domain
