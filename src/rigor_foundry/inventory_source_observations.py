# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — retained configured Git-root observations
"""Observe classified Git-root inputs against actual retained domain/registry/code."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .audit_primitives import canonical_digest
from .context_owner_implementation import OwnerImplementationSnapshot, observe_owner_implementation
from .context_source_lease import RetainedContextSource
from .git_inventory import open_directory_no_follow
from .git_provenance import GitRunner
from .inventory_classification import classify_repository_file_inputs
from .inventory_domain import InventoryDomainRoot
from .inventory_source_selection import read_inventory_domain_selection
from .model_primitives import require_identifier
from .policy_read_budget import PolicyReadBudget1
from .repository_file_inputs import RepositoryFileInputs, observe_repository_file_inputs
from .typed_object_reference import TypedObjectRef1


@dataclass(frozen=True)
class InventoryRootObservation:
    """One observed Git root, retaining all declared roots through its domain reference.

    This is not a complete configured inventory, owner proof, source permission,
    language-content validation or installed host/effect admission. Its other
    roots and ignored/generated observations remain separate owning obligations.
    """

    root: InventoryDomainRoot
    domain_reference: TypedObjectRef1
    registry_reference: TypedObjectRef1
    contract_reference: TypedObjectRef1
    files: RepositoryFileInputs
    source_snapshot_digest: str


def observe_classified_git_root(
    *,
    root_id: str,
    baseline_head: str,
    monorepo_root: Path,
    domain_source: RetainedContextSource,
    registry_source: RetainedContextSource,
    contract_source: RetainedContextSource,
    implementation: OwnerImplementationSnapshot,
    runner: GitRunner,
    budget: PolicyReadBudget1,
) -> InventoryRootObservation:
    """Observe a Git root under actual selected configuration and complete code checks.

    Parameters
    ----------
    root_id:
        Exact Git-root identity within the complete retained domain declaration.
    baseline_head:
        Explicit full commit identity for the selected Git root.
    monorepo_root:
        Already-authorised canonical host root selected outside request data.
    domain_source, registry_source, contract_source:
        Actual borrowed source leases selected by trusted host composition.
    implementation:
        Prior complete installed-package/interpreter observation.
    runner:
        Actual Git runner selected under the host's executable trust policy.
    budget:
        Explicit ceilings for each owning source read and file-input transaction.
        Enclosing whole-host resource and source-access guards remain separate.

    Returns
    -------
    InventoryRootObservation
        Actual baseline/current inputs with configured path classifications and
        a source-selection snapshot. It is not a whole maintained-inventory proof.
    """
    if type(budget) is not PolicyReadBudget1 or type(runner) is not GitRunner:
        raise ValueError("actual Git runner and policy read budget are required")
    limits = PolicyReadBudget1.from_dict(budget.to_dict())
    sources = (domain_source, registry_source, contract_source)
    if any(type(source) is not RetainedContextSource for source in sources):
        raise ValueError("actual retained inventory source selections are required")
    if type(implementation) is not OwnerImplementationSnapshot:
        raise ValueError("complete inventory implementation observation is required")
    implementation.__post_init__()
    actual = observe_owner_implementation(Path(__file__).absolute().parent, budget=limits)
    if actual != implementation:
        raise ValueError("selected inventory implementation or source identity changed")
    selected = require_identifier(root_id, "selected inventory root")
    domain = read_inventory_domain_selection(*sources, actual)
    root = next((item for item in domain.roots if item.root_id == selected), None)
    if root is None or root.source_kind != "git":
        raise ValueError("selected inventory root does not use Git file inputs")
    if not monorepo_root.is_absolute() or ".." in monorepo_root.parts:
        raise ValueError("host monorepo root must be an exact absolute path")
    descriptor = open_directory_no_follow(monorepo_root)
    try:
        opening = os.fstat(descriptor)
        inputs = observe_repository_file_inputs(
            monorepo_root / root.canonical_path,
            baseline_head=baseline_head,
            runner=runner,
            budget=limits,
        )
        classified = classify_repository_file_inputs(
            inputs, root_id=selected, domain=domain, budget=limits
        )
        read_inventory_domain_selection(*sources, actual)
        if observe_owner_implementation(Path(__file__).absolute().parent, budget=limits) != actual:
            raise ValueError("inventory implementation changed during observation")
        closing_descriptor = open_directory_no_follow(monorepo_root)
        try:
            closing = os.fstat(closing_descriptor)
            if (opening.st_dev, opening.st_ino) != (closing.st_dev, closing.st_ino):
                raise ValueError("selected host monorepo directory object changed")
        finally:
            os.close(closing_descriptor)
        snapshot = canonical_digest(
            {
                "implementation_snapshot": actual.snapshot_digest,
                "root_id": selected,
                "sources": [
                    {"reference": source.reference.to_dict(), "snapshot_id": source.snapshot_id}
                    for source in sources
                ],
            }
        )
        return InventoryRootObservation(
            root,
            domain_source.reference,
            registry_source.reference,
            contract_source.reference,
            classified,
            snapshot,
        )
    finally:
        os.close(descriptor)
