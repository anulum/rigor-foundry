# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed context source parser selection
"""Resolve parsed source data with its actual owning parser and original digest."""

from __future__ import annotations

from typing import TypeAlias

from .audit_primitives import require_mapping
from .context_producer_contract import ContextProducerContract1
from .policy_read_budget import PolicyReadBudget1
from .project_registry_models import ProjectRegistry
from .repository_state import RepositoryState1
from .task_definition import TaskDefinition1
from .typed_object_reference import TypedObjectRef1

ContextSourceTarget: TypeAlias = (
    TaskDefinition1 | ContextProducerContract1 | RepositoryState1 | ProjectRegistry
)


def parse_context_source_target(
    reference: TypedObjectRef1, value: object, *, budget: PolicyReadBudget1
) -> ContextSourceTarget:
    """Parse one target with a fixed owner before comparing its declared identity.

    This is a data-integrity API. It receives already decoded source data rather
    than treating an ID as a path or accepting a request-appointed parser.
    Registry children retain their actual parser, embedded deployment profile
    and original canonical serializer. No rewritten child digest is introduced.
    """
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    limits = PolicyReadBudget1.from_dict(budget.to_dict())
    if type(reference) is not TypedObjectRef1:
        raise ValueError("typed context source reference is required")
    ref = TypedObjectRef1.from_dict(reference.to_dict())
    data = require_mapping(value, "context source target")
    if data.get("schema_version") != ref.format_version:
        raise ValueError("context source target version differs from reference")
    target: ContextSourceTarget
    if ref.kind == "task-definition":
        target = TaskDefinition1.from_dict(data, budget=limits)
        identity, digest = target.task_id, target.definition_digest
    elif ref.kind == "context-producer-contract":
        target = ContextProducerContract1.from_dict(data, budget=limits)
        identity, digest = target.contract_id, target.contract_digest
    elif ref.kind == "repository-state":
        target = RepositoryState1.from_dict(data)
        identity, digest = target.root_id, target.repository_state_digest
    else:
        count = 0
        for field in ("groups", "projects", "consumers"):
            items = data.get(field)
            if not isinstance(items, list):
                raise ValueError("registry source collections must be arrays")
            count += len(items)
            if count > limits.max_references:
                raise ValueError("registry source exceeds the reference budget")
            if field == "projects":
                for project in items:
                    record = require_mapping(project, "registry source project")
                    for relation in ("affiliations", "aliases"):
                        values = record.get(relation)
                        if not isinstance(values, list):
                            raise ValueError("registry project relations must be arrays")
                        count += len(values)
                        if count > limits.max_references:
                            raise ValueError("registry source exceeds the reference budget")
        target = ProjectRegistry.from_dict(data)
        identity, digest = target.generation_id, target.registry_sha256
    if (ref.object_id, ref.object_digest) != (identity, digest):
        raise ValueError("context source identity or owning digest differs")
    return target
