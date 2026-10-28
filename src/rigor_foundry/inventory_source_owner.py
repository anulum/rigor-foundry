# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual complete maintained inventory source owner
"""Derive and recheck maintained scope from original retained sources and actual roots."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import cast
from uuid import uuid4

from .audit_primitives import canonical_digest
from .condition_language import ConditionValue
from .context_owner_implementation import OwnerImplementationSnapshot, observe_owner_implementation
from .context_owner_observations import ContextProducerObservation1, OwnerObservation
from .context_owner_proof import OwnerProof1
from .context_producer_contract import ContextProducerContract1
from .context_source_lease import RetainedContextSource
from .git_provenance import GitRunner
from .maintained_inventory import MaintainedInventory1
from .maintained_surface import MaintainedSurface1
from .policy_read_budget import PolicyReadBudget1
from .repository_file_inputs import RepositoryFileInputs
from .repository_state import RepositoryState1
from .repository_state_observations import RepositoryStateObservation, observe_repository_state
from .task_registry_source_owners import OwnedSourceObservations


@dataclass(frozen=True)
class OwnedMaintainedInventory:
    """Original preimages, complete inventory and independently generated owner metadata.

    Attributes
    ----------
    inventory : MaintainedInventory1
        Complete declared maintained surface union, including before-images.
    change, completeness : OwnedSourceObservations
        Original state/baseline observations and their resulting proof metadata.
    capture : RepositoryStateObservation
        All original root, index, file and directory preimages.
    """

    inventory: MaintainedInventory1
    change: OwnedSourceObservations
    completeness: OwnedSourceObservations
    capture: RepositoryStateObservation


class InventorySourceOwner:
    """Fixed actual inventory implementation borrowed by trusted host composition.

    Parameters
    ----------
    monorepo_root : Path
        Previously authorised physical host root, never selected by request data.
    domain_source, registry_source, contract_source : RetainedContextSource
        Original independent configured domain, registry and inventory contract.
    baseline_source, state_source : RetainedContextSource
        Earlier complete before-images and independently retained observed state.
    implementation : OwnerImplementationSnapshot
        Prior complete package/interpreter identity checked by the actual collector.
    runner : GitRunner
        Host-selected actual Git executable under its original trust policy.
    budget : PolicyReadBudget1
        Explicit unchanged ceilings for each original source/collector transaction.

    Raises
    ------
    ValueError
        If actual source roles, fixed implementation or complete scope disagree.

    Notes
    -----
    Proof metadata becomes usable only through this entry's actual verification.
    Declared root completeness is not required-host-root authority, generated
    lineage, continuous root leasing, language validation or native permission.
    """

    def __init__(
        self,
        *,
        monorepo_root: Path,
        domain_source: RetainedContextSource,
        registry_source: RetainedContextSource,
        contract_source: RetainedContextSource,
        baseline_source: RetainedContextSource,
        state_source: RetainedContextSource,
        implementation: OwnerImplementationSnapshot,
        runner: GitRunner,
        budget: PolicyReadBudget1,
    ) -> None:
        """Retain only actual source entries and validate the fixed constructor roles."""
        if type(budget) is not PolicyReadBudget1 or type(runner) is not GitRunner:
            raise ValueError("actual inventory runner and policy read budget are required")
        if any(
            type(item) is not RetainedContextSource
            for item in (
                domain_source,
                registry_source,
                contract_source,
                baseline_source,
                state_source,
            )
        ):
            raise ValueError("inventory owner requires actual retained source selections")
        if type(implementation) is not OwnerImplementationSnapshot:
            raise ValueError("inventory owner requires a complete implementation observation")
        self._budget = PolicyReadBudget1.from_dict(budget.to_dict())
        implementation.__post_init__()
        self._implementation = implementation
        self._root = monorepo_root
        self._sources = (
            domain_source,
            registry_source,
            contract_source,
            baseline_source,
            state_source,
        )
        self._runner = runner
        self._selection_id = uuid4().hex
        self._closed = False
        self._selected_state()

    def _selected_state(self) -> RepositoryState1:
        if self._closed:
            raise ValueError("inventory owner selection is closed")
        if (
            observe_owner_implementation(Path(__file__).absolute().parent, budget=self._budget)
            != self._implementation
        ):
            raise ValueError("selected inventory owner implementation changed")
        state = self._sources[4].read()
        if type(state) is not RepositoryState1:
            raise ValueError("inventory state source has the wrong fixed owning kind")
        return state

    def observe(self) -> OwnedMaintainedInventory:
        """Derive the complete surface union and proof preimages from actual roots.

        Returns
        -------
        OwnedMaintainedInventory
            Every declared root and original preimage, plus current verified data.
            This is a bounded agreeing observation, not an atomic or effect grant.

        Raises
        ------
        ValueError
            If actual state differs, classification/history is unresolved, a merge
            is unmerged, source roles are wrong or a selected source/code changes.
        RuntimeError, OSError
            If original trusted Git or safe filesystem observation refuses.
        """
        state = self._selected_state()
        domain, registry, contract, baseline, state_source = self._sources
        capture = observe_repository_state(
            root_id=state.root_id,
            baseline_source=baseline,
            monorepo_root=self._root,
            domain_source=domain,
            registry_source=registry,
            contract_source=contract,
            implementation=self._implementation,
            runner=self._runner,
            budget=self._budget,
        )
        if capture.state != state:
            raise ValueError("retained inventory state differs from actual complete roots")
        producer = cast(ContextProducerContract1, contract.read())
        rows: list[tuple[str, str, str, str, str, str | None]] = []
        changed: set[str] = set()
        languages: set[str] = set()
        roles: set[str] = set()
        for before, current in zip(capture.baseline.roots, capture.inputs.roots, strict=True):
            actual = current.inputs
            old = {row.relative_path: row for row in before.files}
            if isinstance(actual, RepositoryFileInputs):
                if actual.git.index.unmerged_paths:
                    raise ValueError("unmerged inventory stages hold maintained completeness")
                files = actual.current_files
                index = {row.relative_path: row for row in actual.git.index.entries}
            else:
                files, index = actual.files, {}
            present = {row.relative_path: row for row in files}
            for path in sorted(old.keys() | present.keys() | index.keys()):
                original, current_file = old.get(path), present.get(path)
                effective = (
                    current_file
                    if current_file is not None and current_file.kind != "deleted"
                    else original
                )
                if (
                    effective is None
                    or effective.byte_digest is None
                    or (original is not None and original.byte_digest is None)
                ):
                    raise ValueError(
                        f"maintained byte history is unresolved: {current.root.root_id}/{path}"
                    )
                if effective.language is None or effective.role is None:
                    raise ValueError(
                        f"maintained classification is unresolved: {current.root.root_id}/{path}"
                    )
                languages.add(effective.language)
                roles.add(effective.role)
                if original is not None:
                    if original.language is None or original.role is None:
                        raise ValueError(
                            f"maintained before-classification is unresolved: {current.root.root_id}/{path}"
                        )
                    languages.add(original.language)
                    roles.add(original.role)
                rows.append(
                    (
                        current.root.root_id,
                        path,
                        effective.role,
                        effective.language,
                        effective.byte_digest,
                        None if original is None else original.byte_digest,
                    )
                )
                fields = ("kind", "mode", "byte_digest", "byte_count", "language", "role")
                differs = (
                    original is None
                    or current_file is None
                    or any(
                        getattr(original, field) != getattr(current_file, field)
                        for field in fields
                    )
                )
                if isinstance(actual, RepositoryFileInputs):
                    staged = index.get(path)
                    differs = differs or (
                        (None if original is None else (original.mode, original.object_id))
                        != (None if staged is None else (staged.mode, staged.object_id))
                    )
                if differs:
                    changed.add(current.root.canonical_path + "/" + path)
        values: dict[str, ConditionValue] = {
            "inventory.roots": tuple(item.root.root_id for item in capture.inputs.roots),
            "inventory.languages": tuple(sorted(languages)),
            "inventory.roles": tuple(sorted(roles)),
            "inventory.changed_paths": tuple(sorted(changed)),
            "inventory.repository_state": state.repository_state_digest,
        }
        snapshot = canonical_digest(
            {
                "selection_id": self._selection_id,
                "owner_id": producer.owner_id,
                "implementation_snapshot": self._implementation.snapshot_digest,
                "capture_snapshot": capture.source_snapshot_digest,
                "sources": [
                    {"reference": source.reference.to_dict(), "snapshot_id": source.snapshot_id}
                    for source in self._sources
                ],
            }
        )
        owned: list[OwnedSourceObservations] = []
        for source, subject_kind, subject, observations in (
            (
                state_source,
                "repository-state",
                state.repository_state_digest,
                tuple(
                    OwnerObservation(name, "known", values[name], state.repository_state_digest)
                    for name in producer.fact_references
                ),
            ),
            (baseline, "baseline-inventory", capture.baseline.baseline_digest, ()),
        ):
            observation = ContextProducerObservation1(
                producer.owner_id,
                contract.reference.ref_digest,
                source.reference.ref_digest,
                snapshot,
                subject_kind,
                subject,
                observations,
            )
            proof = OwnerProof1.build(
                owner_id=producer.owner_id,
                owner_class="inventory",
                owner_contract=contract.reference,
                subject_digest=subject,
                source_object=source.reference,
                snapshot_id=snapshot,
                observation_digest=observation.digest(budget=self._budget),
                budget=self._budget,
            )
            owned.append(OwnedSourceObservations(observation, proof))
        change, complete = owned
        surfaces = tuple(
            MaintainedSurface1.build(
                surface_id=canonical_digest({"root_id": root, "relative_path": path}),
                root_id=root,
                relative_path=path,
                role=role,
                language=language,
                content_digest=digest,
                baseline_content_digest=old_digest,
                inventory_proof=change.proof,
                budget=self._budget,
            )
            for root, path, role, language, digest, old_digest in rows
        )
        inventory = MaintainedInventory1.build(
            project_id=state.project_id,
            registry_generation_id=state.registry_generation_id,
            registry_sha256=state.registry_sha256,
            repository_state_digest=state.repository_state_digest,
            baseline_inventory_digest=state.baseline_inventory_digest,
            root_ids=tuple(item.root.root_id for item in capture.inputs.roots),
            surfaces=surfaces,
            change_inventory_proof=change.proof,
            completeness_proof=complete.proof,
            budget=self._budget,
        )
        for source in self._sources:
            source.read()
        self._selected_state()
        return OwnedMaintainedInventory(inventory, change, complete, capture)

    def verify(self, value: OwnedMaintainedInventory) -> None:
        """Recompute actual sources and complete scope before accepting prior metadata.

        Parameters
        ----------
        value : OwnedMaintainedInventory
            Previously captured result from this exact installed owner selection.

        Raises
        ------
        ValueError
            If values, metadata, owner entry or any actual selected input differs.
        RuntimeError, OSError
            If original safe observation cannot complete.
        """
        if (
            type(value) is not OwnedMaintainedInventory
            or type(value.inventory) is not MaintainedInventory1
            or type(value.change) is not OwnedSourceObservations
            or type(value.completeness) is not OwnedSourceObservations
        ):
            raise ValueError("actual owned maintained inventory is required")
        value.inventory.to_dict()
        value.change.observation.verify_proof_binding(value.change.proof, budget=self._budget)
        value.completeness.observation.verify_proof_binding(
            value.completeness.proof, budget=self._budget
        )
        if value != self.observe():
            raise ValueError("inventory differs from the actual selected source owner")

    def close(self) -> None:
        """Revalidate actual sources once without releasing host-borrowed leases.

        Raises
        ------
        ValueError, RuntimeError, OSError
            If closing observation refuses; the entry still becomes closed.
        """
        if self._closed:
            return
        try:
            self.observe()
        finally:
            self._closed = True

    def __enter__(self) -> InventorySourceOwner:
        """Revalidate this actual source/code entry before entering its lifetime."""
        self._selected_state()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Revalidate complete current inputs at the enclosing closing boundary."""
        self.close()
