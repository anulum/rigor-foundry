# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual retained source universe owner
"""Observe the complete host-selected source cohort through fixed original owners."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from types import TracebackType
from uuid import uuid4

from .audit_primitives import canonical_digest
from .context_owner_implementation import OwnerImplementationSnapshot, observe_owner_implementation
from .context_owner_observations import ContextProducerObservation1
from .context_owner_proof import OwnerProof1
from .context_producer_contract import ContextProducerContract1
from .context_source_lease import RetainedContextSource
from .discovery_source_receipt import DiscoverySourceReceipt1
from .native_source_pin import NativeSourcePin
from .policy_read_budget import PolicyReadBudget1
from .policy_source_records import PolicySourceRecord1
from .policy_source_regions import SourceRegion1
from .policy_source_selection import PolicySourceRead, PolicySourceSelection
from .policy_source_spans import SourceSpan1
from .project_registry_models import ProjectRegistry
from .source_capture import SourceCapture
from .source_universe import SourceUniverseEntry1


class SourceUniverseOwner:
    """Fixed source producer borrowing the host's complete original selections.

    Parameters
    ----------
    sources : tuple of PolicySourceSelection
        Entire sorted original cohort, including every held or excluded source.
    registry_source, contract_source : RetainedContextSource
        Actual original registry and fixed source producer contract selections.
    implementation : OwnerImplementationSnapshot
        Prior complete package/interpreter observation, never a supplied code root.
    budget : PolicyReadBudget1
        Explicit complete cohort byte, count and reference ceilings.

    Raises
    ------
    ValueError, OSError, StableReadError, PermissionError
        If original selections, implementation, registry binding or source owner fails.

    Notes
    -----
    Integrity of bytes and partitions grants no semantic acceptance, source
    access, initiating authority, atomic root custody, ready boot or effects.
    The caller owns and closes all borrowed source leases after owner closure.
    """

    def __init__(
        self,
        *,
        sources: tuple[PolicySourceSelection, ...],
        registry_source: RetainedContextSource,
        contract_source: RetainedContextSource,
        implementation: OwnerImplementationSnapshot,
        budget: PolicyReadBudget1,
    ) -> None:
        """Retain an explicit complete host cohort and validate its fixed owning inputs."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        self._budget = PolicyReadBudget1.from_dict(budget.to_dict())
        if (
            type(sources) is not tuple
            or not 0 < len(sources) <= self._budget.max_sources
            or 4 * len(sources) > self._budget.max_references
        ):
            raise ValueError("source universe cohort must be nonempty, immutable and bounded")
        if any(type(item) is not PolicySourceSelection for item in sources):
            raise ValueError("source universe requires actual host source selections")
        identities = tuple(item.source_id for item in sources)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("source universe cohort must retain sorted unique source identities")
        if (
            type(registry_source) is not RetainedContextSource
            or type(contract_source) is not RetainedContextSource
        ):
            raise ValueError(
                "source universe requires actual retained registry and contract sources"
            )
        if type(implementation) is not OwnerImplementationSnapshot:
            raise ValueError(
                "source universe requires the complete original implementation observation"
            )
        implementation.__post_init__()
        self._implementation = implementation
        self._sources = sources
        self._registry = registry_source
        self._contract = contract_source
        self._selection_id = uuid4().hex
        self._closed = False
        self._read()

    def _read(self) -> tuple[ContextProducerContract1, tuple[PolicySourceRead, ...]]:
        """Revalidate fixed code, registry domains and the entire original source cohort."""
        if self._closed:
            raise ValueError("source universe owner is closed")
        actual = observe_owner_implementation(
            Path(__file__).absolute().parent, budget=self._budget
        )
        if actual != self._implementation:
            raise ValueError("selected source owner implementation or lifetime changed")
        registry, contract = self._registry.read(), self._contract.read()
        if type(registry) is not ProjectRegistry or type(contract) is not ContextProducerContract1:
            raise ValueError(
                "source universe registry or contract has the wrong original source kind"
            )
        if (contract.owner_class, contract.implementation_id, contract.implementation_digest) != (
            "source",
            "builtin.policy-source-universe.v1",
            actual.implementation_digest,
        ):
            raise ValueError(
                "source producer contract differs from its actual fixed implementation"
            )
        registry_ref = self._registry.reference
        if (registry_ref.kind, registry_ref.format_version) not in contract.source_formats:
            raise ValueError("source producer excludes the selected original registry format")
        for root in contract.root_bindings:
            project = next(
                (item for item in registry.projects if item.project_id == root.project_id), None
            )
            if (
                project is None
                or root.group_id not in {group.group_id for group in registry.groups}
                or project.owning_group_id != root.group_id
                or not PurePosixPath(root.canonical_path).is_relative_to(
                    PurePosixPath(project.canonical_path)
                )
            ):
                raise ValueError("source producer root differs from original registered ownership")
        discovery: dict[str, list[tuple[PolicySourceSelection, DiscoverySourceReceipt1]]] = {}
        for selected in self._sources:
            record = selected.metadata.read()
            if type(record) is not PolicySourceRecord1:
                raise ValueError(
                    "source universe metadata must retain its original policy source owner"
                )
            reference = selected.metadata.reference
            if (reference.kind, reference.format_version) not in contract.source_formats:
                raise ValueError("source producer excludes an actual original source format")
            if isinstance(record.record, DiscoverySourceReceipt1):
                discovery.setdefault(record.record.receipt_digest, []).append(
                    (selected, record.record)
                )
        for cohort in discovery.values():
            receipt = cohort[0][1]
            if tuple(item.source_id for item, _ in cohort) != tuple(
                name for name, _ in receipt.sources
            ):
                raise ValueError(
                    "source universe omits an original discovery source, including unused rows"
                )
            states = {item.read_state for item, _ in cohort}
            if "verified" in states and states != {"verified"}:
                raise ValueError(
                    "held discovery members prevent reading the complete original snapshot"
                )
        reads = []
        byte_count = 0
        for selected in self._sources:
            observed = selected.read(budget=self._budget)
            byte_count += 0 if observed.payload is None else len(observed.payload)
            if byte_count > self._budget.max_total_source_bytes:
                raise ValueError("complete source universe exceeds its total byte budget")
            reads.append(observed)
        return contract, tuple(reads)

    def _snapshot(self, reads: tuple[PolicySourceRead, ...]) -> str:
        """Bind the entire actual selection without an enclosing entry or proof digest."""
        return canonical_digest(
            {
                "selection_id": self._selection_id,
                "implementation": self._implementation.snapshot_digest,
                "registry": self._registry.snapshot_id,
                "contract": self._contract.snapshot_id,
                "sources": [
                    {
                        "source_id": selected.source_id,
                        "classification": selected.classification,
                        "locator": selected.locator,
                        "read_state": selected.read_state,
                        "disposition": selected.disposition,
                        "disposition_decision": selected.disposition_decision,
                        "source_snapshot": read.snapshot_id,
                        "verification_digest": read.verification_digest,
                    }
                    for selected, read in zip(self._sources, reads, strict=True)
                ],
            }
        )

    def observe(self) -> tuple[SourceUniverseEntry1, ...]:
        """Generate every source row from actual original source/code/registry observations.

        Returns
        -------
        tuple of SourceUniverseEntry1
            Complete sorted cohort, retaining held and excluded rows explicitly.

        Raises
        ------
        ValueError, OSError, StableReadError, PermissionError
            If any original selected source or its fixed owner no longer agrees.
        """
        contract, reads = self._read()
        snapshot = self._snapshot(reads)
        result = []
        for selected, read in zip(self._sources, reads, strict=True):
            reference = selected.metadata.reference
            digest = None if read.payload is None else hashlib.sha256(read.payload).hexdigest()
            subject = reference.object_digest if digest is None else digest
            observation = ContextProducerObservation1(
                contract.owner_id,
                self._contract.reference.ref_digest,
                reference.ref_digest,
                snapshot,
                "source-record" if read.payload is None else "source-bytes",
                subject,
                (),
            )
            proof = OwnerProof1.build(
                owner_id=contract.owner_id,
                owner_class="source",
                owner_contract=self._contract.reference,
                subject_digest=subject,
                source_object=reference,
                snapshot_id=snapshot,
                observation_digest=observation.digest(budget=self._budget),
                budget=self._budget,
            )
            result.append(
                SourceUniverseEntry1.build(
                    source_id=selected.source_id,
                    existing_source=reference,
                    classification=selected.classification,
                    locator=selected.locator,
                    byte_digest=digest,
                    byte_count=None if read.payload is None else len(read.payload),
                    read_state=selected.read_state,
                    disposition=selected.disposition,
                    disposition_decision=selected.disposition_decision,
                    provenance=proof,
                    budget=self._budget,
                )
            )
        self._read()
        return tuple(result)

    def verify(self, entries: tuple[SourceUniverseEntry1, ...]) -> None:
        """Compare the complete cohort with fresh actual original owner observations.

        Parameters
        ----------
        entries : tuple of SourceUniverseEntry1
            Entire declared cohort; subsets and caller-created proofs cannot qualify.

        Raises
        ------
        ValueError, OSError, StableReadError, PermissionError
            If entries or any current original owning source differs.
        """
        if (
            type(entries) is not tuple
            or len(entries) != len(self._sources)
            or any(type(item) is not SourceUniverseEntry1 for item in entries)
        ):
            raise ValueError(
                "source universe verification requires the complete actual entry cohort"
            )
        checked = tuple(
            SourceUniverseEntry1.from_dict(item.to_dict(), budget=self._budget) for item in entries
        )
        if checked != self.observe():
            raise ValueError(
                "source universe entries differ from actual fixed source observations"
            )

    def verify_partitions(
        self,
        entries: tuple[SourceUniverseEntry1, ...],
        *,
        regions: tuple[SourceRegion1, ...],
        spans: tuple[SourceSpan1, ...],
    ) -> tuple[SourceRegion1, ...]:
        """Check complete regions and optional spans over the same actual held bytes.

        Parameters
        ----------
        entries : tuple of SourceUniverseEntry1
            Complete actual observed cohort, including held/excluded entries.
        regions : tuple of SourceRegion1
            Complete ordered partition of every included verified source.
        spans : tuple of SourceSpan1
            Optional original statement spans, bound to those same retained bytes.

        Returns
        -------
        tuple of SourceRegion1
            Original byte-verified regions, without semantic acceptance.

        Raises
        ------
        ValueError, OSError, StableReadError, PermissionError
            If cohort, regions, spans, budgets or original source lifetime differs.
        """
        self.verify(entries)
        if (
            type(regions) is not tuple
            or type(spans) is not tuple
            or len(regions) + len(spans) > self._budget.max_references
        ):
            raise ValueError("source universe partitions exceed their immutable reference budget")
        _, reads = self._read()
        payloads = {
            selected.source_id: read.payload
            for selected, read in zip(self._sources, reads, strict=True)
            if selected.disposition == "included" and read.payload is not None
        }
        positions = dict.fromkeys(payloads, 0)
        previous: tuple[str, int] | None = None
        references = len(spans)
        rules: set[str] = set()
        for region in regions:
            if type(region) is not SourceRegion1:
                raise ValueError("actual source region record is required")
            item = SourceRegion1.from_dict(region.to_dict())
            order = (item.source_id, item.start_byte)
            if previous is not None and order <= previous:
                raise ValueError("source universe regions must retain source and byte order")
            if item.source_id not in payloads:
                raise ValueError("source region is outside included verified original bytes")
            references += 1 + len(item.rule_ids) + len(item.decision_ids)
            rules.update(item.rule_ids)
            if references > self._budget.max_references or len(rules) > self._budget.max_rules:
                raise ValueError("source universe region relations exceed the parser budget")
            payload = payloads[item.source_id]
            if item.start_byte != positions[item.source_id] or item.end_byte > len(payload):
                raise ValueError("source universe partition has a gap, overlap or invalid bound")
            if (
                hashlib.sha256(payload[item.start_byte : item.end_byte]).hexdigest()
                != item.byte_digest
            ):
                raise ValueError("source universe region differs from original retained bytes")
            positions[item.source_id] = item.end_byte
            previous = order
        if any(positions[name] != len(payload) for name, payload in payloads.items()):
            raise ValueError("source universe partition omits original retained bytes")
        span_ids: set[str] = set()
        for span in spans:
            if type(span) is not SourceSpan1:
                raise ValueError("actual source span record is required")
            item_span = SourceSpan1.from_dict(span.to_dict())
            if item_span.span_id in span_ids or item_span.source_id not in payloads:
                raise ValueError("source span identity is duplicated or unresolved")
            span_ids.add(item_span.span_id)
            item_span.verify(payloads[item_span.source_id])
        self.verify(entries)
        return regions

    def verify_external_native_source(self, native: NativeSourcePin) -> None:
        """Keep a separately verified native approval outside its own source inputs.

        Parameters
        ----------
        native : NativeSourcePin
            Actual original pin already authenticated by its separate native
            owner. This method checks independence, not native or issuer trust.

        Raises
        ------
        ValueError
            The pin is malformed or its original path/bytes are already an
            input of this entire cohort, including declared held native inputs.
        """
        if type(native) is not NativeSourcePin:
            raise ValueError("an actual original external native pin is required")
        external = NativeSourcePin.from_dict(native.to_dict())
        path = external.root / external.filename
        _, reads = self._read()
        for selected, read in zip(self._sources, reads, strict=True):
            original = read.record.record
            if selected.payload is not None and selected.payload.path == path:
                raise ValueError("native approval carrier is already a retained corpus input")
            if isinstance(original, NativeSourcePin):
                shared = (
                    original.root / original.filename == path
                    or original.file_digest == external.file_digest
                )
            elif isinstance(original, SourceCapture):
                shared = original.payload_digest == external.file_digest
            else:
                shared = dict(original.sources)[selected.source_id] == external.file_digest
            if shared:
                raise ValueError(
                    "native approval bytes or carrier already belong to the corpus inputs"
                )
        self._read()

    def close(self) -> None:
        """Revalidate the complete selection and close only this borrowing owner."""
        if self._closed:
            return
        try:
            self._read()
        finally:
            self._closed = True

    def __enter__(self) -> SourceUniverseOwner:
        """Revalidate the fixed selection before guarded source use."""
        self._read()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Perform complete final source checks without closing borrowed host leases."""
        self.close()
