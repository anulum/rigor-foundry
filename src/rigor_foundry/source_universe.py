# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — retained source universe entries
"""Preserve complete source dispositions without promoting metadata to observed access."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal, cast

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_integer,
    require_mapping,
    require_string,
)
from .context_owner_proof import OwnerProof1
from .control_assessment import Classification
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1
from .typed_object_reference import TypedObjectRef1

SOURCE_UNIVERSE_ENTRY_SCHEMA_VERSION = "1.0"
SourceReadState = Literal["verified", "unread", "unavailable", "protected"]
SourceDisposition = Literal["included", "excluded"]
_SOURCE_KINDS = frozenset({"source-capture", "native-source-pin", "discovery-source-receipt"})
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "source_id",
        "existing_source",
        "classification",
        "locator",
        "byte_digest",
        "byte_count",
        "read_state",
        "disposition",
        "disposition_decision",
        "provenance",
        "entry_digest",
    }
)


@dataclass(frozen=True)
class SourceUniverseEntry1:
    """One original source, its declared disposition and independent source proof.

    Parameters
    ----------
    source_id : str
        Exact source identity within the complete selected universe.
    existing_source : TypedObjectRef1
        Original capture, native pin or discovery receipt identity.
    classification : Classification
        Explicit output classification; never a grant to read protected bytes.
    locator : str
        Bounded opaque non-whitespace identifier, never an executable path.
    byte_digest, byte_count : str or None, int or None
        Paired exact byte metadata, required for a verified row.
    read_state : SourceReadState
        Explicit verified, unread, unavailable or protected state.
    disposition : SourceDisposition
        Included or excluded without removing the source from the universe.
    disposition_decision : str or None
        Exact decision identity, required for exclusion; acceptance is separate.
    provenance : OwnerProof1
        Independent source owner envelope binding original bytes or record.
    entry_digest : str
        Digest of this complete entry, separate from its independent subject.

    Raises
    ------
    ValueError
        If fixed fields, original reference/proof bindings or entry digest fail.

    Notes
    -----
    Parsing checks data integrity. Only actual fixed source-owner observation
    can qualify a verified row. Relevant held states and unaccepted exclusion
    decisions cannot yield semantic acceptance or ready-boot authority.
    """

    source_id: str
    existing_source: TypedObjectRef1
    classification: Classification
    locator: str
    byte_digest: str | None
    byte_count: int | None
    read_state: SourceReadState
    disposition: SourceDisposition
    disposition_decision: str | None
    provenance: OwnerProof1
    entry_digest: str

    schema_version: ClassVar[str] = SOURCE_UNIVERSE_ENTRY_SCHEMA_VERSION
    object_kind: ClassVar[str] = "source-universe-entry"

    def __post_init__(self) -> None:
        """Validate public direct construction against the same closed entry contract."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        """Validate original source and independent proof before enclosing hashing."""
        if (
            type(self.existing_source) is not TypedObjectRef1
            or type(self.provenance) is not OwnerProof1
        ):
            raise ValueError("source universe requires actual reference and owner proof records")
        source = TypedObjectRef1.from_dict(self.existing_source.to_dict())
        proof = self.provenance.to_dict()
        if source.kind not in _SOURCE_KINDS:
            raise ValueError("source universe requires an original policy source record")
        if self.classification not in {"public", "internal", "confidential", "secret"}:
            raise ValueError("unsupported source classification")
        locator = require_string(self.locator, "source locator")
        if len(locator) > 4096 or any(
            character.isspace() or ord(character) < 32 for character in locator
        ):
            raise ValueError("source locator must be a bounded opaque identifier")
        if self.read_state not in {"verified", "unread", "unavailable", "protected"}:
            raise ValueError("unsupported source read state")
        if self.disposition not in {"included", "excluded"}:
            raise ValueError("unsupported source disposition")
        sha = (
            None
            if self.byte_digest is None
            else require_digest(self.byte_digest, "source byte digest")
        )
        count = (
            None
            if self.byte_count is None
            else require_integer(self.byte_count, "source byte count")
        )
        if (sha is None) != (count is None) or (self.read_state == "verified" and sha is None):
            raise ValueError("source byte metadata must be paired and present when verified")
        decision = (
            None
            if self.disposition_decision is None
            else require_identifier(self.disposition_decision, "source disposition decision")
        )
        if self.disposition == "excluded" and decision is None:
            raise ValueError("excluded source requires its exact disposition decision")
        subject = sha if self.read_state == "verified" else source.object_digest
        if (
            self.provenance.owner_class != "source"
            or self.provenance.source_object != source
            or self.provenance.subject_digest != subject
        ):
            raise ValueError(
                "source universe provenance differs from its original independent subject"
            )
        return {
            "schema_version": SOURCE_UNIVERSE_ENTRY_SCHEMA_VERSION,
            "object_kind": "source-universe-entry",
            "source_id": require_identifier(self.source_id, "universe source identity"),
            "existing_source": source.to_dict(),
            "classification": self.classification,
            "locator": locator,
            "byte_digest": sha,
            "byte_count": count,
            "read_state": self.read_state,
            "disposition": self.disposition,
            "disposition_decision": decision,
            "provenance": proof,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the exact closed entry after checking its full data integrity.

        Returns
        -------
        dict of str to object
            Every original entry field and complete entry_digest.

        Raises
        ------
        ValueError
            If entry values, independent proof binding or digest fails.
        """
        body = self._body()
        if require_digest(self.entry_digest, "source entry digest") != canonical_digest(body):
            raise ValueError("source universe entry digest differs")
        return {**body, "entry_digest": self.entry_digest}

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> SourceUniverseEntry1:
        """Parse an exact source entry without resolving a locator or ingesting bytes.

        Parameters
        ----------
        value : object
            Complete decoded source universe entry.
        budget : PolicyReadBudget1
            Explicit bounds for the inline reference and source proof relations.

        Returns
        -------
        SourceUniverseEntry1
            Validated metadata with no implied source observation.

        Raises
        ------
        ValueError
            If fields, limits, source kind, proof subject or digest differs.
        """
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        if limits.max_references < 4 or limits.max_depth < 3:
            raise ValueError("source entry exceeds the parser budget")
        data = require_mapping(value, "source universe entry")
        require_exact_fields(data, _FIELDS, "source universe entry")
        if (
            data["schema_version"] != SOURCE_UNIVERSE_ENTRY_SCHEMA_VERSION
            or data["object_kind"] != "source-universe-entry"
        ):
            raise ValueError("unsupported source universe entry")
        return cls(
            require_identifier(data["source_id"], "universe source identity"),
            TypedObjectRef1.from_dict(data["existing_source"]),
            cast(Classification, require_string(data["classification"], "source classification")),
            require_string(data["locator"], "source locator"),
            None
            if data["byte_digest"] is None
            else require_digest(data["byte_digest"], "source byte digest"),
            None
            if data["byte_count"] is None
            else require_integer(data["byte_count"], "source byte count"),
            cast(SourceReadState, require_string(data["read_state"], "source read state")),
            cast(SourceDisposition, require_string(data["disposition"], "source disposition")),
            None
            if data["disposition_decision"] is None
            else require_identifier(data["disposition_decision"], "source disposition decision"),
            OwnerProof1.from_dict(data["provenance"], budget=limits),
            require_digest(data["entry_digest"], "source entry digest"),
        )

    @classmethod
    def build(
        cls,
        *,
        source_id: str,
        existing_source: TypedObjectRef1,
        classification: Classification,
        locator: str,
        byte_digest: str | None,
        byte_count: int | None,
        read_state: SourceReadState,
        disposition: SourceDisposition,
        disposition_decision: str | None,
        provenance: OwnerProof1,
        budget: PolicyReadBudget1,
    ) -> SourceUniverseEntry1:
        """Build an explicit entry from independent source observation inputs.

        Parameters
        ----------
        source_id, existing_source, classification, locator : str, TypedObjectRef1, Classification, str
            Original source identity, reference and declared output metadata.
        byte_digest, byte_count, read_state : str or None, int or None, SourceReadState
            Explicit byte metadata and read state, without inferred defaults.
        disposition, disposition_decision : SourceDisposition, str or None
            Declared inclusion and exact optional decision identity.
        provenance : OwnerProof1
            Independent source proof, not the digest of this enclosing entry.
        budget : PolicyReadBudget1
            Explicit parser relation and depth limits.

        Returns
        -------
        SourceUniverseEntry1
            Complete metadata record; actual producer verification is separate.

        Raises
        ------
        ValueError
            If values, runtime types, limits or source-proof relations disagree.
        """
        if type(existing_source) is not TypedObjectRef1 or type(provenance) is not OwnerProof1:
            raise ValueError("source universe requires actual reference and owner proof records")
        body: dict[str, object] = {
            "schema_version": SOURCE_UNIVERSE_ENTRY_SCHEMA_VERSION,
            "object_kind": "source-universe-entry",
            "source_id": source_id,
            "existing_source": existing_source.to_dict(),
            "classification": classification,
            "locator": locator,
            "byte_digest": byte_digest,
            "byte_count": byte_count,
            "read_state": read_state,
            "disposition": disposition,
            "disposition_decision": disposition_decision,
            "provenance": provenance.to_dict(),
        }
        return cls.from_dict({**body, "entry_digest": canonical_digest(body)}, budget=budget)
