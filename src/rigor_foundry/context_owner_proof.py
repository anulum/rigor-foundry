# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — source-owner proof envelopes
"""Bind independent owner observations without treating metadata as authentication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_mapping,
    require_string,
)
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1
from .typed_object_reference import TypedObjectRef1

OWNER_PROOF_SCHEMA_VERSION = "1.0"
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "owner_id",
        "owner_class",
        "owner_contract",
        "subject_digest",
        "source_object",
        "snapshot_id",
        "observation_digest",
        "proof_digest",
    }
)
_OWNER_CLASSES = frozenset(
    {"registry", "task", "inventory", "claim", "fact", "source", "evidence", "review", "native"}
)


@dataclass(frozen=True)
class OwnerProof1:
    """Exact metadata linking an owner to its independent source and observation.

    A containing context or proof digest cannot be its own subject. The installed
    owning consumer must verify the selected source, contract, code and snapshot;
    parsing this envelope alone performs none of that authentication.
    """

    owner_id: str
    owner_class: str
    owner_contract: TypedObjectRef1
    subject_digest: str
    source_object: TypedObjectRef1
    snapshot_id: str
    observation_digest: str
    proof_digest: str

    schema_version: ClassVar[str] = OWNER_PROOF_SCHEMA_VERSION
    object_kind: ClassVar[str] = "owner-proof"

    def __post_init__(self) -> None:
        """Validate direct construction and its complete metadata digest."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        """Check closed classes and actual reference records before serialization."""
        owner_class = require_string(self.owner_class, "source owner class")
        if owner_class not in _OWNER_CLASSES:
            raise ValueError("unsupported source owner class")
        if (
            type(self.owner_contract) is not TypedObjectRef1
            or type(self.source_object) is not TypedObjectRef1
        ):
            raise ValueError("owner proof requires actual typed source references")
        contract = TypedObjectRef1.from_dict(self.owner_contract.to_dict())
        if contract.kind != "context-producer-contract":
            raise ValueError("owner proof contract has the wrong source kind")
        source = TypedObjectRef1.from_dict(self.source_object.to_dict())
        return {
            "schema_version": OWNER_PROOF_SCHEMA_VERSION,
            "object_kind": "owner-proof",
            "owner_id": require_identifier(self.owner_id, "source owner identity"),
            "owner_class": owner_class,
            "owner_contract": contract.to_dict(),
            "subject_digest": require_digest(self.subject_digest, "owner subject digest"),
            "source_object": source.to_dict(),
            "snapshot_id": require_identifier(self.snapshot_id, "owner snapshot identity"),
            "observation_digest": require_digest(
                self.observation_digest, "owner observation digest"
            ),
        }

    @classmethod
    def build(
        cls,
        *,
        owner_id: str,
        owner_class: str,
        owner_contract: TypedObjectRef1,
        subject_digest: str,
        source_object: TypedObjectRef1,
        snapshot_id: str,
        observation_digest: str,
        budget: PolicyReadBudget1,
    ) -> OwnerProof1:
        """Bind explicit independent inputs without authenticating their producer."""
        if (
            type(owner_contract) is not TypedObjectRef1
            or type(source_object) is not TypedObjectRef1
        ):
            raise ValueError("owner proof requires actual typed source references")
        body: dict[str, object] = {
            "schema_version": OWNER_PROOF_SCHEMA_VERSION,
            "object_kind": "owner-proof",
            "owner_id": owner_id,
            "owner_class": owner_class,
            "owner_contract": owner_contract.to_dict(),
            "subject_digest": subject_digest,
            "source_object": source_object.to_dict(),
            "snapshot_id": snapshot_id,
            "observation_digest": observation_digest,
        }
        return cls.from_dict({**body, "proof_digest": canonical_digest(body)}, budget=budget)

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> OwnerProof1:
        """Parse the exact closed envelope under an explicit reference ceiling."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        if limits.max_references < 2:
            raise ValueError("owner proof exceeds the reference budget")
        data = require_mapping(value, "owner proof")
        require_exact_fields(data, _FIELDS, "owner proof")
        if (
            data["schema_version"] != OWNER_PROOF_SCHEMA_VERSION
            or data["object_kind"] != "owner-proof"
        ):
            raise ValueError("unsupported owner proof")
        return cls(
            require_identifier(data["owner_id"], "source owner identity"),
            require_string(data["owner_class"], "source owner class"),
            TypedObjectRef1.from_dict(data["owner_contract"]),
            require_digest(data["subject_digest"], "owner subject digest"),
            TypedObjectRef1.from_dict(data["source_object"]),
            require_identifier(data["snapshot_id"], "owner snapshot identity"),
            require_digest(data["observation_digest"], "owner observation digest"),
            require_digest(data["proof_digest"], "owner proof digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Revalidate metadata integrity without claiming a verified source lease."""
        body = self._body()
        digest = require_digest(self.proof_digest, "owner proof digest")
        if digest != canonical_digest(body):
            raise ValueError("owner proof digest differs")
        return {**body, "proof_digest": digest}
