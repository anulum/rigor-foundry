# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — semantic transition proposal
"""Check exact predecessor links and source bytes without admitting policy."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from itertools import pairwise
from pathlib import Path
from typing import Final, cast

from .audit_primitives import require_exact_fields, require_integer
from .discovery_source_schema import DiscoveryLimits, DiscoveryReadError, DiscoveryValidationError
from .discovery_source_validation import validate_discovery_sources
from .model_primitives import require_digest, require_identifier
from .models import canonical_digest, require_mapping

TRANSITION_PROPOSAL_SCHEMA: Final = "semantic-transition-proposal.v1"
_REPLACEMENT_FIELDS: Final = frozenset(
    {
        "predecessor_id",
        "successor_id",
        "first_line",
        "last_line",
        "statement_digest",
        "replacement_digest",
    }
)
_PROPOSAL_FIELDS: Final = frozenset(
    {
        "schema_version",
        "parent_replay_digest",
        "proposal_source_digest",
        "owner_question_digest",
        "owner_reply_digest",
        "source_receipt_id",
        "source_receipt_digest",
        "replacements",
        "proposal_digest",
    }
)


@dataclass(frozen=True)
class StatementReplacement:
    """One exact changed-meaning replacement and LF-terminated source span."""

    predecessor_id: str
    successor_id: str
    first_line: int
    last_line: int
    statement_digest: str
    replacement_digest: str

    @classmethod
    def build(
        cls,
        *,
        predecessor_id: str,
        successor_id: str,
        first_line: int,
        last_line: int,
        statement_digest: str,
    ) -> StatementReplacement:
        """Bind a successor to a distinct predecessor and exact source lines."""
        predecessor = require_identifier(predecessor_id, "replacement.predecessor_id")
        successor = require_identifier(successor_id, "replacement.successor_id")
        if predecessor == successor:
            raise ValueError("semantic replacement must change candidate identity")
        first = require_integer(first_line, "replacement.first_line", minimum=1)
        last = require_integer(last_line, "replacement.last_line", minimum=first)
        fields: dict[str, object] = {
            "predecessor_id": predecessor,
            "successor_id": successor,
            "first_line": first,
            "last_line": last,
            "statement_digest": require_digest(statement_digest, "replacement.statement_digest"),
        }
        return cls(
            predecessor_id=predecessor,
            successor_id=successor,
            first_line=first,
            last_line=last,
            statement_digest=cast(str, fields["statement_digest"]),
            replacement_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise a digest-bound replacement proposal, not an authority grant."""
        return {
            "predecessor_id": self.predecessor_id,
            "successor_id": self.successor_id,
            "first_line": self.first_line,
            "last_line": self.last_line,
            "statement_digest": self.statement_digest,
            "replacement_digest": self.replacement_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> StatementReplacement:
        """Refuse excess fields, altered spans or recomputed statement digests."""
        data = require_mapping(value, "statement replacement")
        require_exact_fields(data, _REPLACEMENT_FIELDS, "statement replacement")
        replacement = cls.build(
            predecessor_id=require_identifier(
                data.get("predecessor_id"), "replacement.predecessor_id"
            ),
            successor_id=require_identifier(data.get("successor_id"), "replacement.successor_id"),
            first_line=require_integer(
                data.get("first_line"), "replacement.first_line", minimum=1
            ),
            last_line=require_integer(data.get("last_line"), "replacement.last_line", minimum=1),
            statement_digest=require_digest(
                data.get("statement_digest"), "replacement.statement_digest"
            ),
        )
        if data.get("replacement_digest") != replacement.replacement_digest:
            raise ValueError("semantic replacement digest does not match its fields")
        return replacement


@dataclass(frozen=True)
class SemanticTransitionProposal:
    """Evidence-bound transition candidate with no review or activation state."""

    parent_replay_digest: str
    proposal_source_digest: str
    owner_question_digest: str
    owner_reply_digest: str
    source_receipt_id: str
    source_receipt_digest: str
    replacements: tuple[StatementReplacement, ...]
    proposal_digest: str

    @staticmethod
    def body(
        *,
        parent_replay_digest: str,
        proposal_source_digest: str,
        owner_question_digest: str,
        owner_reply_digest: str,
        source_receipt_id: str,
        source_receipt_digest: str,
        replacements: tuple[StatementReplacement, ...],
    ) -> dict[str, object]:
        """Produce the exact proposal body without a reviewer verdict field."""
        if not replacements:
            raise ValueError("semantic transition needs at least one replacement")
        parsed = tuple(StatementReplacement.from_dict(item.to_dict()) for item in replacements)
        predecessors = tuple(item.predecessor_id for item in parsed)
        successors = tuple(item.successor_id for item in parsed)
        if len(set(predecessors)) != len(parsed) or len(set(successors)) != len(parsed):
            raise ValueError("semantic transition candidate identities must be unique")
        if set(predecessors).intersection(successors):
            raise ValueError("semantic transition cannot form a replacement cycle")
        if any(left.last_line >= right.first_line for left, right in pairwise(parsed)):
            raise ValueError("semantic transition source spans must be ordered and disjoint")
        return {
            "schema_version": TRANSITION_PROPOSAL_SCHEMA,
            "parent_replay_digest": require_digest(
                parent_replay_digest, "transition.parent_replay_digest"
            ),
            "proposal_source_digest": require_digest(
                proposal_source_digest, "transition.proposal_source_digest"
            ),
            "owner_question_digest": require_digest(
                owner_question_digest, "transition.owner_question_digest"
            ),
            "owner_reply_digest": require_digest(
                owner_reply_digest, "transition.owner_reply_digest"
            ),
            "source_receipt_id": require_identifier(
                source_receipt_id, "transition.source_receipt_id"
            ),
            "source_receipt_digest": require_digest(
                source_receipt_digest, "transition.source_receipt_digest"
            ),
            "replacements": [item.to_dict() for item in parsed],
        }

    @classmethod
    def build(
        cls,
        *,
        parent_replay_digest: str,
        proposal_source_digest: str,
        owner_question_digest: str,
        owner_reply_digest: str,
        source_receipt_id: str,
        source_receipt_digest: str,
        replacements: tuple[StatementReplacement, ...],
    ) -> SemanticTransitionProposal:
        """Construct one candidate with only structural and digest checks."""
        body = cls.body(
            parent_replay_digest=parent_replay_digest,
            proposal_source_digest=proposal_source_digest,
            owner_question_digest=owner_question_digest,
            owner_reply_digest=owner_reply_digest,
            source_receipt_id=source_receipt_id,
            source_receipt_digest=source_receipt_digest,
            replacements=replacements,
        )
        return cls(
            parent_replay_digest=cast(str, body["parent_replay_digest"]),
            proposal_source_digest=cast(str, body["proposal_source_digest"]),
            owner_question_digest=cast(str, body["owner_question_digest"]),
            owner_reply_digest=cast(str, body["owner_reply_digest"]),
            source_receipt_id=cast(str, body["source_receipt_id"]),
            source_receipt_digest=cast(str, body["source_receipt_digest"]),
            replacements=replacements,
            proposal_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise only a proposal; there is no accepted-state field."""
        return {
            **self.body(
                parent_replay_digest=self.parent_replay_digest,
                proposal_source_digest=self.proposal_source_digest,
                owner_question_digest=self.owner_question_digest,
                owner_reply_digest=self.owner_reply_digest,
                source_receipt_id=self.source_receipt_id,
                source_receipt_digest=self.source_receipt_digest,
                replacements=self.replacements,
            ),
            "proposal_digest": self.proposal_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> SemanticTransitionProposal:
        """Refuse altered, missing and authority-shaped fields in the wire."""
        data = require_mapping(value, "semantic transition proposal")
        require_exact_fields(data, _PROPOSAL_FIELDS, "semantic transition proposal")
        if data.get("schema_version") != TRANSITION_PROPOSAL_SCHEMA:
            raise ValueError("unsupported semantic transition proposal schema")
        raw_replacements = data.get("replacements")
        if not isinstance(raw_replacements, list):
            raise ValueError("semantic transition replacements must be an array")
        proposal = cls.build(
            parent_replay_digest=require_digest(
                data.get("parent_replay_digest"), "transition.parent_replay_digest"
            ),
            proposal_source_digest=require_digest(
                data.get("proposal_source_digest"), "transition.proposal_source_digest"
            ),
            owner_question_digest=require_digest(
                data.get("owner_question_digest"), "transition.owner_question_digest"
            ),
            owner_reply_digest=require_digest(
                data.get("owner_reply_digest"), "transition.owner_reply_digest"
            ),
            source_receipt_id=require_identifier(
                data.get("source_receipt_id"), "transition.source_receipt_id"
            ),
            source_receipt_digest=require_digest(
                data.get("source_receipt_digest"), "transition.source_receipt_digest"
            ),
            replacements=tuple(
                StatementReplacement.from_dict(item)
                for item in cast(list[object], raw_replacements)
            ),
        )
        if data.get("proposal_digest") != proposal.proposal_digest:
            raise ValueError("semantic transition proposal digest does not match its body")
        return proposal

    def matches_captured_evidence(
        self,
        *,
        replay_result: dict[str, object],
        proposal_source: bytes,
        owner_question: bytes,
        owner_reply: bytes,
    ) -> bool:
        """Check immutable bytes and replay links, never semantic acceptance.

        The caller must separately establish native-capture provenance,
        reviewer independence and semantic entailment. A true result is not
        policy promotion, a selected lock or action authority.
        """
        try:
            SemanticTransitionProposal.from_dict(self.to_dict())
            state = require_mapping(replay_result.get("state"), "transition replay state")
            records = state.get("records")
            receipts = require_mapping(state.get("receipts"), "transition receipts")
            if not isinstance(records, list):
                return False
            parsed_records = tuple(require_mapping(item, "transition record") for item in records)
            by_id = {
                require_identifier(item.get("candidate_id"), "transition.candidate_id"): item
                for item in parsed_records
            }
            if len(by_id) != len(parsed_records):
                return False
            receipt = require_mapping(
                receipts.get(self.source_receipt_id), "transition source receipt"
            )
            observed_state_digest = canonical_digest(state)
        except (TypeError, ValueError):
            return False
        if (
            replay_result.get("state_sha256") != self.parent_replay_digest
            or observed_state_digest != self.parent_replay_digest
            or replay_result.get("promotable") is not False
            or receipt.get("receipt_digest") != self.source_receipt_digest
            or sha256(proposal_source).hexdigest() != self.proposal_source_digest
            or sha256(owner_question).hexdigest() != self.owner_question_digest
            or sha256(owner_reply).hexdigest() != self.owner_reply_digest
        ):
            return False
        lines = proposal_source.splitlines(keepends=True)
        if not lines or any(not line.endswith(b"\n") or b"\r" in line for line in lines):
            return False
        for item in self.replacements:
            predecessor = by_id.get(item.predecessor_id)
            successor = by_id.get(item.successor_id)
            if predecessor is None or successor is None:
                return False
            if (
                predecessor.get("source_receipt") is not None
                or successor.get("source_receipt") != self.source_receipt_id
                or successor.get("semantic_status") != "unreviewed"
                or successor.get("promotable") is not False
                or item.last_line > len(lines)
            ):
                return False
            statement = b"".join(lines[item.first_line - 1 : item.last_line])
            if sha256(statement).hexdigest() != item.statement_digest:
                return False
        return True

    def matches_declared_discovery_source(
        self,
        *,
        replay_result: dict[str, object],
        source_root: Path,
        manifest_name: str,
        limits: DiscoveryLimits,
    ) -> bool:
        """Recheck source captures against the replay receipt, not their authority.

        The caller chooses the source root and replay. Host selection, source
        authority, semantic acceptance and Guard activation remain separate.
        """
        try:
            SemanticTransitionProposal.from_dict(self.to_dict())
            state = require_mapping(replay_result.get("state"), "transition replay state")
            receipts = require_mapping(state.get("receipts"), "transition receipts")
            descriptor = require_mapping(
                receipts.get(self.source_receipt_id), "transition source receipt"
            )
            receipt = validate_discovery_sources(
                source_root,
                manifest_name,
                limits=limits,
                required_candidate_ids=tuple(item.successor_id for item in self.replacements),
            )
            return (
                replay_result.get("state_sha256") == self.parent_replay_digest
                and canonical_digest(state) == self.parent_replay_digest
                and replay_result.get("promotable") is False
                and descriptor.get("receipt_digest") == self.source_receipt_digest
                and receipt.get("receipt_digest") == self.source_receipt_digest
                and receipt.get("promotable") is False
                and receipt.get("assertion_class") == "declared-snapshot-integrity-only"
            )
        except (DiscoveryReadError, DiscoveryValidationError, OSError, TypeError, ValueError):
            return False
