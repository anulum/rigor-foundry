# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact native corpus ratification record
"""Bind a corpus declaration to original native source and statement identities."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import ClassVar

from .audit_primitives import canonical_digest
from .model_primitives import require_digest, require_identifier
from .native_source_pin import NATIVE_SOURCE_PIN_SCHEMA
from .policy_model_inputs import (
    checked_policy_budget,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .policy_source_spans import SourceSpan1
from .typed_object_reference import TypedObjectRef1

RULE_CORPUS_RATIFICATION_SCHEMA_VERSION = "1.0"
_NATIVE = frozenset({("native-source-pin", NATIVE_SOURCE_PIN_SCHEMA)})
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "corpus_id",
        "document_digest",
        "universe_digest",
        "decision_set_digest",
        "issuer_id",
        "native_capture",
        "statement_span",
        "statement_digest",
        "ratification_digest",
    }
)


@dataclass(frozen=True)
class RuleCorpusRatification1:
    """Exact native metadata, separate from installed issuer and byte verification.

    The span identifies the original native USER message's raw JSONL line.
    The statement digest identifies its decoded UTF8 text without the capture
    owner's appended LF. These are distinct preimages; the native owner must
    verify both against the same selected original source and actual statement.
    """

    corpus_id: str
    document_digest: str
    universe_digest: str
    decision_set_digest: str
    issuer_id: str
    native_capture: TypedObjectRef1
    statement_span: SourceSpan1
    statement_digest: str
    ratification_digest: str

    schema_version: ClassVar[str] = RULE_CORPUS_RATIFICATION_SCHEMA_VERSION
    object_kind: ClassVar[str] = "rule-corpus-ratification"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Check original reference/span identity before deriving complete metadata."""
        limits = checked_policy_budget(budget)
        if limits.max_references < 2:
            raise ValueError("corpus ratification exceeds the reference budget")
        native = policy_reference(self.native_capture, allowed=_NATIVE)
        if type(self.statement_span) is not SourceSpan1:
            raise ValueError("corpus ratification requires an actual original source span")
        span = SourceSpan1.from_dict(self.statement_span.to_dict())
        if span.source_id != native.object_id:
            raise ValueError("ratification span differs from its native source identity")
        return {
            "schema_version": RULE_CORPUS_RATIFICATION_SCHEMA_VERSION,
            "object_kind": "rule-corpus-ratification",
            "corpus_id": require_identifier(self.corpus_id, "ratification corpus"),
            "document_digest": require_digest(self.document_digest, "ratification document"),
            "universe_digest": require_digest(self.universe_digest, "ratification universe"),
            "decision_set_digest": require_digest(
                self.decision_set_digest, "ratification decisions"
            ),
            "issuer_id": require_identifier(self.issuer_id, "ratification issuer"),
            "native_capture": native.to_dict(),
            "statement_span": span.to_dict(),
            "statement_digest": require_digest(self.statement_digest, "ratification statement"),
        }

    @classmethod
    def build(
        cls,
        *,
        corpus_id: str,
        document_digest: str,
        universe_digest: str,
        decision_set_digest: str,
        issuer_id: str,
        native_capture: TypedObjectRef1,
        statement_span: SourceSpan1,
        statement_digest: str,
        budget: PolicyReadBudget1,
    ) -> RuleCorpusRatification1:
        """Build exact metadata without accepting issuer authority or a native statement.

        Parameters
        ----------
        corpus_id, document_digest, universe_digest, decision_set_digest : str
            Exact corpus and independently derived complete document identities.
        issuer_id : str
            Declared issuer; actual competence requires installed host selection.
        native_capture : TypedObjectRef1
            Actual original native-source-pin reference, never a caller locator.
        statement_span : SourceSpan1
            Original raw native user-message line coordinates and byte digest.
        statement_digest : str
            SHA256 of exact decoded UTF8 statement text, excluding capture LF.
        budget : PolicyReadBudget1
            Explicit original byte, depth and reference limits.

        Returns
        -------
        RuleCorpusRatification1
            Complete metadata record; native verification remains mandatory.

        Raises
        ------
        ValueError
            A field, reference, span relation or allocation bound is invalid.
        """
        candidate = cls(
            corpus_id,
            document_digest,
            universe_digest,
            decision_set_digest,
            issuer_id,
            native_capture,
            statement_span,
            statement_digest,
            "0" * 64,
        )
        result = replace(
            candidate, ratification_digest=canonical_digest(candidate._body(budget=budget))
        )
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate direct records and serialize the exact eleven fields."""
        body = self._body(budget=budget)
        digest = require_digest(self.ratification_digest, "corpus ratification digest")
        if digest != canonical_digest(body):
            raise ValueError("corpus ratification digest differs")
        result = {**body, "ratification_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> RuleCorpusRatification1:
        """Parse bounded exact metadata through the unchanged reference and span owners."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="rule-corpus-ratification",
            schema_version=RULE_CORPUS_RATIFICATION_SCHEMA_VERSION,
            budget=budget,
        )
        result = cls(
            require_identifier(data["corpus_id"], "ratification corpus"),
            require_digest(data["document_digest"], "ratification document"),
            require_digest(data["universe_digest"], "ratification universe"),
            require_digest(data["decision_set_digest"], "ratification decisions"),
            require_identifier(data["issuer_id"], "ratification issuer"),
            TypedObjectRef1.from_dict(data["native_capture"]),
            SourceSpan1.from_dict(data["statement_span"]),
            require_digest(data["statement_digest"], "ratification statement"),
            require_digest(data["ratification_digest"], "corpus ratification digest"),
        )
        result.to_dict(budget=budget)
        return result

    def reference(self, *, budget: PolicyReadBudget1) -> TypedObjectRef1:
        """Return this actual owning record's complete identity, without native admission."""
        self.to_dict(budget=budget)
        return TypedObjectRef1.build(
            kind="rule-corpus-ratification",
            format_version="1.0",
            object_id=self.corpus_id,
            object_digest=self.ratification_digest,
        )
