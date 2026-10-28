# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete dual-signed corpus acceptance
"""Bind the full declared source corpus and one native record to two typed signatures."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import ClassVar

from .audit_primitives import canonical_digest
from .model_primitives import require_digest, require_identifier
from .policy_model_inputs import (
    checked_policy_budget,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .rule_corpus_ratification import RuleCorpusRatification1
from .rule_source_document import RuleSourceDocument1
from .signed_rule_chain_v3 import RuleChainV3Signature
from .typed_object_reference import TypedObjectRef1

RULE_CORPUS_ACCEPTANCE_SCHEMA_VERSION = "1.0"
_COMPONENTS = (
    "qualitative_controls",
    "review_policies",
    "legacy_control_bindings",
    "authority_bindings",
    "freshness_policies",
)
_RATIFICATION = frozenset({("rule-corpus-ratification", "1.0")})
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "corpus_id",
        "document_digest",
        "universe_digest",
        "decision_set_digest",
        "component_set_digest",
        "compiler_contract_digest",
        "native_ratification",
        "author_signature",
        "reviewer_signature",
        "acceptance_digest",
    }
)


def rule_corpus_document_digests(
    document: RuleSourceDocument1,
    *,
    budget: PolicyReadBudget1,
) -> dict[str, str]:
    """Derive the complete corpus identities from actual bounded document arrays.

    Parameters
    ----------
    document : RuleSourceDocument1
        Complete actual source declaration, reparsed with its original owners.
    budget : PolicyReadBudget1
        Explicit allocation bounds for the complete document.

    Returns
    -------
    dict[str, str]
        Corpus ID and exact document, universe, decision, component and compiler
        identities. The component digest hashes all five specified wire arrays.

    Raises
    ------
    ValueError
        The actual model, complete original arrays or content digest is invalid.
    """
    if type(document) is not RuleSourceDocument1:
        raise ValueError("an actual complete rule source document is required")
    checked = RuleSourceDocument1.from_dict(document.to_dict(budget=budget), budget=budget)
    wire = checked.to_dict(budget=budget)
    return {
        "corpus_id": checked.corpus_id,
        "document_digest": checked.document_digest,
        "universe_digest": canonical_digest(wire["universe"]),
        "decision_set_digest": canonical_digest(wire["decisions"]),
        "component_set_digest": canonical_digest({name: wire[name] for name in _COMPONENTS}),
        "compiler_contract_digest": checked.compiler_contract_digest,
    }


def rule_corpus_acceptance_body(
    document: RuleSourceDocument1,
    ratification: RuleCorpusRatification1,
    *,
    budget: PolicyReadBudget1,
) -> dict[str, object]:
    """Derive the exact common unsigned body before either real signature exists.

    Parameters
    ----------
    document : RuleSourceDocument1
        Complete declared corpus, never a caller-provided digest subset.
    ratification : RuleCorpusRatification1
        Actual new record whose exact corpus/document/universe/decisions match.
    budget : PolicyReadBudget1
        Explicit complete-document and metadata bounds.

    Returns
    -------
    dict[str, object]
        The same nine-field preimage for both distinct v3 signature domains.

    Raises
    ------
    ValueError
        A record is malformed or the complete corpus binding differs.

    Notes
    -----
    Derivation authenticates neither native issuer nor signature. The complete
    installed-source/native/signature verifier remains mandatory.
    """
    binding = rule_corpus_document_digests(document, budget=budget)
    if type(ratification) is not RuleCorpusRatification1:
        raise ValueError("an actual corpus ratification record is required")
    native = RuleCorpusRatification1.from_dict(ratification.to_dict(budget=budget), budget=budget)
    if any(
        getattr(native, name) != binding[name]
        for name in ("corpus_id", "document_digest", "universe_digest", "decision_set_digest")
    ):
        raise ValueError("native ratification differs from the actual complete corpus")
    result: dict[str, object] = {
        "schema_version": RULE_CORPUS_ACCEPTANCE_SCHEMA_VERSION,
        "object_kind": "rule-corpus-acceptance",
        **binding,
        "native_ratification": native.reference(budget=budget).to_dict(),
    }
    policy_wire_size(result, budget=budget)
    return result


@dataclass(frozen=True)
class RuleCorpusAcceptance1:
    """Complete dual-signature metadata, awaiting actual native/source verification.

    Parsing checks both exact signature kinds and their common unsigned body;
    selected lifecycle policies, actual source bytes and competent native issuer
    authority are the separate consuming verifier's responsibility.
    """

    corpus_id: str
    document_digest: str
    universe_digest: str
    decision_set_digest: str
    component_set_digest: str
    compiler_contract_digest: str
    native_ratification: TypedObjectRef1
    author_signature: RuleChainV3Signature
    reviewer_signature: RuleChainV3Signature
    acceptance_digest: str

    schema_version: ClassVar[str] = RULE_CORPUS_ACCEPTANCE_SCHEMA_VERSION
    object_kind: ClassVar[str] = "rule-corpus-acceptance"

    def unsigned_body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate the common nine-field body without a signature or output cycle."""
        limits = checked_policy_budget(budget)
        if limits.max_references < 3:
            raise ValueError("corpus acceptance exceeds the reference budget")
        native = policy_reference(self.native_ratification, allowed=_RATIFICATION)
        corpus = require_identifier(self.corpus_id, "accepted corpus")
        if native.object_id != corpus:
            raise ValueError("accepted native reference differs from corpus identity")
        body: dict[str, object] = {
            "schema_version": RULE_CORPUS_ACCEPTANCE_SCHEMA_VERSION,
            "object_kind": "rule-corpus-acceptance",
            "corpus_id": corpus,
            "document_digest": require_digest(self.document_digest, "accepted document"),
            "universe_digest": require_digest(self.universe_digest, "accepted universe"),
            "decision_set_digest": require_digest(self.decision_set_digest, "accepted decisions"),
            "component_set_digest": require_digest(
                self.component_set_digest, "accepted components"
            ),
            "compiler_contract_digest": require_digest(
                self.compiler_contract_digest, "accepted compiler"
            ),
            "native_ratification": native.to_dict(),
        }
        policy_wire_size(body, budget=limits)
        return body

    def _signed_body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Check both actual signatures and exact common-body identities."""
        body = self.unsigned_body(budget=budget)
        digest = canonical_digest(body)
        for signature, kind in (
            (self.author_signature, "rule-corpus-author"),
            (self.reviewer_signature, "rule-corpus-acceptance"),
        ):
            if type(signature) is not RuleChainV3Signature:
                raise ValueError("corpus acceptance requires actual v3 signatures")
            signature.to_dict(budget=budget)
            if (signature.object_kind, signature.body_schema_version, signature.body_digest) != (
                kind,
                "1.0",
                digest,
            ):
                raise ValueError("corpus signature differs from the exact common unsigned body")
        return {
            **body,
            "author_signature": self.author_signature.to_dict(budget=budget),
            "reviewer_signature": self.reviewer_signature.to_dict(budget=budget),
        }

    @classmethod
    def build(
        cls,
        *,
        corpus_id: str,
        document_digest: str,
        universe_digest: str,
        decision_set_digest: str,
        component_set_digest: str,
        compiler_contract_digest: str,
        native_ratification: TypedObjectRef1,
        author_signature: RuleChainV3Signature,
        reviewer_signature: RuleChainV3Signature,
        budget: PolicyReadBudget1,
    ) -> RuleCorpusAcceptance1:
        """Build metadata only when both signatures bind the same exact unsigned body.

        Parameters
        ----------
        corpus_id, document_digest, universe_digest, decision_set_digest : str
            Exact declared complete corpus identities.
        component_set_digest, compiler_contract_digest : str
            Whole five-array component identity and separate compiler contract.
        native_ratification : TypedObjectRef1
            Actual new native ratification record's exact identity.
        author_signature, reviewer_signature : RuleChainV3Signature
            Distinct kind/domain envelopes over the same complete unsigned body.
        budget : PolicyReadBudget1
            Explicit metadata allocation limits.

        Returns
        -------
        RuleCorpusAcceptance1
            Integrity-bound complete envelope, without trusted source admission.

        Raises
        ------
        ValueError
            A field, signature identity, original reference or budget differs.
        """
        candidate = cls(
            corpus_id,
            document_digest,
            universe_digest,
            decision_set_digest,
            component_set_digest,
            compiler_contract_digest,
            native_ratification,
            author_signature,
            reviewer_signature,
            "0" * 64,
        )
        result = replace(
            candidate, acceptance_digest=canonical_digest(candidate._signed_body(budget=budget))
        )
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate complete signatures and the final twelve-field envelope digest."""
        body = self._signed_body(budget=budget)
        digest = require_digest(self.acceptance_digest, "corpus acceptance digest")
        if digest != canonical_digest(body):
            raise ValueError("corpus acceptance digest differs")
        result = {**body, "acceptance_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> RuleCorpusAcceptance1:
        """Parse the bounded exact envelope through both actual v3 signature owners."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="rule-corpus-acceptance",
            schema_version=RULE_CORPUS_ACCEPTANCE_SCHEMA_VERSION,
            budget=budget,
        )
        result = cls(
            require_identifier(data["corpus_id"], "accepted corpus"),
            require_digest(data["document_digest"], "accepted document"),
            require_digest(data["universe_digest"], "accepted universe"),
            require_digest(data["decision_set_digest"], "accepted decisions"),
            require_digest(data["component_set_digest"], "accepted components"),
            require_digest(data["compiler_contract_digest"], "accepted compiler"),
            TypedObjectRef1.from_dict(data["native_ratification"]),
            RuleChainV3Signature.from_dict(data["author_signature"], budget=budget),
            RuleChainV3Signature.from_dict(data["reviewer_signature"], budget=budget),
            require_digest(data["acceptance_digest"], "corpus acceptance digest"),
        )
        result.to_dict(budget=budget)
        return result

    def reference(self, *, budget: PolicyReadBudget1) -> TypedObjectRef1:
        """Return the actual complete envelope identity, separate from source admission."""
        self.to_dict(budget=budget)
        return TypedObjectRef1.build(
            kind="rule-corpus-acceptance",
            format_version="1.0",
            object_id=self.corpus_id,
            object_digest=self.acceptance_digest,
        )
