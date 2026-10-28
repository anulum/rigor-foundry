# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — held complete corpus verification
"""Compose actual source, native issuer and both signature owners through closing checks."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

from .audit_primitives import canonical_digest
from .model_primitives import require_digest
from .policy_model_inputs import checked_policy_budget
from .policy_read_budget import PolicyReadBudget1
from .rule_chain_trust_v3 import RuleObjectKindV3, TrustRolesV3
from .rule_corpus_acceptance import RuleCorpusAcceptance1, rule_corpus_acceptance_body
from .rule_corpus_native import RuleCorpusNativeOwner
from .rule_corpus_ratification import RuleCorpusRatification1
from .rule_source_compiler import verify_rule_source_document
from .rule_source_document import RuleSourceDocument1
from .signed_rule_chain_v3 import RuleChainV3Signature
from .source_universe_owner import SourceUniverseOwner
from .typed_object_reference import TypedObjectRef1


@dataclass(frozen=True)
class RuleCorpusVerifier:
    """Fixed host composition borrowing the same actual owners through consumer use.

    Parameters
    ----------
    source_owner : SourceUniverseOwner
        Actual complete original source/code/registry owner, already held.
    native_owner : RuleCorpusNativeOwner
        Actual retained native owner under independently installed issuer scope.
    roles : TrustRolesV3
        Entire original lifecycle policies from the same held host generation.
    trust_roles_digest : str
        Independently selected protected whole-policy digest.
    clock : callable
        Installed current UTC clock, invoked initially and again at close.
    budget : PolicyReadBudget1
        Explicit complete source and metadata processing bounds.

    Notes
    -----
    A caller-created composition supplies no host authority. No request parser
    installs these owners, policies, clock or protected selection. Verification
    accepts an exact extraction cohort, not a selected effective root, current
    applicability/precedence decision, gate result or effect grant.
    """

    source_owner: SourceUniverseOwner
    native_owner: RuleCorpusNativeOwner
    roles: TrustRolesV3
    trust_roles_digest: str
    clock: Callable[[], datetime]
    budget: PolicyReadBudget1

    def __post_init__(self) -> None:
        """Require actual owning implementations and explicit current selection inputs."""
        if (
            type(self.source_owner) is not SourceUniverseOwner
            or type(self.native_owner) is not RuleCorpusNativeOwner
        ):
            raise ValueError(
                "complete corpus verification requires actual fixed source/native owners"
            )
        if type(self.roles) is not TrustRolesV3 or not callable(self.clock):
            raise ValueError(
                "complete corpus verification requires selected policies and host clock"
            )
        require_digest(self.trust_roles_digest, "selected corpus trust roles")
        checked_policy_budget(self.budget)

    def _verify(
        self,
        acceptance: RuleCorpusAcceptance1,
        document: RuleSourceDocument1,
        ratification: RuleCorpusRatification1,
        targets: tuple[tuple[TypedObjectRef1, object], ...],
    ) -> RuleCorpusAcceptance1:
        """Reparse actual bodies and apply every complete owning relation to one held generation."""
        self.__post_init__()
        if type(acceptance) is not RuleCorpusAcceptance1:
            raise ValueError("an actual complete corpus acceptance envelope is required")
        limits = checked_policy_budget(self.budget)
        accepted = RuleCorpusAcceptance1.from_dict(
            acceptance.to_dict(budget=limits), budget=limits
        )
        body = rule_corpus_acceptance_body(document, ratification, budget=limits)
        if accepted.unsigned_body(budget=limits) != body:
            raise ValueError(
                "accepted identities differ from the entire actual document/native body"
            )
        digest = canonical_digest(body)
        instant = self.clock()
        signatures: tuple[tuple[RuleChainV3Signature, RuleObjectKindV3], ...] = (
            (accepted.author_signature, "rule-corpus-author"),
            (accepted.reviewer_signature, "rule-corpus-acceptance"),
        )
        for signature, kind in signatures:
            if not signature.verify(
                object_kind=kind,
                body_schema_version="1.0",
                body_digest=digest,
                roles=self.roles,
                trust_roles_digest=self.trust_roles_digest,
                now=instant,
                budget=limits,
            ):
                raise PermissionError(
                    "corpus signature or current selected lifecycle policy is invalid"
                )
        verify_rule_source_document(
            document, source_owner=self.source_owner, targets=targets, budget=limits
        )
        if any(
            entry.disposition == "included" and entry.read_state != "verified"
            for entry in document.universe
        ):
            raise PermissionError(
                "included unread or protected source prevents corpus acceptance readiness"
            )
        if any(region.disposition == "unresolved" for region in document.regions):
            raise PermissionError("unresolved source regions prevent corpus acceptance readiness")
        native = self.native_owner.verify(document, ratification)
        self.source_owner.verify_external_native_source(native)
        return accepted

    @contextmanager
    def verified_context(
        self,
        acceptance: RuleCorpusAcceptance1,
        document: RuleSourceDocument1,
        ratification: RuleCorpusRatification1,
        *,
        targets: tuple[tuple[TypedObjectRef1, object], ...],
    ) -> Iterator[RuleCorpusAcceptance1]:
        """Keep complete actual body/source/native/signature validation through consumer use.

        Parameters
        ----------
        acceptance : RuleCorpusAcceptance1
            Complete dual-signature envelope, not a detached trust receipt.
        document : RuleSourceDocument1
            Entire actual declared source and component cohort.
        ratification : RuleCorpusRatification1
            Actual new native record, independently matched by the native owner.
        targets : tuple
            Complete fixed original owning component targets for compilation.

        Yields
        ------
        RuleCorpusAcceptance1
            Exact checked metadata valid only within this retained context.

        Raises
        ------
        ValueError, PermissionError, OSError
            An actual owning relation or closing current-policy/source check
            fails. Consumer failures are not suppressed and no result is issued.
        """
        checked = self._verify(acceptance, document, ratification, targets)
        try:
            yield checked
        finally:
            if self._verify(acceptance, document, ratification, targets) != checked:
                raise PermissionError("accepted corpus generation changed during held use")
