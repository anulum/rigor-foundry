# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — held complete profile source bindings
"""Join complete selected packs and rules to actual held source/native/signature owners."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass

from .audit_primitives import canonical_digest
from .component_source_resolution import StandardPackSource2
from .model_primitives import require_digest, require_identifier
from .pack_source_host import HostPackSourceState, HostPackSourceVerifier
from .policy_model_inputs import policy_wire_size
from .policy_read_budget import PolicyReadBudget1
from .rule_chain_pack_v2 import StandardPackV2
from .rule_chain_pack_v3 import StandardPackV3
from .rule_chain_profile_v3 import ProjectProfileV3
from .rule_corpus_acceptance import RuleCorpusAcceptance1
from .rule_corpus_ratification import RuleCorpusRatification1
from .rule_corpus_verification import RuleCorpusVerifier
from .rule_source_document import RuleSourceDocument1
from .signed_rule_chain_v2 import RuleChainV2TrustRoles
from .source_capture import read_source_payload
from .source_component_reader import PolicyComponent1
from .typed_object_reference import TypedObjectRef1


def _borrowed_source_verifier(state: HostPackSourceState) -> HostPackSourceVerifier:
    """Adapt an already-held original state without acquiring its original provider again."""
    return HostPackSourceVerifier(lambda: nullcontext(state))


@dataclass
class _SelectedPackBounds:
    """Bound complete selected body bytes and nested references across every actual pack."""

    budget: PolicyReadBudget1
    size: int = 2
    references: int = 0
    count: int = 0

    def add(self, pack: StandardPackV2 | StandardPackV3, wire: dict[str, object]) -> None:
        """Charge a fully revalidated actual body before accumulating its source relations."""
        self.size += policy_wire_size(wire, budget=self.budget) + bool(self.count)
        if self.size > self.budget.max_document_bytes:
            raise ValueError("selected pack cohort exceeds the aggregate body byte budget")
        self.references += (
            len(pack.controls) + len(pack.authority_clauses) + len(pack.freshness_policies)
        )
        self.references += sum(len(row.grantor_classes) for row in pack.authority_clauses)
        self.references += sum(len(row.invalidator_ids) for row in pack.freshness_policies)
        for control in pack.controls:
            self.references += sum(
                len(rows)
                for rows in (
                    control.remediation.dependencies,
                    control.remediation.procedure_ids,
                    control.remediation.acceptance_gates,
                    control.remediation.reopen_triggers,
                )
            )
        if isinstance(pack, StandardPackV3):
            self.references += sum(
                2
                + 2 * len(row.evidence.requirements)
                + (0 if row.scope.condition is None else len(row.scope.condition.references))
                for row in pack.controls
            )
        else:
            self.references += sum(
                len(row.evidence.required_adapters)
                + len(row.evidence.evidence_types)
                + (0 if row.condition is None else len(row.condition.references))
                for row in pack.controls
            )
        if self.references > self.budget.max_references:
            raise ValueError(
                "selected pack cohort exceeds the aggregate component reference budget"
            )
        self.count += 1


@dataclass(frozen=True)
class ProfileSourceBindingsV3:
    """Read-only evidence of complete selected source relations within a held context.

    This Python value is neither a selected lock nor a serialized permission.
    It deliberately does not attest competent semantic decisions, applicability,
    current task/fact ownership, effect rights or effective root readiness.
    """

    profile_digest: str
    document_digest: str
    corpus_acceptance_digest: str
    selected_pack_digests: tuple[str, ...]
    pack_source_verification_digests: tuple[str, ...]
    rule_ids: tuple[str, ...]
    qualitative_controls: tuple[TypedObjectRef1, ...]
    legacy_controls: tuple[TypedObjectRef1, ...]


@dataclass(frozen=True)
class ProfileSourceVerifierV3:
    """Borrow one held corpus and original pack-source generation for complete source joins.

    Parameters
    ----------
    corpus_verifier : RuleCorpusVerifier
        Actual already-held complete source/native/current-policy composition.
    original_sources : tuple[HostPackSourceState, ...]
        Actual original pack-source states acquired by the enclosing host once,
        in sorted unique pack-ID order. Pure original verifiers borrow them;
        no independent legacy selected-chain provider is entered.
    expected_profile_digest, expected_project_id, expected_scope_digest : str
        Independently protected profile selection and project/scope preconditions.

    Notes
    -----
    A request cannot install this composition. Successful source verification
    accepts the exact complete extraction and pack selection relations only.
    Original transition/native semantics, competent exclusions, current facts
    and full lock resolution remain separate required owning checks.
    """

    corpus_verifier: RuleCorpusVerifier
    original_sources: tuple[HostPackSourceState, ...]
    expected_profile_digest: str
    expected_project_id: str
    expected_scope_digest: str

    def __post_init__(self) -> None:
        """Require actual fixed corpus/source owners and bounded protected selection inputs."""
        if type(self.corpus_verifier) is not RuleCorpusVerifier:
            raise ValueError("profile source verification requires an actual corpus owner")
        limits = self.corpus_verifier.budget
        if (
            type(self.original_sources) is not tuple
            or len(self.original_sources) > limits.max_references
            or len(self.original_sources) > limits.max_sources
        ):
            raise ValueError("original pack sources require a bounded immutable cohort")
        if any(type(row) is not HostPackSourceState for row in self.original_sources):
            raise ValueError("original pack sources require actual already-held source states")
        identities = tuple(row.selected.pack_id for row in self.original_sources)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("original pack source identities must be sorted and unique")
        require_digest(self.expected_profile_digest, "protected profile3 selection")
        require_identifier(self.expected_project_id, "protected profile3 project")
        require_digest(self.expected_scope_digest, "protected profile3 scope")

    def _verify(
        self,
        profile: ProjectProfileV3,
        packs: tuple[StandardPackV2 | StandardPackV3, ...],
        document: RuleSourceDocument1,
        acceptance: RuleCorpusAcceptance1,
    ) -> ProfileSourceBindingsV3:
        """Verify complete signed parent/child identities and all actual source-component joins."""
        self.__post_init__()
        corpus = self.corpus_verifier
        limits = corpus.budget
        if type(profile) is not ProjectProfileV3:
            raise ValueError("an actual complete project profile3 is required")
        checked = ProjectProfileV3.from_dict(profile.to_dict(budget=limits), budget=limits)
        if (
            checked.profile_digest != self.expected_profile_digest
            or checked.project_id != self.expected_project_id
            or checked.selector_scope_digest != self.expected_scope_digest
            or checked.corpus_acceptance_digest != acceptance.acceptance_digest
        ):
            raise PermissionError("profile3 differs from the protected whole-corpus selection")
        now = corpus.clock()
        if not checked.signature.verify(
            object_kind="project-profile",
            body_schema_version="3.0",
            body_digest=canonical_digest(checked.unsigned_body(budget=limits)),
            roles=corpus.roles,
            trust_roles_digest=corpus.trust_roles_digest,
            now=now,
            budget=limits,
        ):
            raise PermissionError("profile3 current selected signature is invalid")
        if type(packs) is not tuple or len(packs) != len(checked.selected_packs):
            raise ValueError("profile3 requires its exact complete ordered pack cohort")
        originals = {row.selected.pack_id: row for row in self.original_sources}
        legacy = tuple(pack for pack in packs if type(pack) is StandardPackV2)
        if set(originals) != {pack.pack_id for pack in legacy}:
            raise PermissionError(
                "original source states differ from the complete selected old-pack cohort"
            )
        roles2 = RuleChainV2TrustRoles.build(
            pack_issuers=corpus.roles.pack_issuers,
            project_selectors=corpus.roles.project_selectors,
            lock_resolvers=corpus.roles.lock_resolvers,
            semantic_authors=corpus.roles.semantic_authors,
            semantic_reviewers=corpus.roles.semantic_reviewers,
        )
        controls: list[TypedObjectRef1] = []
        original_controls: list[TypedObjectRef1] = []
        original_packs: set[TypedObjectRef1] = set()
        authorities: list[TypedObjectRef1] = []
        freshness: list[TypedObjectRef1] = []
        source_proofs: list[str] = []
        bounds = _SelectedPackBounds(limits)
        original_source_bytes = 0
        for selected, pack in zip(checked.selected_packs, packs, strict=True):
            if type(pack) is StandardPackV3 and selected.pack_format == "3.0":
                wire3 = pack.to_dict(budget=limits)
                current3 = StandardPackV3.from_dict(wire3, budget=limits)
                bounds.add(current3, wire3)
                if (
                    current3.source_digest != document.document_digest
                    or current3.corpus_acceptance_digest != acceptance.acceptance_digest
                    or not current3.signature.verify(
                        object_kind="standard-pack",
                        body_schema_version="3.0",
                        body_digest=canonical_digest(current3.unsigned_body(budget=limits)),
                        roles=corpus.roles,
                        trust_roles_digest=corpus.trust_roles_digest,
                        now=now,
                        budget=limits,
                    )
                ):
                    raise PermissionError(
                        "pack3 source, complete acceptance or current signature differs"
                    )
                controls.extend(row.reference(budget=limits) for row in current3.controls)
                source_proofs.append(
                    canonical_digest(
                        {
                            "contract": "rigor-foundry.complete-pack-source-binding.v3",
                            "pack_digest": current3.pack_digest,
                            "document_digest": document.document_digest,
                            "corpus_acceptance_digest": acceptance.acceptance_digest,
                            "universe_digest": acceptance.universe_digest,
                            "native_ratification": acceptance.native_ratification.to_dict(),
                        }
                    )
                )
                current: StandardPackV2 | StandardPackV3 = current3
            elif type(pack) is StandardPackV2 and selected.pack_format == "2.0":
                original_reader = StandardPackSource2(pack, limits)
                current2 = original_reader.record
                bounds.add(current2, original_reader.to_dict())
                payload = read_source_payload(
                    originals[pack.pack_id].selected.retained_path,
                    maximum_bytes=limits.max_source_bytes,
                )
                original_source_bytes += len(payload)
                if original_source_bytes > limits.max_total_source_bytes:
                    raise ValueError(
                        "original pack sources exceed the complete source byte budget"
                    )
                source = _borrowed_source_verifier(originals[pack.pack_id])
                if not current2.verify_structural_source_signature(
                    roles=roles2, source_verifier=source, now=now
                ):
                    raise PermissionError(
                        "original pack source or current original signature is invalid"
                    )
                if selected.transition_digest != current2.transition_digest:
                    raise PermissionError("original pack transition selection differs")
                proof = source.verify(
                    pack_id=current2.pack_id,
                    source_uri=current2.source_uri,
                    source_digest=current2.source_digest,
                )
                source_proofs.append(
                    require_digest(
                        proof["source_verification_digest"], "original source verification"
                    )
                )
                original_packs.add(StandardPackSource2(current2, limits).reference())
                original_controls.extend(
                    PolicyComponent1(row, limits).reference() for row in current2.controls
                )
                current = current2
            else:
                raise ValueError("selected child format requires its exact actual pack owner")
            if (
                selected.pack_id != current.pack_id
                or selected.pack_digest != current.pack_digest
                or selected.source_digest != current.source_digest
                or selected.pack_signer_key_id != current.signature.key_id
            ):
                raise PermissionError("selected pack identity, source, digest or signer differs")
            authorities.extend(
                PolicyComponent1(row, limits).reference() for row in current.authority_clauses
            )
            freshness.extend(
                PolicyComponent1(row, limits).reference() for row in current.freshness_policies
            )
        expected_controls = tuple(
            row.reference(budget=limits) for row in document.qualitative_controls
        )
        expected_originals = {row.control for row in document.legacy_control_bindings}
        cohorts = (
            (controls, set(expected_controls)),
            (original_controls, expected_originals),
            (authorities, set(document.authority_bindings)),
            (
                freshness,
                {PolicyComponent1(row, limits).reference() for row in document.freshness_policies},
            ),
        )
        for actual, expected in cohorts:
            if len(actual) != len(set(actual)) or set(actual) != expected:
                raise PermissionError(
                    "selected packs omit, duplicate or replace the complete source components"
                )
        if not {row.pack for row in document.legacy_control_bindings}.issubset(original_packs):
            raise PermissionError(
                "complete source legacy bindings name a different original pack cohort"
            )
        needs_legacy_context = any(
            control.condition is not None for pack in legacy for control in pack.controls
        )
        if (checked.legacy_fact_context_digest is not None) != needs_legacy_context:
            raise PermissionError(
                "profile3 legacy fact-context declaration differs from selected original conditions"
            )
        rule_ids = tuple(row.rule_id for row in document.rules)
        if tuple(row.rule_id for row in checked.rule_dispositions) != rule_ids:
            raise PermissionError(
                "profile3 dispositions omit or replace the complete source rule cohort"
            )
        if checked.mandatory_rule_ids != tuple(
            row.rule_id for row in document.rules if row.mandatory_floor
        ):
            raise PermissionError(
                "profile3 mandatory identities differ from the complete declared source floor"
            )
        decisions = {row.decision_id: row for row in document.decisions}
        for disposition in checked.rule_dispositions:
            if disposition.decision_id is not None:
                decision = decisions.get(disposition.decision_id)
                if decision is None or disposition.rule_id not in (
                    *decision.affected_rule_ids,
                    *decision.successor_rule_ids,
                ):
                    raise PermissionError(
                        "profile3 disposition names an absent or unrelated source decision"
                    )
                if disposition.disposition == "excluded" and decision.relation != "exclusion":
                    raise PermissionError(
                        "profile3 exclusion lacks its exact source exclusion declaration"
                    )
        return ProfileSourceBindingsV3(
            checked.profile_digest,
            document.document_digest,
            acceptance.acceptance_digest,
            tuple(row.pack_digest for row in packs),
            tuple(source_proofs),
            rule_ids,
            expected_controls,
            tuple(sorted(expected_originals, key=lambda row: row.object_id)),
        )

    @contextmanager
    def verified_context(
        self,
        profile: ProjectProfileV3,
        packs: tuple[StandardPackV2 | StandardPackV3, ...],
        document: RuleSourceDocument1,
        acceptance: RuleCorpusAcceptance1,
        ratification: RuleCorpusRatification1,
        *,
        targets: tuple[tuple[TypedObjectRef1, object], ...],
    ) -> Iterator[ProfileSourceBindingsV3]:
        """Keep complete actual corpus and selected source relations checked through consumer use.

        Parameters
        ----------
        profile, packs : ProjectProfileV3, tuple
            Actual signed complete selection and exact ordered versioned bodies.
        document, acceptance, ratification : object
            Actual complete original source document, dual-signature acceptance
            and independently selected original native approval.
        targets : tuple
            Complete original typed compilation targets, never dynamic loaders.

        Yields
        ------
        ProfileSourceBindingsV3
            Read-only complete source evidence, valid only inside this context.

        Raises
        ------
        ValueError, PermissionError, OSError
            Any actual body, current crypto, source/native custody, complete
            selection relation or closing generation check fails. Consumer
            failures propagate. No effective lock or permission is produced.
        """
        with self.corpus_verifier.verified_context(
            acceptance, document, ratification, targets=targets
        ):
            checked = self._verify(profile, packs, document, acceptance)
            try:
                yield checked
            finally:
                if self._verify(profile, packs, document, acceptance) != checked:
                    raise PermissionError(
                        "complete profile source generation changed during held use"
                    )
