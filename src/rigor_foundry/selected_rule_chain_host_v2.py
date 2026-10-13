# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected v2 rule-chain host verification
"""Rebuild the four-successor chain before trusting a host-selected lock."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass
from datetime import datetime

from .adapter_operations_v2 import AdapterOperationsV2
from .effect_target_table_v2 import EffectTargetTableV2
from .effect_vocabulary_v2 import EffectVocabularyV2
from .effective_profile import AdapterLock
from .extractor_registry_v2 import ExtractorRegistryV2
from .model_primitives import require_digest, require_identifier
from .pack_source_host import HostPackSourceVerifier
from .rule_chain_candidate_v2 import (
    RuleChainCandidateReportV2,
    inspect_rule_chain_candidate_v2,
)
from .rule_chain_lock_v2 import EffectiveProfileLockV2
from .rule_chain_pack_v2 import StandardPackV2
from .rule_chain_profile_v2 import ProjectProfileV2
from .semantic_acceptance_host_v2 import HostSemanticAcceptanceVerifierV2
from .semantic_transition import SemanticTransitionProposal
from .signed_rule_chain_v2 import RuleChainV2TrustRoles
from .tier0_builtin.path_admission_v2 import PinnedPathScopeV2


@dataclass(frozen=True)
class SelectedRuleChainArtifactsV2:
    """Exact source artifacts used to freshly inspect the four-successor chain.

    Attributes
    ----------
    proposal : SemanticTransitionProposal
        Exact unchanged four-successor proposal.
    proposal_artifact : bytes
        Bounded serialized artifact that parses to the same proposal.
    proposal_source : bytes
        Exact original proposal source capture.
    original_owner_question : bytes
        Selected source-selection owner question capture.
    original_owner_reply : bytes
        Selected source-selection owner reply capture.
    normative_source : bytes
        Exact LF-terminated source containing the selected statement spans.
    ratification_manifest : bytes
        Selected full-text native ratification manifest.
    ratification_question : bytes
        Exact selected full-text owner question capture.
    ratification_reply : bytes
        Exact selected owner reply capture.
    findings : bytes
        Bounded exact retained independent-review findings bytes.

    Notes
    -----
    These are input bytes, not an assertion that a previous transition or lock was accepted.
    """

    proposal: SemanticTransitionProposal
    proposal_artifact: bytes
    proposal_source: bytes
    original_owner_question: bytes
    original_owner_reply: bytes
    normative_source: bytes
    ratification_manifest: bytes
    ratification_question: bytes
    ratification_reply: bytes
    findings: bytes


@dataclass(frozen=True)
class HostSelectedRuleChainStateV2:
    """One protected choice of source, reviewer, packs, profile and signed lock.

    Attributes
    ----------
    artifacts : SelectedRuleChainArtifactsV2
        Exact proposal, source, native captures and review findings to reinspect.
    acceptance_verifier : HostSemanticAcceptanceVerifierV2
        Host-selected acceptance verifier for the same transition.
    packs : tuple[StandardPackV2, ...]
        Exact selected signed packs.
    profile : ProjectProfileV2
        Exact signed selection of pack clauses and freshness policies.
    source_verifiers : Mapping[str, HostPackSourceVerifier]
        Host retained-source verifier for each selected pack ID.
    roles : RuleChainV2TrustRoles
        Five selected enrolled signing-role policies.
    current_adapters : tuple[AdapterLock, ...]
        Current protected adapter custody records.
    effect_vocabulary : EffectVocabularyV2
        Exact closed reviewed effect vocabulary.
    effect_target_table : EffectTargetTableV2
        Exact closed reviewed target-kind table.
    extractor_registry : ExtractorRegistryV2
        Selected sealed extractor metadata.
    effect_operations : AdapterOperationsV2
        Selected closed operation metadata, matching its dependencies.
    lock : EffectiveProfileLockV2
        Exact selected signed resolved effective-profile lock.
    expected_lock_digest : str
        Protected selected lock digest.
    expected_project_id : str
        Protected selected project identity.
    expected_scope_digest : str
        Protected selector-scope digest.
    expected_acceptance_host_selection_digest : str
        Protected acceptance selection precondition.
    expected_effect_vocabulary_digest : str
        Protected vocabulary body precondition.
    expected_effect_target_table_digest : str
        Protected target-table body precondition.
    expected_extractor_registry_digest : str
        Protected extractor registry body precondition.
    expected_effect_operations_digest : str
        Protected operations body precondition.
    expected_resolver_code_digest : str
        Protected resolver-code precondition carried in the signed lock.
    expected_issuer_order : tuple[str, ...]
        Protected ordered grantor identity list for structural checks.
    clock : Callable[[], datetime]
        Trusted current UTC clock callable.
    revalidate : Callable[[], None]
        Host callback that refuses changed selection or revocation custody.
    path_scope : PinnedPathScopeV2 | None
        Optional selected-registry path data used by downstream bound consumers.

    Notes
    -----
    The provider pins the state and revocations for the complete lease. A path scope or fixture
    provider is not an execution capability.
    """

    artifacts: SelectedRuleChainArtifactsV2
    acceptance_verifier: HostSemanticAcceptanceVerifierV2
    packs: tuple[StandardPackV2, ...]
    profile: ProjectProfileV2
    source_verifiers: Mapping[str, HostPackSourceVerifier]
    roles: RuleChainV2TrustRoles
    current_adapters: tuple[AdapterLock, ...]
    effect_vocabulary: EffectVocabularyV2
    effect_target_table: EffectTargetTableV2
    extractor_registry: ExtractorRegistryV2
    effect_operations: AdapterOperationsV2
    lock: EffectiveProfileLockV2
    expected_lock_digest: str
    expected_project_id: str
    expected_scope_digest: str
    expected_acceptance_host_selection_digest: str
    expected_effect_vocabulary_digest: str
    expected_effect_target_table_digest: str
    expected_extractor_registry_digest: str
    expected_effect_operations_digest: str
    expected_resolver_code_digest: str
    expected_issuer_order: tuple[str, ...]
    clock: Callable[[], datetime]
    revalidate: Callable[[], None]
    path_scope: PinnedPathScopeV2 | None = None


@dataclass(frozen=True)
class SelectedRuleChainProofV2:
    """Read-only evidence of the selected lock and its four exact successors.

    Attributes
    ----------
    lock_digest : str
        Digest of the freshly verified selected lock.
    rule_projection_digest : str
        Digest of its complete resolved rule projection.
    acceptance_digest : str
        Signed reviewer acceptance envelope binding the transition.
    candidate_report_digest : str
        Digest of the freshly rebuilt four-successor inspection.
    successor_clause_digests : tuple[str, ...]
        Four exact successor clause digests in proposal order.

    Notes
    -----
    The proof records structural and source relations; it does not authorize dispatch.
    """

    lock_digest: str
    rule_projection_digest: str
    acceptance_digest: str
    candidate_report_digest: str
    successor_clause_digests: tuple[str, ...]


@dataclass(frozen=True)
class HostSelectedRuleChainVerifierV2:
    """Reinspect the complete signed chain under host-selected state.

    Attributes
    ----------
    state : Callable[[], AbstractContextManager[HostSelectedRuleChainStateV2]]
        Protected callable yielding a consistent selected state in a context manager.

    Notes
    -----
    The protected consumer supplies custody, grant and effect checks. This verifier provides no
    signer, grant writer or dispatch callback.
    """

    state: Callable[[], AbstractContextManager[HostSelectedRuleChainStateV2]]

    @contextmanager
    def verified_lease(
        self,
    ) -> Iterator[tuple[HostSelectedRuleChainStateV2, SelectedRuleChainProofV2]]:
        """Hold the selected state and repeat full chain checks after the consumer.

        Yields
        ------
        tuple[HostSelectedRuleChainStateV2, SelectedRuleChainProofV2]
            Pinned state and initial read-only proof, valid for consumption inside the context.

        Raises
        ------
        ValueError
            Input selection or chain data is malformed.
        PermissionError
            Initial verification, host revalidation or closing proof comparison refuses.
        OSError
            A required retained or native source cannot be safely read.
        RuntimeError
            A state context suppresses a failure without completing the lease.

        Notes
        -----
        The provider prevents selection changes for the lease. Consumers separately revalidate their
        grant and permit before any effect.
        """
        completed = False
        with self.state() as selected:
            if not isinstance(selected, HostSelectedRuleChainStateV2):
                raise PermissionError("selected v2 rule-chain host state is unavailable")
            proof = HostSelectedRuleChainVerifierV2(lambda: nullcontext(selected)).verify()
            yield selected, proof
            selected.revalidate()
            final_proof = HostSelectedRuleChainVerifierV2(lambda: nullcontext(selected)).verify()
            if final_proof != proof:
                raise PermissionError("selected v2 rule chain changed during lease")
            completed = True
        if not completed:
            raise RuntimeError("selected v2 rule-chain host lease suppressed a failure")

    def verify(self) -> SelectedRuleChainProofV2:
        """Rebuild the selected chain and verify all protected lock preconditions.

        Returns
        -------
        SelectedRuleChainProofV2
            Read-only proof after current signatures, source proofs, operation bodies, projection and
            adapter custody agree.

        Raises
        ------
        ValueError
            A selected body, signature record, digest or identity is malformed.
        PermissionError
            Any selected precondition, source dependency or structural lock verification differs.
        OSError
            A selected source cannot be safely opened or read.
        RuntimeError
            The host state context suppresses a failure without a result.
        """
        result: SelectedRuleChainProofV2 | None = None
        with self.state() as selected:
            if not isinstance(selected, HostSelectedRuleChainStateV2):
                raise PermissionError("selected v2 rule-chain host state is unavailable")
            expected_lock = require_digest(
                selected.expected_lock_digest, "selected v2 lock digest"
            )
            expected_project = require_identifier(
                selected.expected_project_id, "selected v2 project"
            )
            expected_scope = require_digest(selected.expected_scope_digest, "selected v2 scope")
            expected_acceptance = require_digest(
                selected.expected_acceptance_host_selection_digest,
                "selected v2 acceptance host selection",
            )
            expected_resolver = require_digest(
                selected.expected_resolver_code_digest, "selected v2 resolver code"
            )
            expected_vocabulary = require_digest(
                selected.expected_effect_vocabulary_digest, "selected v2 effect vocabulary"
            )
            expected_table = require_digest(
                selected.expected_effect_target_table_digest, "selected v2 effect target table"
            )
            expected_registry = require_digest(
                selected.expected_extractor_registry_digest, "selected v2 extractor registry"
            )
            expected_operations = require_digest(
                selected.expected_effect_operations_digest, "selected v2 effect operations"
            )
            vocabulary = EffectVocabularyV2.from_bytes(selected.effect_vocabulary.body_bytes)
            target_table = EffectTargetTableV2.from_bytes(selected.effect_target_table.body_bytes)
            extractors = ExtractorRegistryV2.from_bytes(selected.extractor_registry.body_bytes)
            operations = AdapterOperationsV2.from_bytes(
                selected.effect_operations.body_bytes,
                vocabulary=vocabulary,
                target_table=target_table,
                extractors=extractors,
            )
            if (
                vocabulary != selected.effect_vocabulary
                or vocabulary.vocabulary_digest != expected_vocabulary
                or target_table != selected.effect_target_table
                or target_table.table_digest != expected_table
                or extractors != selected.extractor_registry
                or extractors.registry_digest != expected_registry
                or operations != selected.effect_operations
                or operations.operations_digest != expected_operations
            ):
                raise PermissionError(
                    "selected v2 effect-operation body differs from protected choice"
                )
            lock = EffectiveProfileLockV2.from_dict(selected.lock.to_dict())
            if lock != selected.lock or lock.lock_digest != expected_lock:
                raise PermissionError("selected v2 lock differs from protected choice")
            artifacts = selected.artifacts
            now = selected.clock()
            report: RuleChainCandidateReportV2 = inspect_rule_chain_candidate_v2(
                proposal=artifacts.proposal,
                proposal_artifact=artifacts.proposal_artifact,
                proposal_source=artifacts.proposal_source,
                original_owner_question=artifacts.original_owner_question,
                original_owner_reply=artifacts.original_owner_reply,
                normative_source=artifacts.normative_source,
                ratification_manifest=artifacts.ratification_manifest,
                ratification_question=artifacts.ratification_question,
                ratification_reply=artifacts.ratification_reply,
                findings=artifacts.findings,
                acceptance_verifier=selected.acceptance_verifier,
                packs=selected.packs,
                profile=selected.profile,
                source_verifiers=selected.source_verifiers,
                roles=selected.roles,
                expected_project_id=expected_project,
                expected_scope_digest=expected_scope,
                now=now,
            )
            if not lock.verify_structural_lock(
                candidate=report,
                profile=selected.profile,
                packs=selected.packs,
                source_verifiers=selected.source_verifiers,
                current_adapters=selected.current_adapters,
                roles=selected.roles,
                expected_acceptance_host_selection_digest=expected_acceptance,
                expected_effect_operations_digest=expected_operations,
                expected_resolver_code_digest=expected_resolver,
                expected_issuer_order=selected.expected_issuer_order,
                now=now,
            ):
                raise PermissionError("selected v2 lock no longer verifies")
            selected.revalidate()
            result = SelectedRuleChainProofV2(
                lock.lock_digest,
                lock.rule_projection_digest,
                lock.acceptance_digest,
                report.report_digest,
                report.successor_clause_digests,
            )
        if result is None:
            raise RuntimeError("selected v2 rule-chain host lease suppressed a failure")
        return result
