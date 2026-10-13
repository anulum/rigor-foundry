# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — four-successor v2 chain tests
"""Exercise signed CLEAR through the real pack and project-profile APIs."""

from __future__ import annotations

from contextlib import ExitStack
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from test_rule_chain_pack_v2 import _clause, _freshness, _host_source, _pack
from test_rule_chain_pack_v2 import _roles as pack_roles
from test_rule_chain_profile_v2 import _profile
from test_semantic_acceptance_host_v2 import _fixture as acceptance_fixture
from test_semantic_acceptance_host_v2 import _host as acceptance_host
from test_semantic_transition import _HOST_SOURCE

from rigor_foundry.rule_chain_candidate_v2 import (
    RuleChainCandidateReportV2,
    inspect_rule_chain_candidate_v2,
)
from rigor_foundry.rule_chain_pack_v2 import StandardPackV2
from rigor_foundry.rule_chain_profile_v2 import ProjectProfileV2, SelectedPackV2
from rigor_foundry.semantic_acceptance_host_v2 import (
    HostSemanticAcceptanceStateV2,
    HostSemanticAcceptanceVerifierV2,
)
from rigor_foundry.semantic_transition import SemanticTransitionProposal
from rigor_foundry.signed_rule_chain_v2 import RuleChainV2TrustRoles

_NOW = datetime(2026, 9, 23, 0, 30, tzinfo=UTC)


def _chain(
    root: Path, *, omit_fourth: bool = False, cross_first: bool = False, nested: bool = False
) -> tuple[
    SemanticTransitionProposal,
    HostSemanticAcceptanceStateV2,
    dict[str, object],
    StandardPackV2,
    ProjectProfileV2,
    RuleChainV2TrustRoles,
]:
    """Build four source-exact clauses inside a signed pack and profile."""
    proposal, _, state, inputs = acceptance_fixture(root)
    lines = _HOST_SOURCE.splitlines(keepends=True)
    clauses = tuple(
        _clause(
            clause_id=f"core/{'shared/' if nested else ''}authority-{index + 1}",
            successor_id=replacement.successor_id,
            statement_digest=sha256(
                b"crossed statement\n" if cross_first and index == 0 else lines[index]
            ).hexdigest(),
            source_receipt_digest=proposal.source_receipt_digest,
            transition_digest=state.acceptance.acceptance_digest,
        )
        for index, replacement in enumerate(proposal.replacements)
    )
    pack = _pack(
        transition=state.acceptance.acceptance_digest,
        clauses=clauses,
        policies=(_freshness(policy_id="core/shared/freshness"),) if nested else None,
    )
    ids = tuple(clause.clause_id for clause in clauses)
    profile = _profile(
        pack=pack,
        authority=ids[:3] if omit_fourth else ids,
        freshness=("core/shared/freshness",) if nested else ("core/freshness",),
    )
    prior = pack_roles()
    roles = RuleChainV2TrustRoles.build(
        pack_issuers=prior.pack_issuers,
        project_selectors=prior.project_selectors,
        lock_resolvers=prior.lock_resolvers,
        semantic_authors=prior.semantic_authors,
        semantic_reviewers=state.reviewer_policy.trust_policy,
    )
    return proposal, state, inputs, pack, profile, roles


def _inspect(
    candidate: tuple[
        SemanticTransitionProposal,
        HostSemanticAcceptanceStateV2,
        dict[str, object],
        StandardPackV2,
        ProjectProfileV2,
        RuleChainV2TrustRoles,
    ],
    *,
    source_id: str | None = None,
    extra_pack: StandardPackV2 | None = None,
) -> RuleChainCandidateReportV2:
    """Call the public four-link candidate API against retained source files."""
    proposal, state, inputs, pack, profile, roles = candidate
    with ExitStack() as stack:
        source = stack.enter_context(_host_source())
        sources = {source_id or pack.pack_id: source}
        packs: tuple[StandardPackV2, ...] = (pack,)
        if extra_pack is not None:
            sources[extra_pack.pack_id] = stack.enter_context(
                _host_source(pack_id=extra_pack.pack_id, source_uri=extra_pack.source_uri)
            )
            packs = (pack, extra_pack)
        return inspect_rule_chain_candidate_v2(
            proposal=proposal,
            proposal_artifact=cast(bytes, inputs["proposal_artifact"]),
            proposal_source=cast(bytes, inputs["proposal_source"]),
            original_owner_question=cast(bytes, inputs["original_owner_question"]),
            original_owner_reply=cast(bytes, inputs["original_owner_reply"]),
            normative_source=cast(bytes, inputs["normative_source"]),
            ratification_manifest=cast(bytes, inputs["ratification_manifest"]),
            ratification_question=cast(bytes, inputs["ratification_question"]),
            ratification_reply=cast(bytes, inputs["ratification_reply"]),
            findings=cast(bytes, inputs["findings"]),
            acceptance_verifier=acceptance_host(state),
            packs=packs,
            profile=profile,
            source_verifiers=sources,
            roles=roles,
            expected_project_id=profile.project_id,
            expected_scope_digest=profile.selector_scope_digest,
            now=_NOW,
        )


def test_four_successors_join_signed_clear_pack_and_profile(tmp_path: Path) -> None:
    """All exact successor spans reach a non-admissible signed-chain report."""
    candidate = _chain(tmp_path)
    report = _inspect(candidate)
    assert report == _inspect(candidate)
    assert report.acceptance_digest == candidate[1].acceptance.acceptance_digest
    assert len(report.successor_clause_digests) == 4
    assert report.guard_admissible is False


@pytest.mark.parametrize(
    ("fault", "match"),
    [
        ("omitted", "omits or crosses"),
        ("crossed", "omits or crosses"),
        ("wrong-reviewer-trust", "do not share"),
        ("wrong-pack-transition", "do not share"),
        ("wrong-source", "statement differs"),
    ],
)
def test_incomplete_or_crossed_v2_chain_refuses(tmp_path: Path, fault: str, match: str) -> None:
    """A signed pack cannot borrow a different source, reviewer or successor."""
    candidate = _chain(tmp_path, omit_fourth=fault == "omitted", cross_first=fault == "crossed")
    proposal, state, inputs, pack, profile, roles = candidate
    if fault == "wrong-reviewer-trust":
        roles = pack_roles()
    elif fault == "wrong-pack-transition":
        pack = _pack(
            transition="0" * 64,
            clauses=tuple(
                _clause(
                    clause_id=clause.clause_id,
                    successor_id=clause.successor_id,
                    statement_digest=clause.statement_digest,
                    source_receipt_digest=clause.source_receipt_digest,
                    transition_digest="0" * 64,
                )
                for clause in pack.authority_clauses
            ),
        )
        profile = _profile(
            pack=pack, authority=tuple(clause.clause_id for clause in pack.authority_clauses)
        )
    elif fault == "wrong-source":
        inputs["normative_source"] = b"changed source\n"
    with pytest.raises((PermissionError, ValueError), match=match):
        _inspect((proposal, state, inputs, pack, profile, roles))


def test_unselected_pack_source_verifier_refuses(tmp_path: Path) -> None:
    """A valid signature does not replace the host's retained source selection."""
    with pytest.raises(PermissionError, match="retained pack sources are unverified"):
        _inspect(_chain(tmp_path), source_id="other-pack")


def test_caller_cannot_substitute_unrecognised_acceptance_verifier(tmp_path: Path) -> None:
    """The candidate API requires the typed host verifier, not a caller object."""
    proposal, _state, inputs, pack, profile, roles = _chain(tmp_path)
    with _host_source() as source, pytest.raises(PermissionError, match="host verifier"):
        inspect_rule_chain_candidate_v2(
            proposal=proposal,
            proposal_artifact=cast(bytes, inputs["proposal_artifact"]),
            proposal_source=cast(bytes, inputs["proposal_source"]),
            original_owner_question=cast(bytes, inputs["original_owner_question"]),
            original_owner_reply=cast(bytes, inputs["original_owner_reply"]),
            normative_source=cast(bytes, inputs["normative_source"]),
            ratification_manifest=cast(bytes, inputs["ratification_manifest"]),
            ratification_question=cast(bytes, inputs["ratification_question"]),
            ratification_reply=cast(bytes, inputs["ratification_reply"]),
            findings=cast(bytes, inputs["findings"]),
            acceptance_verifier=cast(HostSemanticAcceptanceVerifierV2, object()),
            packs=(pack,),
            profile=profile,
            source_verifiers={pack.pack_id: source},
            roles=roles,
            expected_project_id=profile.project_id,
            expected_scope_digest=profile.selector_scope_digest,
            now=_NOW,
        )


@pytest.mark.parametrize("duplicate", ["clause", "freshness"])
def test_cross_pack_duplicate_ids_refuse_before_four_successor_join(
    tmp_path: Path, duplicate: str
) -> None:
    """Two signed packs cannot silently choose one source rule by pack order."""
    proposal, state, inputs, pack, profile, roles = _chain(tmp_path, nested=True)
    aux = _pack(
        pack_id="core/shared",
        transition=pack.transition_digest,
        clauses=(
            _clause(
                clause_id=(
                    "core/shared/authority-1"
                    if duplicate == "clause"
                    else "core/shared/other-authority"
                ),
                source_receipt_digest=proposal.source_receipt_digest,
                transition_digest=state.acceptance.acceptance_digest,
            ),
        ),
        policies=(
            _freshness(
                policy_id=(
                    "core/shared/freshness"
                    if duplicate == "freshness"
                    else "core/shared/other-freshness"
                )
            ),
        ),
    )
    selected_aux = SelectedPackV2.build(
        pack_id=aux.pack_id,
        pack_digest=aux.pack_digest,
        source_digest=aux.source_digest,
        transition_digest=aux.transition_digest,
        pack_signer_key_id=aux.signature.key_id,
    )
    profile = _profile(
        pack=pack,
        extra_selections=(selected_aux,),
        authority=profile.authority_clause_ids,
        freshness=profile.freshness_policy_ids,
    )
    with pytest.raises(PermissionError, match="repeat a clause or freshness policy ID"):
        _inspect((proposal, state, inputs, pack, profile, roles), extra_pack=aux)
