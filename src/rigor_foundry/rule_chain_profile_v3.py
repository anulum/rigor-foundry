# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit mixed-format complete profile selection
"""Bind exact pack formats and whole-corpus rule dispositions under one signed parent3."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import ClassVar, cast

from .audit_primitives import canonical_digest, require_string
from .model_primitives import require_digest, require_identifier
from .policy_model_inputs import (
    checked_policy_budget,
    policy_identifiers,
    policy_record_mapping,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .signed_rule_chain_v3 import RuleChainV3Signature
from .standard_pack import TARGET_LEVEL_ORDER, TargetLevel

PROJECT_PROFILE_V3_SCHEMA_VERSION = "3.0"
PROFILE_RULE_DISPOSITION_SCHEMA_VERSION = "1.0"
_SELECTION_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "pack_id",
        "pack_format",
        "pack_digest",
        "source_digest",
        "transition_digest",
        "corpus_acceptance_digest",
        "pack_signer_key_id",
        "selection_digest",
    }
)
_DISPOSITION_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "rule_id",
        "disposition",
        "decision_id",
        "disposition_digest",
    }
)
_PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "project_id",
        "profile_id",
        "selector_scope_digest",
        "selected_packs",
        "corpus_acceptance_digest",
        "mandatory_rule_ids",
        "rule_dispositions",
        "target_maturity",
        "legacy_fact_context_digest",
        "local_constraint_digests",
        "signature",
        "profile_digest",
    }
)


@dataclass(frozen=True)
class PackSelectionV3:
    """An exact child-format selection, preserving the two distinct acceptance relations.

    Legacy null corpus metadata never exempts its controls from the enclosing
    profile's complete corpus. Parsing does not resolve a pack or accept a source.
    """

    pack_id: str
    pack_format: str
    pack_digest: str
    source_digest: str
    transition_digest: str | None
    corpus_acceptance_digest: str | None
    pack_signer_key_id: str
    selection_digest: str

    schema_version: ClassVar[str] = PROJECT_PROFILE_V3_SCHEMA_VERSION
    object_kind: ClassVar[str] = "pack-selection"

    def _body(self) -> dict[str, object]:
        """Refuse unknown formats and every ambiguous or missing acceptance combination."""
        version = require_string(self.pack_format, "selected pack format")
        if version not in {"2.0", "3.0"}:
            raise ValueError("unsupported selected pack format")
        if version == "2.0":
            transition = require_digest(self.transition_digest, "original pack transition")
            if self.corpus_acceptance_digest is not None:
                raise ValueError("original pack selection must retain null corpus metadata")
            corpus = None
        else:
            corpus = require_digest(self.corpus_acceptance_digest, "new pack corpus acceptance")
            if self.transition_digest is not None:
                raise ValueError("new pack selection cannot substitute a legacy transition")
            transition = None
        return {
            "schema_version": PROJECT_PROFILE_V3_SCHEMA_VERSION,
            "object_kind": "pack-selection",
            "pack_id": require_identifier(self.pack_id, "selected pack identity"),
            "pack_format": version,
            "pack_digest": require_digest(self.pack_digest, "selected pack digest"),
            "source_digest": require_digest(self.source_digest, "selected pack source"),
            "transition_digest": transition,
            "corpus_acceptance_digest": corpus,
            "pack_signer_key_id": require_identifier(
                self.pack_signer_key_id, "selected pack signer"
            ),
        }

    @classmethod
    def build(
        cls,
        *,
        pack_id: str,
        pack_format: str,
        pack_digest: str,
        source_digest: str,
        transition_digest: str | None,
        corpus_acceptance_digest: str | None,
        pack_signer_key_id: str,
        budget: PolicyReadBudget1,
    ) -> PackSelectionV3:
        """Hash exact supplied child identities without looking up latest or installing trust."""
        candidate = cls(
            pack_id,
            pack_format,
            pack_digest,
            source_digest,
            transition_digest,
            corpus_acceptance_digest,
            pack_signer_key_id,
            "0" * 64,
        )
        result = replace(candidate, selection_digest=canonical_digest(candidate._body()))
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Serialize the closed format relation after checking its complete digest and bounds."""
        body = self._body()
        digest = require_digest(self.selection_digest, "pack selection digest")
        if digest != canonical_digest(body):
            raise ValueError("pack selection digest differs")
        result = {**body, "selection_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> PackSelectionV3:
        """Parse exact parent3 selection fields without casting an original SelectedPackV2."""
        data = policy_record_mapping(
            value,
            fields=_SELECTION_FIELDS,
            object_kind="pack-selection",
            schema_version=PROJECT_PROFILE_V3_SCHEMA_VERSION,
            budget=budget,
        )
        result = cls(
            require_identifier(data["pack_id"], "selected pack identity"),
            require_string(data["pack_format"], "selected pack format"),
            require_digest(data["pack_digest"], "selected pack digest"),
            require_digest(data["source_digest"], "selected pack source"),
            None
            if data["transition_digest"] is None
            else require_digest(data["transition_digest"], "original pack transition"),
            None
            if data["corpus_acceptance_digest"] is None
            else require_digest(data["corpus_acceptance_digest"], "new pack corpus acceptance"),
            require_identifier(data["pack_signer_key_id"], "selected pack signer"),
            require_digest(data["selection_digest"], "pack selection digest"),
        )
        result.to_dict(budget=budget)
        return result


@dataclass(frozen=True)
class ProfileRuleDisposition1:
    """Explicit source-rule inclusion or exclusion, separate from competent decision acceptance."""

    rule_id: str
    disposition: str
    decision_id: str | None
    disposition_digest: str

    schema_version: ClassVar[str] = PROFILE_RULE_DISPOSITION_SCHEMA_VERSION
    object_kind: ClassVar[str] = "profile-rule-disposition"

    def _body(self) -> dict[str, object]:
        """Require an exact decision identity for every exclusion without accepting that decision."""
        disposition = require_string(self.disposition, "profile rule disposition")
        if disposition not in {"included", "excluded"}:
            raise ValueError("unsupported profile rule disposition")
        decision = (
            None
            if self.decision_id is None
            else require_identifier(self.decision_id, "profile rule decision")
        )
        if disposition == "excluded" and decision is None:
            raise ValueError("excluded profile rule requires an exact decision")
        return {
            "schema_version": PROFILE_RULE_DISPOSITION_SCHEMA_VERSION,
            "object_kind": "profile-rule-disposition",
            "rule_id": require_identifier(self.rule_id, "profile rule identity"),
            "disposition": disposition,
            "decision_id": decision,
        }

    @classmethod
    def build(
        cls,
        *,
        rule_id: str,
        disposition: str,
        decision_id: str | None,
        budget: PolicyReadBudget1,
    ) -> ProfileRuleDisposition1:
        """Bind a declarative disposition; hashes confer no exception or exclusion authority."""
        candidate = cls(rule_id, disposition, decision_id, "0" * 64)
        result = replace(candidate, disposition_digest=canonical_digest(candidate._body()))
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate the exact versioned body and its enclosing digest within explicit bounds."""
        body = self._body()
        digest = require_digest(self.disposition_digest, "profile rule disposition digest")
        if digest != canonical_digest(body):
            raise ValueError("profile rule disposition digest differs")
        result = {**body, "disposition_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> ProfileRuleDisposition1:
        """Refuse unversioned, excess, missing or malformed rule-disposition fields."""
        data = policy_record_mapping(
            value,
            fields=_DISPOSITION_FIELDS,
            object_kind="profile-rule-disposition",
            schema_version=PROFILE_RULE_DISPOSITION_SCHEMA_VERSION,
            budget=budget,
        )
        result = cls(
            require_identifier(data["rule_id"], "profile rule identity"),
            require_string(data["disposition"], "profile rule disposition"),
            None
            if data["decision_id"] is None
            else require_identifier(data["decision_id"], "profile rule decision"),
            require_digest(data["disposition_digest"], "profile rule disposition digest"),
        )
        result.to_dict(budget=budget)
        return result


@dataclass(frozen=True)
class ProjectProfileV3:
    """One signed whole-corpus selection, without a second legacy profile or effective lock.

    The actual selected-pack/source/issuer/fact owner must derive the complete
    rule/control cohort, mandatory floor and conditions. Integrity parsing never
    accepts a self-selected subset, exclusion, current fact or maturity override.
    """

    project_id: str
    profile_id: str
    selector_scope_digest: str
    selected_packs: tuple[PackSelectionV3, ...]
    corpus_acceptance_digest: str
    mandatory_rule_ids: tuple[str, ...]
    rule_dispositions: tuple[ProfileRuleDisposition1, ...]
    target_maturity: TargetLevel
    legacy_fact_context_digest: str | None
    local_constraint_digests: tuple[str, ...]
    signature: RuleChainV3Signature
    profile_digest: str

    schema_version: ClassVar[str] = PROJECT_PROFILE_V3_SCHEMA_VERSION
    object_kind: ClassVar[str] = "project-profile"

    @staticmethod
    def body(
        *,
        project_id: str,
        profile_id: str,
        selector_scope_digest: str,
        selected_packs: tuple[PackSelectionV3, ...],
        corpus_acceptance_digest: str,
        mandatory_rule_ids: tuple[str, ...],
        rule_dispositions: tuple[ProfileRuleDisposition1, ...],
        target_maturity: TargetLevel,
        legacy_fact_context_digest: str | None,
        local_constraint_digests: tuple[str, ...],
        budget: PolicyReadBudget1,
    ) -> dict[str, object]:
        """Derive the full unsigned selection, preserving explicit selected-pack order.

        Parameters
        ----------
        project_id, profile_id, selector_scope_digest, corpus_acceptance_digest : str
            Exact project, selector scope and whole-corpus identities.
        selected_packs : tuple[PackSelectionV3, ...]
            Nonempty ordered exact child selections with unique pack IDs.
        mandatory_rule_ids, rule_dispositions : tuple
            Sorted unique mandatory identities and complete declared rule dispositions.
        target_maturity : TargetLevel
            Original maturity vocabulary, subject to separate source authority.
        legacy_fact_context_digest : str or None
            Exact actual legacy fact-context identity when required by selected conditions.
        local_constraint_digests : tuple[str, ...]
            Sorted unique exact local constraints, without implicit waivers.
        budget : PolicyReadBudget1
            Explicit complete array, reference, byte and nesting bounds.

        Returns
        -------
        dict[str, object]
            Exact unsigned profile. Completeness against actual sources requires the owner.
        """
        limits = checked_policy_budget(budget)
        if (
            type(selected_packs) is not tuple
            or not selected_packs
            or len(selected_packs) > limits.max_references
            or type(rule_dispositions) is not tuple
            or len(rule_dispositions) > limits.max_rules
        ):
            raise ValueError("profile3 requires bounded immutable complete selections")
        if any(type(row) is not PackSelectionV3 for row in selected_packs) or any(
            type(row) is not ProfileRuleDisposition1 for row in rule_dispositions
        ):
            raise ValueError("profile3 requires actual versioned selection and disposition owners")
        packs = [row.to_dict(budget=limits) for row in selected_packs]
        pack_ids = [row.pack_id for row in selected_packs]
        if len(pack_ids) != len(set(pack_ids)):
            raise ValueError("profile3 cannot select a pack twice")
        corpus = require_digest(corpus_acceptance_digest, "profile3 whole corpus acceptance")
        if any(
            row.pack_format == "3.0" and row.corpus_acceptance_digest != corpus
            for row in selected_packs
        ):
            raise ValueError("profile3 and every new pack must bind the same complete corpus")
        mandatory = policy_identifiers(mandatory_rule_ids, budget=limits)
        dispositions = [row.to_dict(budget=limits) for row in rule_dispositions]
        rule_ids = [row.rule_id for row in rule_dispositions]
        if rule_ids != sorted(set(rule_ids)):
            raise ValueError("profile3 rule dispositions must be sorted and unique")
        included = {row.rule_id for row in rule_dispositions if row.disposition == "included"}
        if not set(mandatory).issubset(included):
            raise ValueError("profile3 cannot omit or exclude a declared mandatory floor")
        if (
            type(local_constraint_digests) is not tuple
            or len(local_constraint_digests) > limits.max_references
        ):
            raise ValueError("profile3 constraints require a bounded immutable tuple")
        constraints = tuple(
            require_digest(row, "profile3 local constraint") for row in local_constraint_digests
        )
        if constraints != tuple(sorted(set(constraints))):
            raise ValueError("profile3 constraints must be sorted and unique")
        count = 5 * len(selected_packs) + len(mandatory) + len(constraints)
        count += sum(1 + (row.decision_id is not None) for row in rule_dispositions)
        if count > limits.max_references:
            raise ValueError("profile3 exceeds the aggregate reference budget")
        maturity = require_string(target_maturity, "profile3 target maturity")
        if maturity not in TARGET_LEVEL_ORDER:
            raise ValueError("unsupported profile3 target maturity")
        body: dict[str, object] = {
            "schema_version": PROJECT_PROFILE_V3_SCHEMA_VERSION,
            "object_kind": "project-profile",
            "project_id": require_identifier(project_id, "profile3 project identity"),
            "profile_id": require_identifier(profile_id, "profile3 identity"),
            "selector_scope_digest": require_digest(
                selector_scope_digest, "profile3 selector scope"
            ),
            "selected_packs": packs,
            "corpus_acceptance_digest": corpus,
            "mandatory_rule_ids": list(mandatory),
            "rule_dispositions": dispositions,
            "target_maturity": maturity,
            "legacy_fact_context_digest": None
            if legacy_fact_context_digest is None
            else require_digest(legacy_fact_context_digest, "profile3 legacy fact context"),
            "local_constraint_digests": list(constraints),
        }
        policy_wire_size(body, budget=limits)
        return body

    def unsigned_body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Return every exact selection field after direct-object and whole-bound checks."""
        return self.body(
            project_id=self.project_id,
            profile_id=self.profile_id,
            selector_scope_digest=self.selector_scope_digest,
            selected_packs=self.selected_packs,
            corpus_acceptance_digest=self.corpus_acceptance_digest,
            mandatory_rule_ids=self.mandatory_rule_ids,
            rule_dispositions=self.rule_dispositions,
            target_maturity=self.target_maturity,
            legacy_fact_context_digest=self.legacy_fact_context_digest,
            local_constraint_digests=self.local_constraint_digests,
            budget=budget,
        )

    def _signed_body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Bind only actual new profile signature metadata to the entire unsigned body."""
        body = self.unsigned_body(budget=budget)
        if type(self.signature) is not RuleChainV3Signature:
            raise ValueError("profile3 requires an actual version3 signature")
        signature = RuleChainV3Signature.from_dict(
            self.signature.to_dict(budget=budget), budget=budget
        )
        if signature.object_kind != "project-profile" or signature.body_digest != canonical_digest(
            body
        ):
            raise ValueError("profile3 signature metadata differs from its complete body")
        return {**body, "signature": signature.to_dict(budget=budget)}

    @classmethod
    def build(
        cls,
        *,
        project_id: str,
        profile_id: str,
        selector_scope_digest: str,
        selected_packs: tuple[PackSelectionV3, ...],
        corpus_acceptance_digest: str,
        mandatory_rule_ids: tuple[str, ...],
        rule_dispositions: tuple[ProfileRuleDisposition1, ...],
        target_maturity: TargetLevel,
        legacy_fact_context_digest: str | None,
        local_constraint_digests: tuple[str, ...],
        signature: RuleChainV3Signature,
        budget: PolicyReadBudget1,
    ) -> ProjectProfileV3:
        """Hash the complete selection and supplied signature without accepting source authority."""
        candidate = cls(
            project_id,
            profile_id,
            selector_scope_digest,
            selected_packs,
            corpus_acceptance_digest,
            mandatory_rule_ids,
            rule_dispositions,
            target_maturity,
            legacy_fact_context_digest,
            local_constraint_digests,
            signature,
            "0" * 64,
        )
        result = replace(
            candidate, profile_digest=canonical_digest(candidate._signed_body(budget=budget))
        )
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Serialize the exact signed parent3 after revalidating its full digest and bounds."""
        body = self._signed_body(budget=budget)
        digest = require_digest(self.profile_digest, "profile3 digest")
        if digest != canonical_digest(body):
            raise ValueError("profile3 digest differs")
        result = {**body, "profile_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> ProjectProfileV3:
        """Parse closed parent3 fields without legacy coercion or any provider installation."""
        limits = checked_policy_budget(budget)
        data = policy_record_mapping(
            value,
            fields=_PROFILE_FIELDS,
            object_kind="project-profile",
            schema_version=PROJECT_PROFILE_V3_SCHEMA_VERSION,
            budget=limits,
        )
        arrays: dict[str, list[object]] = {}
        for name in (
            "selected_packs",
            "mandatory_rule_ids",
            "rule_dispositions",
            "local_constraint_digests",
        ):
            rows = data[name]
            if type(rows) is not list or len(rows) > limits.max_references:
                raise ValueError("profile3 requires bounded complete arrays")
            arrays[name] = rows
        result = cls(
            require_identifier(data["project_id"], "profile3 project identity"),
            require_identifier(data["profile_id"], "profile3 identity"),
            require_digest(data["selector_scope_digest"], "profile3 selector scope"),
            tuple(
                PackSelectionV3.from_dict(row, budget=limits) for row in arrays["selected_packs"]
            ),
            require_digest(data["corpus_acceptance_digest"], "profile3 whole corpus acceptance"),
            tuple(
                require_identifier(row, "profile3 mandatory rule")
                for row in arrays["mandatory_rule_ids"]
            ),
            tuple(
                ProfileRuleDisposition1.from_dict(row, budget=limits)
                for row in arrays["rule_dispositions"]
            ),
            cast(TargetLevel, require_string(data["target_maturity"], "profile3 target maturity")),
            None
            if data["legacy_fact_context_digest"] is None
            else require_digest(
                data["legacy_fact_context_digest"], "profile3 legacy fact context"
            ),
            tuple(
                require_digest(row, "profile3 local constraint")
                for row in arrays["local_constraint_digests"]
            ),
            RuleChainV3Signature.from_dict(data["signature"], budget=limits),
            require_digest(data["profile_digest"], "profile3 digest"),
        )
        result.to_dict(budget=limits)
        return result
