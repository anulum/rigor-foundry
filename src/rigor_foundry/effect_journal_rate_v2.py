# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual effect-journal rate contexts
"""Read historical operation intents for each actual selected Stage B part."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import cast

from .adapter_operations_v2 import AdapterOperationsV2
from .constraint_evaluators_v2 import EvaluatorContextV2, RateContextV2, RateIntentV2
from .effect_journal_records_v2 import parse_effect_target_ref_v2
from .effect_journal_state_v2 import replay_effect_journal_v2
from .effect_journal_v2 import EffectJournalLeaseV2
from .effect_target_render_v2 import render_target_v2
from .effect_target_table_v2 import EffectTargetTableV2
from .project_registry_primitives import project_registry_strict_json
from .selected_clause_semantics_host_v2 import HostSelectedClauseSemanticsStateV2
from .selected_dispatch_extraction_v2 import ExtractedDispatchPartV2
from .selected_rule_chain_host_v2 import HostSelectedRuleChainStateV2


@dataclass(frozen=True)
class EffectJournalRateSourceV2:
    """Installed journal source bound by the common evaluator to each actual part.

    Parameters
    ----------
    journal
        Actual retained exclusive store lease, rescanned for every rate clause.
    history_started_at
        Independently established UTC start of complete retained history. The
        journal header and its first record cannot establish this timestamp.
    clock
        Installed fresh UTC host clock; request time never selects the window.
    honoured_closure_digests
        Separately verified anchor closures for complete semantic journal replay.
        Closure changes require a new source under the same retained transaction.
    catalogue_for
        Retained original selected chain for each historical operation catalogue
        digest. Missing history refuses; current catalogue does not replace it.
    other_context_for
        Explicit installed source for non-rate constraints.

    Notes
    -----
    Construction, a cooperative file owner and a returned context establish no
    protected custody, native ingress, physical pin or effect permission. This
    source reads the effect journal, never the permit-consumption ledger.
    """

    journal: EffectJournalLeaseV2
    history_started_at: datetime
    clock: Callable[[], datetime]
    honoured_closure_digests: frozenset[str]
    other_context_for: Callable[[str, str], EvaluatorContextV2]
    catalogue_for: Callable[[str], HostSelectedRuleChainStateV2]

    def __call__(self, clause_digest: str, subject: str) -> EvaluatorContextV2:
        """Delegate other subjects and refuse a rate read without an actual part.

        Parameters
        ----------
        clause_digest, subject
            Selected clause identity and requested fixed constraint subject.

        Returns
        -------
        EvaluatorContextV2
            Actual context returned by the installed non-rate evidence reader.

        Raises
        ------
        PermissionError
            A rate context was requested before binding an extracted part.
        """
        if subject == "rate":
            raise PermissionError("effect journal rate source requires an extracted part")
        return self.other_context_for(clause_digest, subject)

    def for_part(
        self, selected: HostSelectedClauseSemanticsStateV2, part: ExtractedDispatchPartV2
    ) -> Callable[[str, str], EvaluatorContextV2]:
        """Bind signed rate parameters and the actual extracted class and target.

        Parameters
        ----------
        selected, part
            Same retained selected semantics and independently extracted part
            used by the common Stage B evaluator, never request declarations.

        Returns
        -------
        Callable[[str, str], EvaluatorContextV2]
            Fresh contexts for this part and exact selected clause digests.

        Raises
        ------
        ValueError
            The supplied target cannot be canonically rendered.

        Notes
        -----
        The returned reader revalidates actual history and catalogue data on
        each call. Binding itself authenticates neither the part nor custody.
        """
        entries = cast(list[dict[str, object]], selected.signed.body.to_dict()["entries"])
        target = render_target_v2(part.target_ref, part.target_kind)

        def context_for(clause_digest: str, subject: str) -> EvaluatorContextV2:
            """Read a fresh complete journal for the exact selected rate clause.

            Parameters
            ----------
            clause_digest, subject
                Exact bound rate clause, or a subject delegated to the installed reader.

            Returns
            -------
            EvaluatorContextV2
                Fresh retained-history rate context or delegated non-rate context.

            Raises
            ------
            PermissionError, ValueError, OSError
                Clause binding, UTC times, journal consistency, replay or the
                intent's original catalogue refuses or cannot be read.
            """
            if subject != "rate":
                return self(clause_digest, subject)
            matches = [
                entry
                for entry in entries
                if entry["clause_digest"] == clause_digest and entry["subject"] == "rate"
            ]
            if len(matches) != 1 or matches[0]["effect_class"] != part.effect_class:
                raise PermissionError("effect journal rate clause differs from selected part")
            params = cast(dict[str, object], matches[0]["params"])
            seconds = params["window_seconds"]
            if type(seconds) is not int or not 1 <= seconds <= 604_800:
                raise PermissionError("effect journal rate window is invalid")
            now = self.clock()
            origin = self.history_started_at
            if any(
                value.tzinfo is None or value.utcoffset() != timedelta(0)
                for value in (now, origin)
            ):
                raise PermissionError("effect journal rate clock or history origin is not UTC")
            snapshot = self.journal.verified_snapshot()
            replay_effect_journal_v2(
                snapshot, honoured_closure_digests=self.honoured_closure_digests
            )
            intents: list[RateIntentV2] = []
            for record in snapshot.records:
                host_time = datetime.fromisoformat(record.host_time.replace("Z", "+00:00"))
                if host_time < origin or host_time > now:
                    raise PermissionError(
                        "effect journal record time lies outside retained history"
                    )
                if record.kind != "operation-intent":
                    continue
                parts = self._operation_parts(record.body)
                for recorded_part in parts:
                    if recorded_part[
                        "effect_class"
                    ] == part.effect_class and parse_effect_target_ref_v2(
                        recorded_part["target_ref"]
                    ) == (part.target_form, part.target_value):
                        intents.append(RateIntentV2(part.effect_class, target, host_time))
            return RateContextV2(
                now,
                part.effect_class,
                target,
                tuple(intents),
                origin <= now - timedelta(seconds=seconds),
            )

        return context_for

    def _operation_parts(self, body: dict[str, object]) -> list[dict[str, object]]:
        """Compare each retained intent with its exact original reviewed catalogue."""
        digest = cast(str, body["adapter_operations_digest"])
        chain = self.catalogue_for(digest)
        operations = AdapterOperationsV2.from_bytes(
            chain.effect_operations.body_bytes,
            vocabulary=chain.effect_vocabulary,
            target_table=chain.effect_target_table,
            extractors=chain.extractor_registry,
        )
        if operations != chain.effect_operations or operations.operations_digest != digest:
            raise PermissionError("effect journal original catalogue digest differs")
        table = EffectTargetTableV2.from_bytes(chain.effect_target_table.body_bytes)
        catalogue = cast(dict[str, object], project_registry_strict_json(operations.body_bytes))
        matches = [
            operation
            for operation in cast(list[dict[str, object]], catalogue["operations"])
            if operation["operation_id"] == body["operation_key"]
        ]
        if len(matches) != 1:
            raise PermissionError("effect journal operation is absent from original catalogue")
        registered = matches[0]
        expected = cast(list[dict[str, object]], registered["parts"])
        parts = cast(list[dict[str, object]], body["parts"])
        if registered["atomicity"] != body["atomicity"] or len(parts) != len(expected):
            raise PermissionError("effect journal operation shape differs from original catalogue")
        for actual, declared in zip(parts, expected, strict=True):
            form, _value = parse_effect_target_ref_v2(actual["target_ref"])
            if (
                actual["index"] != declared["index"]
                or actual["effect_class"] != declared["effect_class"]
                or not table.allows(
                    cast(str, declared["effect_class"]), cast(str, declared["target_kind"]), form
                )
                or actual["operation_variant"] != "replace-or-create"
            ):
                raise PermissionError("effect journal part differs from original catalogue")
        return parts
