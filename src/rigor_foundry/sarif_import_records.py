# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded records of imported third-party SARIF rules and results
"""Keep what a third-party SARIF result says, bounded and digested, never adjudicated.

An imported result keeps the producer's own words: its level, kind, baseline state,
suppressions, fingerprints and properties are recorded verbatim within fixed bounds, and
what does not fit is kept by digest. Nothing is mapped onto RigorFoundry severity,
confidence or category, and every imported candidate stays ``unreviewed``. Every result
field follows the one rule of ``sarif_import_bounds``: absent takes the SARIF default, and
present but mistyped, ``null`` included, skips the result.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Final, cast

from .audit_primitives import canonical_digest
from .candidate_anchor import TrackedBlobAnchor, candidate_anchor_from_dict
from .sarif_import_bounds import ResultSkipped, bounded_text, bounded_value, present_field
from .sarif_import_rules import RunRules, ToolComponent, imported_rule_id, require_producer_id

IMPORT_STATE: Final = "unreviewed"
CANDIDATE_KINDS: Final = frozenset({"fail", "open", "review"})
OBSERVATION_KINDS: Final = frozenset({"pass", "notApplicable", "informational"})
MAX_MESSAGE_BYTES: Final = 8 * 1024
MAX_PROPERTIES_BYTES: Final = 16 * 1024
MAX_FINGERPRINT_BYTES: Final = 4 * 1024
MAX_SNIPPET_BYTES: Final = 2 * 1024
MAX_CONTEXT_REGION_BYTES: Final = 4 * 1024


def _suppression(item: object) -> tuple[str | None, str | None]:
    """Return one suppression's status and kind, skipping the result if either is mistyped."""
    if not isinstance(item, dict):
        raise ResultSkipped("malformed-suppressions")
    return (
        present_field(item, "status", str, "malformed-suppressions", None),
        present_field(item, "kind", str, "malformed-suppressions", None),
    )


@dataclass(frozen=True)
class PreservedResult:
    """What one producer result says, kept verbatim within bounds and by digest beyond them."""

    run_index: int
    result_index: int
    rule_id: str
    rule_index: int | None
    tool_component_index: int | None
    tool_component: ToolComponent
    message_text: str
    message_text_sha256: str
    message_truncated: bool
    level: str | None
    kind: str
    baseline_state: str | None
    suppressions: tuple[tuple[str | None, str | None], ...]
    partial_fingerprints: dict[str, object] | None
    partial_fingerprints_sha256: str
    fingerprints: dict[str, object] | None
    fingerprints_sha256: str
    properties: dict[str, object] | None
    properties_sha256: str
    properties_truncated: bool
    result_object_sha256: str

    @classmethod
    def build(
        cls,
        producer_id: str,
        result: dict[str, Any],
        rules: RunRules,
        *,
        run_index: int,
        result_index: int,
    ) -> PreservedResult:
        """Record one result object of a run, resolving its rule by id or index.

        Parameters
        ----------
        producer_id : str
            The declared producer slug.
        result : dict[str, Any]
            One ``runs[].results`` entry, verbatim.
        rules : RunRules
            The run's recorded rules, per tool component.
        run_index : int
            The run's position in the file.
        result_index : int
            The result's position in its run.

        Returns
        -------
        PreservedResult
            The bounded record.

        Raises
        ------
        ResultSkipped
            With ``result-without-rule`` if no rule id (``ruleId`` or ``rule.id``) and no rule
            index (``ruleIndex`` or ``rule.index``) is given, ``rule-index-out-of-range`` if the
            index names no rule, ``rule-id-index-mismatch`` if an id and an index disagree,
            ``rule-id-mismatch`` or ``rule-index-mismatch`` if the result-level and the
            ``rule`` reference forms disagree, ``unresolvable-tool-component`` if
            ``rule.toolComponent`` gives no index, ``tool-component-out-of-range`` if the
            index names no extension, ``missing-message`` if the result has no
            message text, ``unknown-kind`` if the kind is neither a candidate nor an
            observation kind, or ``malformed-<field>`` if a present field is mistyped, an
            explicit ``null`` included. An absent kind is SARIF's default ``fail``.
        """
        reference = present_field(result, "rule", dict, "malformed-rule-reference", {})
        index = present_field(result, "ruleIndex", int, "malformed-rule-reference", None)
        referenced_index = present_field(reference, "index", int, "malformed-rule-reference", None)
        if isinstance(index, bool) or isinstance(referenced_index, bool):
            raise ResultSkipped("malformed-rule-reference")
        # SARIF's default index -1 means that no index is given.
        index, referenced_index = (
            None if item == -1 else item for item in (index, referenced_index)
        )
        if None not in (index, referenced_index) and index != referenced_index:
            raise ResultSkipped("rule-index-mismatch")
        index = referenced_index if index is None else index
        component_reference = present_field(
            reference, "toolComponent", dict, "malformed-rule-reference", None
        )
        component = None
        if component_reference is not None:
            component = present_field(
                component_reference, "index", int, "malformed-rule-reference", -1
            )
            if isinstance(component, bool):
                raise ResultSkipped("malformed-rule-reference")
            if component == -1:
                # A component named only by name or guid cannot be matched to one extension.
                raise ResultSkipped("unresolvable-tool-component")
        source = present_field(result, "ruleId", str, "malformed-rule-id", None)
        referenced = present_field(reference, "id", str, "malformed-rule-id", None)
        if "" in (source, referenced):
            raise ResultSkipped("malformed-rule-id")
        if None not in (source, referenced) and source != referenced:
            raise ResultSkipped("rule-id-mismatch")
        source = referenced if source is None else source
        tool_component = rules.component(component).component
        indexed = None if index is None else rules.resolve(component, index)
        if source is not None:
            rule_id = imported_rule_id(producer_id, source)
            if indexed is not None and indexed.rule_id != rule_id:
                raise ResultSkipped("rule-id-index-mismatch")
        elif indexed is not None:
            rule_id = indexed.rule_id
        else:
            raise ResultSkipped("result-without-rule")
        message = result.get("message")
        full_text = message.get("text") if isinstance(message, dict) else None
        if not isinstance(full_text, str):
            raise ResultSkipped("missing-message")
        text, truncated = bounded_text(full_text, MAX_MESSAGE_BYTES)
        kind = present_field(result, "kind", str, "malformed-kind", "fail")
        if kind not in CANDIDATE_KINDS | OBSERVATION_KINDS:
            raise ResultSkipped("unknown-kind")
        level = present_field(result, "level", str, "malformed-level", None)
        baseline = present_field(result, "baselineState", str, "malformed-baseline-state", None)
        suppressions = tuple(
            _suppression(item)
            for item in present_field(result, "suppressions", list, "malformed-suppressions", [])
        )
        partial, partial_digest, _ = bounded_value(
            present_field(result, "partialFingerprints", dict, "malformed-fingerprints", {}),
            MAX_FINGERPRINT_BYTES,
        )
        fingerprints, fingerprints_digest, _ = bounded_value(
            present_field(result, "fingerprints", dict, "malformed-fingerprints", {}),
            MAX_FINGERPRINT_BYTES,
        )
        properties, properties_digest, properties_cut = bounded_value(
            present_field(result, "properties", dict, "malformed-properties", {}),
            MAX_PROPERTIES_BYTES,
        )
        return cls(
            run_index=run_index,
            result_index=result_index,
            rule_id=rule_id,
            rule_index=index,
            tool_component_index=component,
            tool_component=tool_component,
            message_text=text,
            message_text_sha256=hashlib.sha256(full_text.encode("utf-8")).hexdigest(),
            message_truncated=truncated,
            level=level,
            kind=kind,
            baseline_state=baseline,
            suppressions=suppressions,
            partial_fingerprints=cast(dict[str, object], partial)
            if isinstance(partial, dict)
            else None,
            partial_fingerprints_sha256=partial_digest,
            fingerprints=cast(dict[str, object], fingerprints)
            if isinstance(fingerprints, dict)
            else None,
            fingerprints_sha256=fingerprints_digest,
            properties=cast(dict[str, object], properties)
            if isinstance(properties, dict)
            else None,
            properties_sha256=properties_digest,
            properties_truncated=properties_cut,
            result_object_sha256=canonical_digest(result),
        )

    @property
    def is_candidate_kind(self) -> bool:
        """Return whether the producer's kind makes this result a candidate, not an observation."""
        return self.kind in CANDIDATE_KINDS

    def to_dict(self) -> dict[str, object]:
        """Serialise the preserved result."""
        return {
            "run_index": self.run_index,
            "result_index": self.result_index,
            "rule_id": self.rule_id,
            "rule_index": self.rule_index,
            "tool_component_index": self.tool_component_index,
            "tool_component": self.tool_component.to_dict(),
            "message_text": self.message_text,
            "message_text_sha256": self.message_text_sha256,
            "message_truncated": self.message_truncated,
            "level": self.level,
            "kind": self.kind,
            "baseline_state": self.baseline_state,
            "suppressions": [
                {"status": status, "kind": kind} for status, kind in self.suppressions
            ],
            "partial_fingerprints": self.partial_fingerprints,
            "partial_fingerprints_sha256": self.partial_fingerprints_sha256,
            "fingerprints": self.fingerprints,
            "fingerprints_sha256": self.fingerprints_sha256,
            "properties": self.properties,
            "properties_sha256": self.properties_sha256,
            "properties_truncated": self.properties_truncated,
            "result_object_sha256": self.result_object_sha256,
        }


@dataclass(frozen=True)
class LocationMetadata:
    """Where within its anchored lines a result points: kept beside the anchor, never in it."""

    start_column: int | None
    end_column: int | None
    snippet: dict[str, object] | None
    snippet_sha256: str | None
    snippet_truncated: bool
    context_region: dict[str, object] | None
    context_region_sha256: str | None
    context_region_truncated: bool
    location_count: int

    def to_dict(self) -> dict[str, object]:
        """Serialise the location metadata."""
        return {
            "start_column": self.start_column,
            "end_column": self.end_column,
            "snippet": self.snippet,
            "snippet_sha256": self.snippet_sha256,
            "snippet_truncated": self.snippet_truncated,
            "context_region": self.context_region,
            "context_region_sha256": self.context_region_sha256,
            "context_region_truncated": self.context_region_truncated,
            "location_count": self.location_count,
        }


@dataclass(frozen=True)
class ImportedCandidate:
    """One anchored third-party finding, kept as an ``unreviewed`` candidate and never judged."""

    candidate_id: str
    producer_id: str
    anchor: TrackedBlobAnchor
    location: LocationMetadata
    result: PreservedResult
    state: str = IMPORT_STATE

    @classmethod
    def build(
        cls,
        producer_id: str,
        anchor: TrackedBlobAnchor,
        result: PreservedResult,
        location: LocationMetadata,
    ) -> ImportedCandidate:
        """Bind one candidate kind result to its tracked-blob anchor.

        Parameters
        ----------
        producer_id : str
            The declared producer slug.
        anchor : TrackedBlobAnchor
            The exact tracked blob span the result names.
        result : PreservedResult
            The preserved result of a candidate kind.
        location : LocationMetadata
            Columns, snippet and context region, which stay outside the identity.

        Returns
        -------
        ImportedCandidate
            The candidate, identified by producer, rule, the rule's tool component name and
            version (never its position), anchor, message digest and the canonical digest of
            the partial fingerprints, which sorts their keys and covers them even when they
            exceed the bound; the producer's own ``fingerprints`` are data only.

        Raises
        ------
        ValueError
            If the result's kind makes it an observation instead.
        """
        if not result.is_candidate_kind:
            raise ValueError(f"a {result.kind} result is an observation, not a candidate")
        identity = {
            "producer_id": require_producer_id(producer_id),
            "rule_id": result.rule_id,
            "tool_component": result.tool_component.to_dict(),
            "anchor": anchor.to_dict(),
            "message_text_sha256": result.message_text_sha256,
            "partial_fingerprints_sha256": result.partial_fingerprints_sha256,
        }
        return cls(canonical_digest(identity), producer_id, anchor, location, result)

    def to_dict(self) -> dict[str, object]:
        """Serialise the candidate."""
        return {
            "candidate_id": self.candidate_id,
            "producer_id": self.producer_id,
            "state": self.state,
            "anchor": self.anchor.to_dict(),
            "location": self.location.to_dict(),
            "result": self.result.to_dict(),
        }


@dataclass(frozen=True)
class ImportObservation:
    """A producer result kept without a candidate: a non-finding kind or no tracked location."""

    producer_id: str
    reason: str
    result: PreservedResult

    def to_dict(self) -> dict[str, object]:
        """Serialise the observation."""
        return {
            "producer_id": self.producer_id,
            "reason": self.reason,
            "result": self.result.to_dict(),
        }


@dataclass(frozen=True)
class ImportSkip:
    """A producer result that could not be recorded, by position and reason code."""

    run_index: int
    result_index: int
    reason: str

    def to_dict(self) -> dict[str, object]:
        """Serialise the skip."""
        return {
            "run_index": self.run_index,
            "result_index": self.result_index,
            "reason": self.reason,
        }


def anchor_from_record(value: object) -> TrackedBlobAnchor:
    """Return the tracked-blob anchor of a serialised imported candidate.

    Parameters
    ----------
    value : object
        A serialised anchor.

    Returns
    -------
    TrackedBlobAnchor
        The parsed anchor.

    Raises
    ------
    ValueError
        If the anchor is malformed or not a tracked-blob anchor.
    """
    anchor = candidate_anchor_from_dict(value)
    if not isinstance(anchor, TrackedBlobAnchor):
        raise ValueError("an imported candidate anchors only to a tracked blob")
    return anchor
