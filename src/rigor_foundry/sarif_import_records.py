# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded records of imported third-party SARIF rules and results
"""Keep what a third-party SARIF rule or result says, bounded and digested, never adjudicated.

An imported result keeps the producer's own words: its level, kind, baseline state,
suppressions, fingerprints and properties are recorded verbatim within fixed bounds, and
what does not fit is kept by digest. Nothing is mapped onto RigorFoundry severity,
confidence or category, and every imported candidate stays ``unreviewed``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Final, cast

from .audit_primitives import canonical_digest
from .candidate_anchor import TrackedBlobAnchor, candidate_anchor_from_dict

IMPORT_STATE: Final = "unreviewed"
CANDIDATE_KINDS: Final = frozenset({"fail", "open", "review"})
OBSERVATION_KINDS: Final = frozenset({"pass", "notApplicable", "informational"})
MAX_MESSAGE_BYTES: Final = 8 * 1024
MAX_SHORT_DESCRIPTION_BYTES: Final = 1024
MAX_PROPERTIES_BYTES: Final = 16 * 1024
MAX_FINGERPRINT_BYTES: Final = 4 * 1024
MAX_TAGS: Final = 32
MAX_TAG_BYTES: Final = 64
_PRODUCER_ID: Final = re.compile(r"[a-z][a-z0-9-]{0,31}")


class ResultSkipped(ValueError):
    """One result that cannot be recorded, with a stable reason code."""

    def __init__(self, reason: str) -> None:
        """Record the reason code.

        Parameters
        ----------
        reason : str
            Stable machine-readable skip code.
        """
        super().__init__(reason)
        self.reason = reason


def _json_bytes(value: object) -> bytes:
    """Return the canonical JSON bytes that bounds and digests are measured on."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _bounded_text(text: str, limit: int) -> tuple[str, bool]:
    """Return ``text`` cut to at most ``limit`` UTF-8 bytes and whether it was cut."""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _bounded_value(value: object, limit: int) -> tuple[object | None, str, bool]:
    """Return a JSON value kept verbatim within ``limit`` bytes, its digest and truncation."""
    digest = hashlib.sha256(_json_bytes(value)).hexdigest()
    if len(_json_bytes(value)) <= limit:
        return value, digest, False
    return None, digest, True


def require_producer_id(value: object) -> str:
    """Return one valid producer slug, the namespace of its imported rules.

    Parameters
    ----------
    value : object
        Candidate producer identifier.

    Returns
    -------
    str
        A lower-case slug such as ``codeql``.

    Raises
    ------
    ValueError
        If the value is not a lower-case slug of at most 32 characters.
    """
    if not isinstance(value, str) or _PRODUCER_ID.fullmatch(value) is None:
        raise ValueError("producer id must be a lower-case slug of at most 32 characters")
    return value


def imported_rule_id(producer_id: str, source_rule_id: str) -> str:
    """Return the separate-namespace id of one imported rule, never a RigorFoundry rule id.

    Parameters
    ----------
    producer_id : str
        The declared producer slug.
    source_rule_id : str
        The producer's own non-empty rule id.

    Returns
    -------
    str
        ``ext:<producer_id>:<source_rule_id>``.
    """
    if not source_rule_id:
        raise ValueError("an imported rule id needs the producer's rule id")
    return f"ext:{require_producer_id(producer_id)}:{source_rule_id}"


@dataclass(frozen=True)
class ImportedRule:
    """Bounded metadata of one producer rule, with a digest of the whole rule object."""

    rule_id: str
    rule_index: int
    name: str | None
    short_description: str | None
    short_description_truncated: bool
    help_uri: str | None
    help_uri_dropped: bool
    default_level: str | None
    tags: tuple[str, ...]
    tags_truncated: bool
    rule_object_sha256: str

    @classmethod
    def build(cls, producer_id: str, rule: dict[str, Any], rule_index: int) -> ImportedRule:
        """Record one rule object of a producer's driver.

        Parameters
        ----------
        producer_id : str
            The declared producer slug.
        rule : dict[str, Any]
            One ``tool.driver.rules`` entry, verbatim.
        rule_index : int
            Its position in the driver's rules.

        Returns
        -------
        ImportedRule
            The bounded record.

        Raises
        ------
        ResultSkipped
            With ``rule-without-id`` if the rule has no string id.
        """
        source = rule.get("id")
        if not isinstance(source, str) or not source:
            raise ResultSkipped("rule-without-id")
        name = rule.get("name") if isinstance(rule.get("name"), str) else None
        short = rule.get("shortDescription")
        text = short.get("text") if isinstance(short, dict) else None
        description, cut = (
            _bounded_text(text, MAX_SHORT_DESCRIPTION_BYTES)
            if isinstance(text, str)
            else (None, False)
        )
        uri = rule.get("helpUri")
        https = isinstance(uri, str) and uri.startswith("https://")
        configuration = rule.get("defaultConfiguration")
        level = configuration.get("level") if isinstance(configuration, dict) else None
        properties = rule.get("properties")
        raw_tags = properties.get("tags") if isinstance(properties, dict) else None
        offered = raw_tags if isinstance(raw_tags, list) else []
        malformed = raw_tags is not None and not isinstance(raw_tags, list)
        kept = tuple(
            tag
            for tag in offered[:MAX_TAGS]
            if isinstance(tag, str) and len(tag.encode("utf-8")) <= MAX_TAG_BYTES
        )
        return cls(
            rule_id=imported_rule_id(producer_id, source),
            rule_index=rule_index,
            name=name,
            short_description=description,
            short_description_truncated=cut,
            help_uri=cast(str, uri) if https else None,
            help_uri_dropped=uri is not None and not https,
            default_level=level if isinstance(level, str) else None,
            tags=kept,
            tags_truncated=malformed or len(kept) != len(offered),
            rule_object_sha256=canonical_digest(rule),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the rule record."""
        return {
            "rule_id": self.rule_id,
            "rule_index": self.rule_index,
            "name": self.name,
            "short_description": self.short_description,
            "short_description_truncated": self.short_description_truncated,
            "help_uri": self.help_uri,
            "help_uri_dropped": self.help_uri_dropped,
            "default_level": self.default_level,
            "tags": list(self.tags),
            "tags_truncated": self.tags_truncated,
            "rule_object_sha256": self.rule_object_sha256,
        }


@dataclass(frozen=True)
class PreservedResult:
    """What one producer result says, kept verbatim within bounds and by digest beyond them."""

    run_index: int
    result_index: int
    rule_id: str
    rule_index: int | None
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
        rules: tuple[ImportedRule, ...],
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
        rules : tuple[ImportedRule, ...]
            The run's recorded driver rules, in driver order.
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
            With ``result-without-rule`` if neither ``ruleId`` nor ``rule.index`` is given,
            ``rule-index-out-of-range`` if the index names no rule, or
            ``rule-id-index-mismatch`` if both are given and disagree.
        """
        rule_reference = result.get("rule")
        raw_index = rule_reference.get("index") if isinstance(rule_reference, dict) else None
        index = raw_index if type(raw_index) is int else None
        source = result.get("ruleId")
        if source is None and isinstance(rule_reference, dict):
            source = rule_reference.get("id")
        if index is not None and not 0 <= index < len(rules):
            raise ResultSkipped("rule-index-out-of-range")
        if isinstance(source, str) and source:
            rule_id = imported_rule_id(producer_id, source)
            if index is not None and rules[index].rule_id != rule_id:
                raise ResultSkipped("rule-id-index-mismatch")
        elif index is not None:
            rule_id = rules[index].rule_id
        else:
            raise ResultSkipped("result-without-rule")
        message = result.get("message")
        raw_text = message.get("text") if isinstance(message, dict) else None
        full_text = raw_text if isinstance(raw_text, str) else ""
        text, truncated = _bounded_text(full_text, MAX_MESSAGE_BYTES)
        kind = result.get("kind", "fail")
        level = result.get("level")
        baseline = result.get("baselineState")
        suppressions = result.get("suppressions")
        kept_suppressions = tuple(
            (
                item.get("status") if isinstance(item.get("status"), str) else None,
                item.get("kind") if isinstance(item.get("kind"), str) else None,
            )
            for item in (suppressions if isinstance(suppressions, list) else [])
            if isinstance(item, dict)
        )
        partial, partial_digest, _ = _bounded_value(
            result.get("partialFingerprints", {}), MAX_FINGERPRINT_BYTES
        )
        fingerprints, fingerprints_digest, _ = _bounded_value(
            result.get("fingerprints", {}), MAX_FINGERPRINT_BYTES
        )
        properties, properties_digest, properties_cut = _bounded_value(
            result.get("properties", {}), MAX_PROPERTIES_BYTES
        )
        return cls(
            run_index=run_index,
            result_index=result_index,
            rule_id=rule_id,
            rule_index=index,
            message_text=text,
            message_text_sha256=hashlib.sha256(full_text.encode("utf-8")).hexdigest(),
            message_truncated=truncated,
            level=level if isinstance(level, str) else None,
            kind=kind if isinstance(kind, str) else "fail",
            baseline_state=baseline if isinstance(baseline, str) else None,
            suppressions=kept_suppressions,
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
class ImportedCandidate:
    """One anchored third-party finding, kept as an ``unreviewed`` candidate and never judged."""

    candidate_id: str
    producer_id: str
    anchor: TrackedBlobAnchor
    result: PreservedResult
    state: str = IMPORT_STATE

    @classmethod
    def build(
        cls, producer_id: str, anchor: TrackedBlobAnchor, result: PreservedResult
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

        Returns
        -------
        ImportedCandidate
            The candidate, identified by producer, rule, anchor, message digest and the
            canonical digest of the partial fingerprints, which sorts their keys and covers
            them even when they exceed the bound; the producer's own ``fingerprints`` are
            data only.

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
            "anchor": anchor.to_dict(),
            "message_text_sha256": result.message_text_sha256,
            "partial_fingerprints_sha256": result.partial_fingerprints_sha256,
        }
        return cls(canonical_digest(identity), producer_id, anchor, result)

    def to_dict(self) -> dict[str, object]:
        """Serialise the candidate."""
        return {
            "candidate_id": self.candidate_id,
            "producer_id": self.producer_id,
            "state": self.state,
            "anchor": self.anchor.to_dict(),
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
