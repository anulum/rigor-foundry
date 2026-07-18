# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — machine-verifiable candidate anchors
"""Bind audit candidates to exact Git objects and bounded line spans."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal, cast

from .audit_primitives import (
    Category,
    Confidence,
    _integer,
    _mapping,
    _sha256,
    _string,
    require_string,
)
from .git_inventory import GitInventory, TrackedFile
from .rules import RULES_BY_ID

ANCHOR_SCHEMA_VERSION = "1.0"
MAX_CANDIDATE_EXCERPT_BYTES = 512

_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_BASE_ANCHOR_FIELDS = {"schema_version", "kind", "path", "line_start", "line_end"}
_BLOB_ANCHOR_FIELDS = _BASE_ANCHOR_FIELDS | {"blob_oid", "content_sha256"}
_TREE_ANCHOR_FIELDS = _BASE_ANCHOR_FIELDS | {"tree_oid", "tracked_content_sha256"}
_CANDIDATE_FIELDS = {
    "candidate_id",
    "category",
    "rule_id",
    "anchor",
    "symbol",
    "evidence",
    "confidence",
    "rationale",
    "verification",
}


def _repository_path(value: object, field: str, *, allow_root: bool) -> str:
    """Return one canonical POSIX repository-relative path."""
    path = _string(value, field)
    pure = PurePosixPath(path)
    if "\\" in path or pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"{field} must be a canonical repository-relative POSIX path")
    if path != pure.as_posix() or (path == "." and not allow_root):
        raise ValueError(f"{field} must be a canonical repository-relative POSIX path")
    return path


def _object_id(value: object, field: str) -> str:
    """Return one validated SHA-1 or SHA-256 Git object identifier."""
    result = _string(value, field)
    if _OBJECT_ID.fullmatch(result) is None:
        raise ValueError(f"{field} must be a lowercase Git object identifier")
    return result


def _sha256_digest(value: object, field: str) -> str:
    """Return one exact SHA-256 content identity."""
    result = _string(value, field)
    if _SHA256.fullmatch(result) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return result


def _line_count(item: TrackedFile) -> int:
    """Return the addressable line count for one tracked object."""
    if item.text is None:
        return 1
    return max(1, len(item.text.splitlines()))


def _validate_span(line_start: int, line_end: int) -> None:
    """Reject non-positive or reversed inclusive line spans."""
    _integer(line_start, "anchor.line_start", minimum=1)
    _integer(line_end, "anchor.line_end", minimum=line_start)


def _utf8_prefix(value: str, byte_limit: int) -> str:
    """Return the longest valid UTF-8 prefix within ``byte_limit`` bytes."""
    return value.encode("utf-8")[:byte_limit].decode("utf-8", errors="ignore")


def bounded_candidate_evidence(label: str, values: tuple[str, ...]) -> str:
    """Summarise a deterministic value sequence within the evidence byte cap.

    Parameters
    ----------
    label:
        Short description of the values.
    values:
        Deterministically ordered values represented by the evidence.

    Returns
    -------
    str
        Count, SHA-256 identity, and either the complete sequence or a bounded
        prefix marked as truncated.

    Raises
    ------
    ValueError
        If the label or a sequence value is empty, or the fixed identity fields
        leave no room for a value prefix.
    """
    clean_label = " ".join(require_string(label, "candidate.evidence.label").split())
    clean_values = tuple(
        " ".join(require_string(value, "candidate.evidence.value").split()) for value in values
    )
    encoded_values = json.dumps(
        clean_values,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    identity = hashlib.sha256(encoded_values).hexdigest()
    joined = ", ".join(clean_values)
    header = f"{clean_label}: count={len(clean_values)}; sha256={identity}; values="
    complete = header + (joined or "none")
    if len(complete.encode("utf-8")) <= MAX_CANDIDATE_EXCERPT_BYTES:
        return complete
    suffix = "; truncated=true"
    byte_limit = (
        MAX_CANDIDATE_EXCERPT_BYTES - len(header.encode("utf-8")) - len(suffix.encode("utf-8"))
    )
    if byte_limit < 1:
        raise ValueError("candidate evidence identity leaves no room for a value prefix")
    return header + _utf8_prefix(joined, byte_limit) + suffix


@dataclass(frozen=True)
class TrackedBlobAnchor:
    """Exact scanned Git blob and inclusive repository line span."""

    path: str
    line_start: int
    line_end: int
    blob_oid: str
    content_sha256: str
    kind: Literal["tracked-blob"] = "tracked-blob"

    def __post_init__(self) -> None:
        """Reject malformed direct construction."""
        self._validate()

    @classmethod
    def build(
        cls,
        item: TrackedFile,
        *,
        line_start: int,
        line_end: int | None = None,
    ) -> TrackedBlobAnchor:
        """Build an anchor for the exact bytes inspected by a scanner."""
        if item.scanned_blob_id is None:
            raise ValueError("tracked path has no scanned blob content")
        final_line = line_start if line_end is None else line_end
        anchor = cls(
            path=item.path,
            line_start=line_start,
            line_end=final_line,
            blob_oid=item.scanned_blob_id,
            content_sha256=item.content_digest,
        )
        if final_line > _line_count(item):
            raise ValueError("anchor line span exceeds the tracked blob")
        return anchor

    def _validate(self) -> None:
        """Reject malformed blob anchors."""
        _repository_path(self.path, "anchor.path", allow_root=False)
        _validate_span(self.line_start, self.line_end)
        _object_id(self.blob_oid, "anchor.blob_oid")
        _sha256_digest(self.content_sha256, "anchor.content_sha256")

    def errors(self, inventory: GitInventory) -> tuple[str, ...]:
        """Return divergence from one exact inventory."""
        matches = tuple(item for item in inventory.files if item.path == self.path)
        if len(matches) != 1:
            return ("tracked blob path must occur exactly once in the inventory",)
        item = matches[0]
        errors: list[str] = []
        if item.scanned_blob_id is None:
            errors.append("tracked path has no scanned blob")
        elif self.blob_oid != item.scanned_blob_id:
            errors.append("blob object id does not match the scanned bytes")
        if self.content_sha256 != item.content_digest:
            errors.append("blob content digest does not match the scanned bytes")
        if self.line_end > _line_count(item):
            errors.append("blob line span exceeds the scanned object")
        if len(self.blob_oid) != (40 if inventory.object_format == "sha1" else 64):
            errors.append("blob object id does not match the repository object format")
        return tuple(errors)

    def to_dict(self) -> dict[str, object]:
        """Serialise a strict tracked-blob anchor."""
        return {
            "schema_version": ANCHOR_SCHEMA_VERSION,
            "kind": self.kind,
            "path": self.path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "blob_oid": self.blob_oid,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True)
class RepositoryTreeAnchor:
    """Exact tree state supporting an absence or repository-wide candidate."""

    path: str
    line_start: int
    line_end: int
    tree_oid: str
    tracked_content_sha256: str
    kind: Literal["repository-tree"] = "repository-tree"

    def __post_init__(self) -> None:
        """Reject malformed direct construction."""
        self._validate()

    @classmethod
    def build(
        cls,
        inventory: GitInventory,
        *,
        path: str,
    ) -> RepositoryTreeAnchor:
        """Build a repository-state locus without fabricating a blob."""
        anchor = cls(
            path=path,
            line_start=1,
            line_end=1,
            tree_oid=inventory.head_tree,
            tracked_content_sha256=inventory.tracked_content_digest,
        )
        return anchor

    def _validate(self) -> None:
        """Reject malformed tree anchors."""
        _repository_path(self.path, "anchor.path", allow_root=True)
        _validate_span(self.line_start, self.line_end)
        if (self.line_start, self.line_end) != (1, 1):
            raise ValueError("repository-tree anchor uses the fixed 1:1 state locus")
        _object_id(self.tree_oid, "anchor.tree_oid")
        _sha256_digest(
            self.tracked_content_sha256,
            "anchor.tracked_content_sha256",
        )

    def errors(self, inventory: GitInventory) -> tuple[str, ...]:
        """Return divergence from one exact inventory."""
        errors: list[str] = []
        if self.tree_oid != inventory.head_tree:
            errors.append("repository tree object does not match the inventory")
        if self.tracked_content_sha256 != inventory.tracked_content_digest:
            errors.append("repository content digest does not match the inventory")
        if len(self.tree_oid) != (40 if inventory.object_format == "sha1" else 64):
            errors.append("tree object id does not match the repository object format")
        return tuple(errors)

    def to_dict(self) -> dict[str, object]:
        """Serialise a strict repository-tree anchor."""
        return {
            "schema_version": ANCHOR_SCHEMA_VERSION,
            "kind": self.kind,
            "path": self.path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "tree_oid": self.tree_oid,
            "tracked_content_sha256": self.tracked_content_sha256,
        }


CandidateAnchor = TrackedBlobAnchor | RepositoryTreeAnchor


def candidate_anchor_from_dict(value: object) -> CandidateAnchor:
    """Parse one strict discriminated candidate anchor."""
    data = _mapping(value, "candidate.anchor")
    if data.get("schema_version") != ANCHOR_SCHEMA_VERSION:
        raise ValueError("unsupported candidate-anchor schema version")
    kind = _string(data.get("kind"), "anchor.kind")
    anchor: CandidateAnchor
    if kind == "tracked-blob":
        if set(data) != _BLOB_ANCHOR_FIELDS:
            raise ValueError("tracked-blob anchor fields do not match the schema")
        anchor = TrackedBlobAnchor(
            path=_repository_path(data.get("path"), "anchor.path", allow_root=False),
            line_start=_integer(data.get("line_start"), "anchor.line_start", minimum=1),
            line_end=_integer(data.get("line_end"), "anchor.line_end", minimum=1),
            blob_oid=_object_id(data.get("blob_oid"), "anchor.blob_oid"),
            content_sha256=_sha256_digest(
                data.get("content_sha256"),
                "anchor.content_sha256",
            ),
        )
    elif kind == "repository-tree":
        if set(data) != _TREE_ANCHOR_FIELDS:
            raise ValueError("repository-tree anchor fields do not match the schema")
        anchor = RepositoryTreeAnchor(
            path=_repository_path(data.get("path"), "anchor.path", allow_root=True),
            line_start=_integer(data.get("line_start"), "anchor.line_start", minimum=1),
            line_end=_integer(data.get("line_end"), "anchor.line_end", minimum=1),
            tree_oid=_object_id(data.get("tree_oid"), "anchor.tree_oid"),
            tracked_content_sha256=_sha256_digest(
                data.get("tracked_content_sha256"),
                "anchor.tracked_content_sha256",
            ),
        )
    else:
        raise ValueError("anchor.kind is unsupported")
    return anchor


@dataclass(frozen=True)
class Candidate:
    """One anchored static signal that requires evidence review."""

    candidate_id: str
    category: Category
    rule_id: str
    anchor: CandidateAnchor
    symbol: str
    evidence: str
    confidence: Confidence
    rationale: str
    verification: str

    @property
    def path(self) -> str:
        """Return the anchored repository-relative locus."""
        return self.anchor.path

    @property
    def line(self) -> int:
        """Return the first line in the anchored inclusive span."""
        return self.anchor.line_start

    @classmethod
    def build(
        cls,
        *,
        category: Category,
        rule_id: str,
        anchor: CandidateAnchor,
        symbol: str,
        evidence: str,
        confidence: Confidence,
        rationale: str,
        verification: str,
    ) -> Candidate:
        """Build a candidate whose identifier binds its complete anchor."""
        excerpt = " ".join(require_string(evidence, "candidate.evidence").split())
        if len(excerpt.encode("utf-8")) > MAX_CANDIDATE_EXCERPT_BYTES:
            raise ValueError(
                f"candidate.evidence must not exceed {MAX_CANDIDATE_EXCERPT_BYTES} UTF-8 bytes"
            )
        definition = RULES_BY_ID.get(rule_id)
        if definition is None:
            raise ValueError(f"unregistered audit rule: {rule_id}")
        if definition.category != category:
            raise ValueError(f"audit rule {rule_id} does not belong to {category}")
        fields = {
            "category": category,
            "rule_id": rule_id,
            "anchor": anchor.to_dict(),
            "symbol": symbol,
            "evidence": excerpt,
            "confidence": confidence,
            "rationale": rationale,
            "verification": verification,
        }
        return cls(
            candidate_id=_sha256(fields),
            category=category,
            rule_id=rule_id,
            anchor=anchor,
            symbol=symbol,
            evidence=excerpt,
            confidence=confidence,
            rationale=rationale,
            verification=verification,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the candidate and its machine-verifiable anchor."""
        return {
            "candidate_id": self.candidate_id,
            "category": self.category,
            "rule_id": self.rule_id,
            "anchor": self.anchor.to_dict(),
            "symbol": self.symbol,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "verification": self.verification,
        }

    @classmethod
    def from_dict(cls, value: object) -> Candidate:
        """Parse a candidate and verify its content-derived identifier."""
        data = _mapping(value, "candidate")
        if set(data) != _CANDIDATE_FIELDS:
            raise ValueError("candidate fields do not match the schema")
        category = _string(data.get("category"), "candidate.category")
        confidence = _string(data.get("confidence"), "candidate.confidence")
        if category not in {
            "test-authenticity",
            "architecture",
            "godfile",
            "governance",
            "application-security",
            "reliability",
            "supply-chain",
            "container",
            "data-privacy",
        }:
            raise ValueError("candidate.category is unsupported")
        if confidence not in {"low", "medium", "high"}:
            raise ValueError("candidate.confidence is unsupported")
        candidate = cls.build(
            category=cast(Category, category),
            rule_id=_string(data.get("rule_id"), "candidate.rule_id"),
            anchor=candidate_anchor_from_dict(data.get("anchor")),
            symbol=_string(data.get("symbol", ""), "candidate.symbol", allow_empty=True),
            evidence=_string(data.get("evidence"), "candidate.evidence"),
            confidence=cast(Confidence, confidence),
            rationale=_string(data.get("rationale"), "candidate.rationale"),
            verification=_string(data.get("verification"), "candidate.verification"),
        )
        recorded_id = _string(data.get("candidate_id"), "candidate.candidate_id")
        if candidate.candidate_id != recorded_id:
            raise ValueError("candidate identifier does not match its content")
        return candidate


def candidate_anchor_errors(
    inventory: GitInventory,
    candidates: tuple[Candidate, ...],
) -> tuple[str, ...]:
    """Return indexed anchor divergence for a candidate collection."""
    errors: list[str] = []
    for index, candidate in enumerate(candidates):
        errors.extend(
            f"candidates[{index}]: {error}" for error in candidate.anchor.errors(inventory)
        )
    return tuple(errors)


def candidate_object_format_errors(
    object_format: str,
    candidates: tuple[Candidate, ...],
) -> tuple[str, ...]:
    """Return anchor identifiers that contradict a declared Git object format."""
    if object_format not in {"sha1", "sha256"}:
        return ("report object format is unsupported",)
    expected_length = 40 if object_format == "sha1" else 64
    errors: list[str] = []
    for index, candidate in enumerate(candidates):
        object_id = (
            candidate.anchor.blob_oid
            if isinstance(candidate.anchor, TrackedBlobAnchor)
            else candidate.anchor.tree_oid
        )
        if len(object_id) != expected_length:
            errors.append(
                f"candidates[{index}]: anchor object id length contradicts object format"
            )
    return tuple(errors)
