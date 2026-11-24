# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — tracked-only location resolution of imported SARIF results
"""Resolve the tracked blob span an imported SARIF result names, or record why it names none.

Only tracked paths are anchored. They are resolved exactly and never followed:

- a relative URI without ``uriBaseId`` resolves against the repository root;
- a relative URI with ``uriBaseId`` resolves through ``run.originalUriBaseIds`` to a base
  id that the import declares to be the repository root, or to an absolute ``file:`` base
  under the declared checkout root;
- an absolute ``file:`` URI is accepted only under the declared checkout root.

Each URI and base URI is percent-decoded exactly once. Dot segments are then removed as
RFC 3986 does, except that a ``..`` with nothing left to remove refuses the result instead
of being dropped. The resolved path must equal one tracked inventory path exactly, compared
case-sensitively, and a symbolic link is never followed. ``region.startLine`` and
``endLine`` become a ``TrackedBlobAnchor`` on the scanned blob; columns, the snippet and the
context region are metadata beside the anchor. A result without a physical artifact
location is an unanchored observation, never a candidate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Final
from urllib.parse import unquote_to_bytes

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .sarif_import_bounds import ResultSkipped, bounded_value, present_field
from .sarif_import_records import (
    MAX_CONTEXT_REGION_BYTES,
    MAX_SNIPPET_BYTES,
    ImportedCandidate,
    ImportObservation,
    ImportSkip,
    LocationMetadata,
    PreservedResult,
)
from .sarif_import_rules import RunRules

_SCHEME: Final = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):")
_DRIVE: Final = re.compile(r"[A-Za-z]:")
_FORBIDDEN: Final = re.compile(r"[\x00-\x1f\x7f\\]")


@dataclass(frozen=True)
class LocationRoots:
    """The repository root as one import declares it.

    Parameters
    ----------
    checkout_root : str
        Absolute POSIX path at which the producer saw the checkout. An absolute ``file:``
        URI is accepted only below it.
    root_base_ids : frozenset[str]
        The ``uriBaseId`` names that denote the repository root itself.
    """

    checkout_root: str
    root_base_ids: frozenset[str]

    def __post_init__(self) -> None:
        """Refuse a checkout root that is not one canonical absolute directory below ``/``."""
        path = PurePosixPath(self.checkout_root)
        canonical = path.is_absolute() and path.as_posix() == self.checkout_root
        if not canonical or self.checkout_root == "/" or ".." in path.parts:
            raise ValueError("the checkout root must be a canonical absolute POSIX path below /")
        if _FORBIDDEN.search(self.checkout_root):
            raise ValueError("the checkout root must not hold control characters or backslashes")
        if not all(isinstance(base, str) and base for base in self.root_base_ids):
            raise ValueError("every root uriBaseId must be a non-empty string")


@dataclass(frozen=True)
class ResolvedLocation:
    """The exact tracked blob span of one result and the metadata beside it."""

    anchor: TrackedBlobAnchor
    metadata: LocationMetadata


def _decoded(text: str) -> str:
    """Percent-decode one URI path exactly once, refusing what no tracked path may hold."""
    if "?" in text or "#" in text:
        raise ResultSkipped("uri-query-or-fragment")
    try:
        decoded = unquote_to_bytes(text).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ResultSkipped("invalid-percent-encoding") from error
    if _FORBIDDEN.search(decoded):
        raise ResultSkipped("forbidden-path-character")
    return decoded


def _without_dot_segments(segments: list[str]) -> list[str]:
    """Remove ``.`` and ``..`` segments as RFC 3986 does, refusing a ``..`` that climbs out."""
    kept: list[str] = []
    for segment in segments:
        if segment == "..":
            if not kept:
                raise ResultSkipped("dot-dot-segment")
            kept.pop()
        elif segment != ".":
            kept.append(segment)
    return kept


def _file_path(uri: str) -> str | None:
    """Return the decoded path of an absolute ``file:`` URI, or None for a relative one."""
    match = _SCHEME.match(uri)
    if match is None:
        return None
    if len(match.group(1)) == 1:
        raise ResultSkipped("drive-letter")
    if match.group(1).lower() != "file":
        raise ResultSkipped("unsupported-scheme")
    rest = uri[match.end() :]
    if rest.startswith("//"):
        authority, slash, path = rest[2:].partition("/")
        if authority or not slash:
            raise ResultSkipped("malformed-file-uri")
        rest = "/" + path
    elif not rest.startswith("/"):
        raise ResultSkipped("malformed-file-uri")
    return _decoded(rest)


def _reference_segments(uri: str) -> list[str]:
    """Return the decoded segments of one relative-path reference."""
    decoded = _decoded(uri)
    if decoded.startswith("/"):
        raise ResultSkipped("absolute-path-reference")
    if _DRIVE.match(decoded):
        raise ResultSkipped("drive-letter")
    return decoded.split("/")


def _metadata(physical: dict[str, Any], region: dict[str, Any], count: int) -> LocationMetadata:
    """Return columns, snippet and context region, which stay outside the anchor."""
    for key in ("startColumn", "endColumn"):
        if key in region and (type(region[key]) is not int or region[key] < 1):
            raise ResultSkipped("malformed-region")
    snippet = present_field(region, "snippet", dict, "malformed-region", None)
    context = present_field(physical, "contextRegion", dict, "malformed-region", None)
    kept_snippet, snippet_digest, snippet_cut = bounded_value(snippet, MAX_SNIPPET_BYTES)
    kept_context, context_digest, context_cut = bounded_value(context, MAX_CONTEXT_REGION_BYTES)
    return LocationMetadata(
        start_column=region.get("startColumn"),
        end_column=region.get("endColumn"),
        snippet=kept_snippet if isinstance(kept_snippet, dict) else None,
        snippet_sha256=None if snippet is None else snippet_digest,
        snippet_truncated=snippet_cut,
        context_region=kept_context if isinstance(kept_context, dict) else None,
        context_region_sha256=None if context is None else context_digest,
        context_region_truncated=context_cut,
        location_count=count,
    )


def _line_span(physical: dict[str, Any]) -> tuple[int, int, dict[str, Any]]:
    """Return the 1-based inclusive line span of a physical location and its region."""
    if "region" not in physical:
        raise ResultSkipped("no-line-region")
    region = physical["region"]
    if not isinstance(region, dict):
        raise ResultSkipped("malformed-region")
    if "startLine" not in region:
        raise ResultSkipped("no-line-region")
    start = region["startLine"]
    end = region.get("endLine", start)
    if type(start) is not int or type(end) is not int or not 1 <= start <= end:
        raise ResultSkipped("malformed-region")
    return start, end, region


@dataclass(frozen=True)
class RunLocations:
    """The location context of one run: declared roots, base URIs, artifacts, tracked files."""

    roots: LocationRoots
    files: dict[str, TrackedFile]
    dirty_paths: frozenset[str]
    bases: dict[str, Any] | None
    artifacts: list[Any] | None

    @classmethod
    def build(
        cls, run: dict[str, Any], inventory: GitInventory, roots: LocationRoots
    ) -> RunLocations:
        """Bind one run's base URIs and artifacts to one exact inventory.

        Parameters
        ----------
        run : dict[str, Any]
            One ``runs[]`` entry of a strictly parsed SARIF document.
        inventory : GitInventory
            The verified inventory of the commit being imported.
        roots : LocationRoots
            The import's declared checkout root and root base ids.

        Returns
        -------
        RunLocations
            The resolver for that run's results. A mistyped ``originalUriBaseIds`` or
            ``artifacts`` refuses each result that needs it, never the whole file.
        """
        bases = run.get("originalUriBaseIds", {})
        artifacts = run.get("artifacts", [])
        return cls(
            roots=roots,
            files={item.path: item for item in inventory.files},
            dirty_paths=frozenset(inventory.dirty_paths),
            bases=bases if isinstance(bases, dict) else None,
            artifacts=artifacts if isinstance(artifacts, list) else None,
        )

    def _under_checkout(self, path: str, outside: str) -> list[str]:
        """Return the repository segments of an absolute path under the checkout root."""
        segments = path[1:].split("/")
        if _DRIVE.match(segments[0]):
            raise ResultSkipped("drive-letter")
        kept = _without_dot_segments(segments)
        root = self.roots.checkout_root[1:].split("/")
        if kept[: len(root)] != root:
            raise ResultSkipped(outside)
        return kept[len(root) :]

    def _base_segments(self, base_id: str, seen: frozenset[str]) -> list[str]:
        """Return the repository segments that one ``uriBaseId`` denotes."""
        if base_id in self.roots.root_base_ids:
            return []
        if base_id in seen:
            raise ResultSkipped("uri-base-cycle")
        if self.bases is None:
            raise ResultSkipped("malformed-uri-base")
        if base_id not in self.bases:
            raise ResultSkipped("unknown-uri-base-id")
        entry = self.bases[base_id]
        if not isinstance(entry, dict):
            raise ResultSkipped("malformed-uri-base")
        if "uri" not in entry:
            raise ResultSkipped("base-chain-not-at-root")
        uri = entry["uri"]
        parent = present_field(entry, "uriBaseId", str, "malformed-uri-base", None)
        if not isinstance(uri, str) or not uri.endswith("/"):
            raise ResultSkipped("malformed-uri-base")
        absolute = _file_path(uri)
        if absolute is not None:
            if parent is not None:
                raise ResultSkipped("malformed-uri-base")
            return self._under_checkout(absolute[:-1], "base-chain-not-at-root")
        if parent is None:
            raise ResultSkipped("base-chain-not-at-root")
        prefix = self._base_segments(parent, seen | {base_id})
        return _without_dot_segments([*prefix, *_reference_segments(uri)[:-1]])

    def _artifact_uri(self, artifact: dict[str, Any]) -> tuple[str, str | None]:
        """Return the URI and base id an artifact location names, through ``run.artifacts``."""
        uri = present_field(artifact, "uri", str, "malformed-locations", None)
        base_id = present_field(artifact, "uriBaseId", str, "malformed-locations", None)
        index = present_field(artifact, "index", int, "malformed-locations", -1)
        if isinstance(index, bool):
            raise ResultSkipped("malformed-locations")
        # SARIF's default index -1 means that the location lists no artifact.
        if index != -1:
            if self.artifacts is None:
                raise ResultSkipped("malformed-locations")
            if not 0 <= index < len(self.artifacts):
                raise ResultSkipped("artifact-index-out-of-range")
            entry = self.artifacts[index]
            listed = entry.get("location") if isinstance(entry, dict) else None
            if not isinstance(listed, dict):
                raise ResultSkipped("malformed-locations")
            listed_uri = present_field(listed, "uri", str, "malformed-locations", None)
            listed_base = present_field(listed, "uriBaseId", str, "malformed-locations", None)
            if uri is None:
                uri, base_id = listed_uri, listed_base
            elif (uri, base_id) != (listed_uri, listed_base):
                raise ResultSkipped("artifact-index-mismatch")
        if uri is None:
            raise ResultSkipped("malformed-locations")
        return uri, base_id

    def _repository_path(self, uri: str, base_id: str | None) -> str:
        """Return the repository-relative path one URI resolves to."""
        absolute = _file_path(uri)
        if absolute is not None:
            if base_id is not None:
                raise ResultSkipped("absolute-uri-with-base")
            return "/".join(self._under_checkout(absolute, "outside-checkout-root"))
        prefix = [] if base_id is None else self._base_segments(base_id, frozenset())
        return "/".join(_without_dot_segments([*prefix, *_reference_segments(uri)]))

    def _tracked(self, path: str) -> TrackedFile:
        """Return the one tracked, clean, regular file at exactly ``path``."""
        item = self.files.get(path)
        if item is None:
            raise ResultSkipped("untracked-path")
        if path in self.dirty_paths:
            raise ResultSkipped("dirty-path")
        if item.content_kind == "symlink":
            raise ResultSkipped("symlink-path")
        if item.scanned_blob_id is None:
            raise ResultSkipped("no-scanned-blob")
        return item

    def resolve(self, result: dict[str, Any]) -> ResolvedLocation | None:
        """Resolve a result's first location to one tracked blob span.

        Parameters
        ----------
        result : dict[str, Any]
            One ``runs[].results`` entry of this run, verbatim.

        Returns
        -------
        ResolvedLocation | None
            The anchor and its metadata, or None when the result names no physical
            artifact location: no location, or only logical locations.

        Raises
        ------
        ResultSkipped
            With the reason code of the first refusal: a malformed location, an artifact
            index out of range or contradicting its URI, a refused URI or base, a path that
            is not one clean tracked regular file, no line region, or a span past the blob.
        """
        locations = present_field(result, "locations", list, "malformed-locations", [])
        if not locations:
            return None
        first = locations[0]
        if not isinstance(first, dict):
            raise ResultSkipped("malformed-locations")
        physical = present_field(first, "physicalLocation", dict, "malformed-locations", None)
        if physical is None or "artifactLocation" not in physical:
            return None
        artifact = physical["artifactLocation"]
        if not isinstance(artifact, dict):
            raise ResultSkipped("malformed-locations")
        item = self._tracked(self._repository_path(*self._artifact_uri(artifact)))
        start, end, region = _line_span(physical)
        metadata = _metadata(physical, region, len(locations))
        try:
            anchor = TrackedBlobAnchor.build(item, line_start=start, line_end=end)
        except ValueError as error:
            # The path, blob and span shape were checked above; only the span can still fail.
            raise ResultSkipped("span-outside-blob") from error
        return ResolvedLocation(anchor, metadata)


def route_result(
    producer_id: str,
    result: dict[str, Any],
    rules: RunRules,
    locations: RunLocations,
    *,
    run_index: int,
    result_index: int,
) -> ImportedCandidate | ImportObservation | ImportSkip:
    """Record one result as an anchored candidate, an observation, or a skip with its reason.

    Parameters
    ----------
    producer_id : str
        The declared producer slug.
    result : dict[str, Any]
        One ``runs[].results`` entry, verbatim.
    rules : RunRules
        The run's recorded rules, per tool component.
    locations : RunLocations
        The run's location resolver.
    run_index : int
        The run's position in the file.
    result_index : int
        The result's position in its run.

    Returns
    -------
    ImportedCandidate | ImportObservation | ImportSkip
        A candidate for a finding kind with a tracked anchor; an observation for a
        non-finding kind (reason ``kind-<kind>``) or a finding without a physical location
        (reason ``unanchored``); otherwise the skip and its reason.
    """
    try:
        preserved = PreservedResult.build(
            producer_id, result, rules, run_index=run_index, result_index=result_index
        )
        if not preserved.is_candidate_kind:
            return ImportObservation(producer_id, f"kind-{preserved.kind}", preserved)
        resolved = locations.resolve(result)
    except ResultSkipped as skipped:
        return ImportSkip(run_index, result_index, skipped.reason)
    if resolved is None:
        return ImportObservation(producer_id, "unanchored", preserved)
    return ImportedCandidate.build(producer_id, resolved.anchor, preserved, resolved.metadata)
