# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact project-memory source content binding
"""Verify complete immutable source bytes, without fetching or admitting them.

Digest equality proves byte identity, not authentic capture, current source
freshness, semantic support, sensitivity or permission. The service must obtain
sources through its separately trusted capture and admission policy. Locators
are metadata here, never executable instructions, filesystem paths or URLs to fetch.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from .project_memory_models import ProjectMemoryManifest
from .project_memory_primitives import (
    PROJECT_MEMORY_MAX_RECORDS,
    PROJECT_MEMORY_MAX_SOURCES,
    ProjectMemorySource,
)


def verify_project_memory_sources(
    manifest: ProjectMemoryManifest,
    source_contents: Mapping[tuple[str, str, str], bytes],
    *,
    max_source_bytes: int,
) -> tuple[tuple[ProjectMemorySource, bytes], ...]:
    """Bind every record source to exact already-captured immutable bytes.

    Keys are complete (source_id, locator, sha256) triples. Shared exact sources
    are retained once; different snapshots sharing an ID or locator are not
    collapsed. Missing/extra references, mutable bytes, excess counts/bytes or
    mismatching hashes raise ValueError with no source details in the message.
    Returned pairs are sorted immutable data, not an admission certificate.

    ``max_source_bytes`` is an explicit positive exact integer bounded by2**53-1
    and counts every distinct referenced snapshot, including equal bytes under
    different metadata. Empty source files are valid when their hash matches.
    No I/O, network retrieval, implicit source refresh or sensitivity scan occurs.
    """
    if type(max_source_bytes) is not int or not 0 < max_source_bytes <= 2**53 - 1:
        raise ValueError("source budget must be a positive exact integer")
    if len(source_contents) > PROJECT_MEMORY_MAX_RECORDS * PROJECT_MEMORY_MAX_SOURCES:
        raise ValueError("source content count exceeds model limits")
    manifest = ProjectMemoryManifest.from_bytes(manifest.to_bytes())
    expected = {
        (source.source_id, source.locator, source.sha256): source
        for record in manifest.records
        for source in record.sources
    }
    supplied = dict(source_contents)
    if set(supplied) != set(expected):
        raise ValueError("source content must match every exact manifest reference")
    if any(type(payload) is not bytes for payload in supplied.values()):
        raise ValueError("source content requires immutable bytes")
    if sum(len(payload) for payload in supplied.values()) > max_source_bytes:
        raise ValueError("source content exceeds its byte budget")
    for key, payload in supplied.items():
        if hashlib.sha256(payload).hexdigest() != key[2]:
            raise ValueError("source content digest mismatch")
    return tuple((expected[key], supplied[key]) for key in sorted(expected))
