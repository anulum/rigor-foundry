# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — retained context source lifetime
"""Retain actual selected source descriptors through use and closing validation."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from types import TracebackType
from typing import cast
from uuid import uuid4

from .audit_primitives import canonical_digest
from .context_source_resolution import ContextSourceTarget, parse_context_source_target
from .git_inventory import open_directory_no_follow, read_stable_regular_file_at
from .model_primitives import require_digest
from .policy_read_budget import PolicyReadBudget1
from .policy_source_reads import parse_policy_document_payload
from .project_registry_models import ProjectRegistry
from .typed_object_reference import TypedObjectRef1


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Bind object identity and all stability fields used by the underlying reader."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class RetainedContextSource:
    """One source selected by trusted host composition, never reconstructed from wire.

    The caller must already own access and independently select path/reference/raw
    digest. This concrete reader retains a file and parent directory descriptor,
    checks actual data with its fixed parser, and revalidates before use/close.
    It grants no task, event, claim, effect or installation authority.
    """

    def __init__(
        self, path: Path, *, reference: TypedObjectRef1, raw_digest: str, budget: PolicyReadBudget1
    ) -> None:
        """Open an exact canonical source selection and retain its actual descriptors."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        self._budget = PolicyReadBudget1.from_dict(budget.to_dict())
        if type(reference) is not TypedObjectRef1:
            raise ValueError("typed context source reference is required")
        self._reference = TypedObjectRef1.from_dict(reference.to_dict())
        self._raw_digest = require_digest(raw_digest, "selected source byte digest")
        self._path = path.absolute()
        self._parent = -1
        self._file = -1
        self._closed = False
        try:
            self._parent = open_directory_no_follow(self._path.parent)
            self._file = os.open(
                self._path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._parent
            )
            metadata = os.fstat(self._file)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("context source must be a single-link regular file")
            self._file_identity = _identity(metadata)
            self._parent_identity = _identity(os.fstat(self._parent))
            self._selection_id = uuid4().hex
            self._snapshot_id = canonical_digest(
                {
                    "selection_id": self._selection_id,
                    "path": str(self._path),
                    "reference": self._reference.to_dict(),
                    "raw_digest": self._raw_digest,
                    "file_identity": list(self._file_identity),
                    "parent_identity": list(self._parent_identity),
                }
            )
            self.read()
        except BaseException:
            self._release()
            raise

    @property
    def snapshot_id(self) -> str:
        """Return the identity of this actual retained selection after revalidation."""
        self._check_identity()
        return self._snapshot_id

    @property
    def reference(self) -> TypedObjectRef1:
        """Return a revalidated inert reference to this retained source."""
        self._check_identity()
        return TypedObjectRef1.from_dict(self._reference.to_dict())

    def _check_identity(self) -> None:
        """Refuse closed, replaced, edited or aliased source/parent identities."""
        if self._closed:
            raise ValueError("context source lease is closed")
        parent = open_directory_no_follow(self._path.parent)
        try:
            if (
                _identity(os.fstat(parent)) != self._parent_identity
                or _identity(os.fstat(self._parent)) != self._parent_identity
            ):
                raise ValueError("context source directory identity changed")
            if (
                _identity(os.fstat(self._file)) != self._file_identity
                or _identity(os.stat(self._path.name, dir_fd=parent, follow_symlinks=False))
                != self._file_identity
            ):
                raise ValueError("context source file identity changed")
        finally:
            os.close(parent)

    def read(self) -> ContextSourceTarget:
        """Revalidate retained identity, bounded original bytes and the actual owning parser."""
        self._check_identity()
        payload = read_stable_regular_file_at(
            self._parent,
            self._path.name,
            str(self._path),
            buffer_limit=self._budget.max_document_bytes,
            maximum_bytes=self._budget.max_document_bytes,
            require_single_link=True,
        ).payload
        # Equal buffer/read ceilings retain all bytes of a successful stable read.
        payload = cast(bytes, payload)
        self._check_identity()
        if hashlib.sha256(payload).hexdigest() != self._raw_digest:
            raise ValueError("context source byte digest differs from installed selection")
        value = parse_policy_document_payload(payload, budget=self._budget)
        target = parse_context_source_target(self._reference, value, budget=self._budget)
        if isinstance(target, ProjectRegistry) and target.to_bytes() != payload:
            raise ValueError("selected registry bytes are not canonical")
        self._check_identity()
        return target

    def _release(self) -> None:
        """Release owned descriptors exactly once, including a failed constructor."""
        for name in ("_file", "_parent"):
            descriptor = getattr(self, name)
            if descriptor != -1:
                os.close(descriptor)
                setattr(self, name, -1)
        self._closed = True

    def close(self) -> None:
        """Perform a final complete read/check and release even when closing refuses."""
        if self._closed:
            return
        try:
            self.read()
        finally:
            self._release()

    def __enter__(self) -> RetainedContextSource:
        """Validate this concrete selection before entering its held lifetime."""
        self._check_identity()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Check the same source at the closing boundary and release all owned handles."""
        self.close()
