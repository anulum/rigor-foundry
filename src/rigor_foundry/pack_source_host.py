# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-selected retained pack source
"""Verify a pack source against exact host-held bytes without fetching it."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path

from .model_primitives import require_digest, require_identifier
from .models import canonical_digest, require_string
from .source_capture import MAX_SOURCE_BYTES, read_source_payload


@dataclass(frozen=True)
class HostPackSourceSelection:
    """One pack's URI, exact digest and retained local object selected by the host.

    This is an integrity-bound selection, not authority by itself. Only a
    trusted host composition may supply its expected digest to a verifier.
    """

    pack_id: str
    source_uri: str
    source_digest: str
    retained_path: Path
    selection_digest: str

    @classmethod
    def build(
        cls,
        *,
        pack_id: str,
        source_uri: str,
        source_digest: str,
        retained_path: Path,
    ) -> HostPackSourceSelection:
        """Bind source identity without treating the pack as its own selector.

        Parameters
        ----------
        pack_id : str
            Pack whose signed source claim may use this selection.
        source_uri : str
            Exact URI selected by the host; it is never fetched here.
        source_digest : str
            SHA-256 of the retained source bytes.
        retained_path : Path
            Absolute path to the host-held, single-link regular file.

        Returns
        -------
        HostPackSourceSelection
            Selection whose digest binds all four inputs.

        Raises
        ------
        ValueError
            If the URI, digest, identity or path is malformed.
        """
        if (
            not isinstance(retained_path, Path)
            or not retained_path.is_absolute()
            or ".." in retained_path.parts
        ):
            raise ValueError("retained pack source needs an absolute untraversed path")
        uri = require_string(source_uri, "pack source.source_uri")
        if any(character.isspace() for character in uri):
            raise ValueError("pack source URI must not contain whitespace")
        identity = require_identifier(pack_id, "pack source.pack_id")
        digest = require_digest(source_digest, "pack source.source_digest")
        body: dict[str, object] = {
            "schema_version": "host-pack-source.v1",
            "pack_id": identity,
            "source_uri": uri,
            "source_digest": digest,
            "retained_path": str(retained_path),
        }
        return cls(identity, uri, digest, retained_path, canonical_digest(body))


@dataclass(frozen=True)
class HostPackSourceState:
    """Selection and revocation snapshot held stable for the retained-file read.

    The state provider must keep the selection and revocation view consistent
    throughout verification. A request cannot supply its own instance.
    """

    selected: HostPackSourceSelection
    expected_selection_digest: str
    revoked_selection_digests: frozenset[str]


@dataclass(frozen=True)
class HostPackSourceVerifier:
    """Check retained bytes under a host-held lease, never caller source sets.

    The state provider must be composed by the trusted host, not supplied by a
    pack or effect request. This proves captured object identity only; remote
    mutation or revocation after the lease requires a separate current proof.

    Parameters
    ----------
    state : Callable
        Host-controlled lease over one selected source and revocation snapshot.
    """

    state: Callable[[], AbstractContextManager[HostPackSourceState]]

    def verify(self, *, pack_id: str, source_uri: str, source_digest: str) -> dict[str, object]:
        """Return an integrity proof for the currently selected retained bytes.

        Parameters
        ----------
        pack_id : str
            Exact pack identity making the source claim.
        source_uri : str
            URI signed into that pack.
        source_digest : str
            Source digest signed into that pack.

        Returns
        -------
        dict[str, object]
            Digest-bound retained-object proof, expressly non-promotable.

        Raises
        ------
        PermissionError
            If host state is absent, revoked or differs from the pack claim.
        ValueError
            If the retained bytes differ from the selected digest.
        StableReadError
            If the retained file cannot be read safely as one regular object.
        """
        proof: dict[str, object] | None = None
        with self.state() as current:
            if not isinstance(current, HostPackSourceState):
                raise PermissionError("pack source host state is unavailable")
            selected = current.selected
            checked = HostPackSourceSelection.build(
                pack_id=selected.pack_id,
                source_uri=selected.source_uri,
                source_digest=selected.source_digest,
                retained_path=selected.retained_path,
            )
            expected = require_digest(
                current.expected_selection_digest,
                "pack source host.expected_selection_digest",
            )
            for revoked in current.revoked_selection_digests:
                require_digest(revoked, "pack source host.revoked_selection_digest")
            if (
                checked != selected
                or checked.selection_digest != expected
                or expected in current.revoked_selection_digests
                or checked.pack_id != pack_id
                or checked.source_uri != source_uri
                or checked.source_digest != source_digest
            ):
                raise PermissionError("pack source differs from host selection")
            payload = read_source_payload(checked.retained_path, maximum_bytes=MAX_SOURCE_BYTES)
            if hashlib.sha256(payload).hexdigest() != checked.source_digest:
                raise ValueError("retained pack source digest differs")
            body: dict[str, object] = {
                "schema_version": "host-pack-source-verification.v1",
                "assertion_class": "retained-object-integrity-only",
                "promotable": False,
                "pack_id": checked.pack_id,
                "source_uri": checked.source_uri,
                "source_digest": checked.source_digest,
                "selection_digest": checked.selection_digest,
            }
            proof = {**body, "source_verification_digest": canonical_digest(body)}
        if proof is None:
            raise PermissionError("pack source host state suppressed verification failure")
        return proof
