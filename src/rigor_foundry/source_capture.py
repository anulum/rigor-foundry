# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — external-source capture provenance
"""Record bounded retrieval policy and exact retained-payload identity."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_integer,
    require_mapping,
    require_string,
)
from .git_inventory import open_directory_no_follow, read_stable_regular_file_at
from .model_primitives import (
    require_boolean,
    require_digest,
    require_identifier,
    require_nonempty_strings,
    require_semantic_version,
    require_utc_timestamp,
)

SOURCE_PROVENANCE_SCHEMA_VERSION = "1.0"
MAX_SOURCE_BYTES = 32 * 1024 * 1024

_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "allowed_hosts",
        "allow_cross_origin_redirects",
        "maximum_redirects",
        "timeout_seconds",
        "maximum_bytes",
        "allowed_media_types",
        "freshness_seconds",
        "policy_digest",
    }
)
_CAPTURE_FIELDS = frozenset(
    {
        "schema_version",
        "requested_uri",
        "final_uri",
        "redirect_count",
        "http_status",
        "media_type",
        "retrieved_at",
        "payload_size",
        "payload_digest",
        "retrieval_policy",
        "retrieval_policy_digest",
        "retriever_name",
        "retriever_version",
        "retriever_executable_digest",
        "capture_digest",
    }
)
_DNS_NAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


def require_media_type(value: object, field: str) -> str:
    """Return a lowercase media type without parameters."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    if (
        value != value.lower()
        or ";" in value
        or "/" not in value
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase media type without parameters")
    return value


def require_https_uri(value: object, field: str) -> str:
    """Return a bounded canonical HTTPS URI without credentials or fragments."""
    text = require_string(value, field)
    if len(text) > 2048 or any(not 33 <= ord(character) <= 126 for character in text):
        raise ValueError(f"{field} must be a bounded printable-ASCII HTTPS URI")
    if not text.startswith("https://") or "#" in text:
        raise ValueError(f"{field} must be a canonical HTTPS URI without credentials or fragment")
    remainder = text.removeprefix("https://")
    authority = remainder.split("/", maxsplit=1)[0].split("?", maxsplit=1)[0]
    if "@" in authority:
        raise ValueError(f"{field} must be a canonical HTTPS URI without credentials or fragment")
    if ":" in authority:
        raise ValueError(f"{field} has an invalid port")
    if (
        _DNS_NAME.fullmatch(authority) is None
        or authority != authority.lower()
        or all(label.isdigit() for label in authority.split("."))
    ):
        raise ValueError(f"{field} must be a canonical HTTPS URI without credentials or fragment")
    suffix = remainder[len(authority) :]
    path = suffix.split("?", maxsplit=1)[0]
    if re.search(r"%(?![0-9A-Fa-f]{2})", path):
        raise ValueError(f"{field} contains invalid percent encoding")
    decoded_dots = re.sub(r"%2e", ".", path, flags=re.IGNORECASE)
    if any(part in {".", ".."} for part in decoded_dots.split("/")):
        raise ValueError(f"{field} must not contain dot path segments")
    return text


def _source_host(uri: str) -> str:
    """Return the already-validated lowercase host of one HTTPS URI."""
    return uri.removeprefix("https://").split("/", maxsplit=1)[0].split("?", maxsplit=1)[0]


@dataclass(frozen=True, init=False)
class SourceRetrievalPolicy:
    """Explicit authority, transport, size, media, and freshness constraints."""

    allowed_hosts: tuple[str, ...]
    allow_cross_origin_redirects: bool
    maximum_redirects: int
    timeout_seconds: int
    maximum_bytes: int
    allowed_media_types: tuple[str, ...]
    freshness_seconds: int
    policy_digest: str

    @classmethod
    def build(
        cls,
        *,
        allowed_hosts: tuple[str, ...],
        allow_cross_origin_redirects: bool,
        maximum_redirects: int,
        timeout_seconds: int,
        maximum_bytes: int,
        allowed_media_types: tuple[str, ...],
        freshness_seconds: int,
    ) -> SourceRetrievalPolicy:
        """Build a deterministic retrieval policy."""
        hosts = require_nonempty_strings(
            list(allowed_hosts),
            "source retrieval policy.allowed_hosts",
            minimum=1,
        )
        if hosts != tuple(sorted(set(hosts))) or any(
            _DNS_NAME.fullmatch(host) is None or all(label.isdigit() for label in host.split("."))
            for host in hosts
        ):
            raise ValueError("source retrieval policy hosts must be sorted unique DNS names")
        media_types = tuple(
            require_media_type(item, "source retrieval policy.allowed_media_types")
            for item in require_nonempty_strings(
                list(allowed_media_types),
                "source retrieval policy.allowed_media_types",
                minimum=1,
            )
        )
        if media_types != tuple(sorted(set(media_types))):
            raise ValueError("source retrieval policy media types must be sorted and unique")
        redirects = require_integer(maximum_redirects, "source retrieval policy.maximum_redirects")
        if redirects > 10:
            raise ValueError("source retrieval policy.maximum_redirects must be <= 10")
        fields: dict[str, object] = {
            "schema_version": SOURCE_PROVENANCE_SCHEMA_VERSION,
            "allowed_hosts": list(hosts),
            "allow_cross_origin_redirects": require_boolean(
                allow_cross_origin_redirects,
                "source retrieval policy.allow_cross_origin_redirects",
            ),
            "maximum_redirects": redirects,
            "timeout_seconds": require_integer(
                timeout_seconds,
                "source retrieval policy.timeout_seconds",
                minimum=1,
            ),
            "maximum_bytes": require_integer(
                maximum_bytes,
                "source retrieval policy.maximum_bytes",
                minimum=1,
            ),
            "allowed_media_types": list(media_types),
            "freshness_seconds": require_integer(
                freshness_seconds,
                "source retrieval policy.freshness_seconds",
                minimum=1,
            ),
        }
        if cast(int, fields["maximum_bytes"]) > MAX_SOURCE_BYTES:
            raise ValueError(
                f"source retrieval policy.maximum_bytes must be <= {MAX_SOURCE_BYTES}"
            )
        policy = object.__new__(cls)
        object.__setattr__(policy, "allowed_hosts", hosts)
        object.__setattr__(
            policy,
            "allow_cross_origin_redirects",
            cast(bool, fields["allow_cross_origin_redirects"]),
        )
        object.__setattr__(policy, "maximum_redirects", redirects)
        object.__setattr__(policy, "timeout_seconds", cast(int, fields["timeout_seconds"]))
        object.__setattr__(policy, "maximum_bytes", cast(int, fields["maximum_bytes"]))
        object.__setattr__(policy, "allowed_media_types", media_types)
        object.__setattr__(policy, "freshness_seconds", cast(int, fields["freshness_seconds"]))
        object.__setattr__(policy, "policy_digest", canonical_digest(fields))
        return policy

    def to_dict(self) -> dict[str, object]:
        """Serialise the retrieval policy."""
        return {
            "schema_version": SOURCE_PROVENANCE_SCHEMA_VERSION,
            "allowed_hosts": list(self.allowed_hosts),
            "allow_cross_origin_redirects": self.allow_cross_origin_redirects,
            "maximum_redirects": self.maximum_redirects,
            "timeout_seconds": self.timeout_seconds,
            "maximum_bytes": self.maximum_bytes,
            "allowed_media_types": list(self.allowed_media_types),
            "freshness_seconds": self.freshness_seconds,
            "policy_digest": self.policy_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> SourceRetrievalPolicy:
        """Parse and integrity-check a retrieval policy."""
        data = require_mapping(value, "source retrieval policy")
        require_exact_fields(data, _POLICY_FIELDS, "source retrieval policy")
        if data.get("schema_version") != SOURCE_PROVENANCE_SCHEMA_VERSION:
            raise ValueError("unsupported source-provenance schema version")
        policy = cls.build(
            allowed_hosts=require_nonempty_strings(
                data.get("allowed_hosts"),
                "source retrieval policy.allowed_hosts",
                minimum=1,
            ),
            allow_cross_origin_redirects=require_boolean(
                data.get("allow_cross_origin_redirects"),
                "source retrieval policy.allow_cross_origin_redirects",
            ),
            maximum_redirects=require_integer(
                data.get("maximum_redirects"),
                "source retrieval policy.maximum_redirects",
            ),
            timeout_seconds=require_integer(
                data.get("timeout_seconds"),
                "source retrieval policy.timeout_seconds",
                minimum=1,
            ),
            maximum_bytes=require_integer(
                data.get("maximum_bytes"),
                "source retrieval policy.maximum_bytes",
                minimum=1,
            ),
            allowed_media_types=require_nonempty_strings(
                data.get("allowed_media_types"),
                "source retrieval policy.allowed_media_types",
                minimum=1,
            ),
            freshness_seconds=require_integer(
                data.get("freshness_seconds"),
                "source retrieval policy.freshness_seconds",
                minimum=1,
            ),
        )
        if data.get("policy_digest") != policy.policy_digest:
            raise ValueError("source retrieval policy digest does not match its content")
        return policy


def _capture_fields(
    *,
    requested_uri: str,
    final_uri: str,
    redirect_count: int,
    http_status: int,
    media_type: str,
    retrieved_at: str,
    payload_size: int,
    payload_digest: str,
    retrieval_policy: SourceRetrievalPolicy,
    retriever_name: str,
    retriever_version: str,
    retriever_executable_digest: str,
) -> dict[str, object]:
    """Validate and return the canonical source-capture body."""
    policy = SourceRetrievalPolicy.from_dict(retrieval_policy.to_dict())
    requested = require_https_uri(requested_uri, "source capture.requested_uri")
    final = require_https_uri(final_uri, "source capture.final_uri")
    if (
        _source_host(requested) not in policy.allowed_hosts
        or _source_host(final) not in policy.allowed_hosts
    ):
        raise ValueError("source capture host is absent from retrieval policy")
    redirects = require_integer(redirect_count, "source capture.redirect_count")
    if redirects > policy.maximum_redirects:
        raise ValueError("source capture redirect count exceeds retrieval policy")
    if requested != final and redirects == 0:
        raise ValueError("source capture URI changed without a redirect")
    if not policy.allow_cross_origin_redirects and _source_host(requested) != _source_host(final):
        raise ValueError("source capture cross-origin redirect is forbidden")
    status = require_integer(http_status, "source capture.http_status")
    if status != 200:
        raise ValueError("source capture requires HTTP status 200")
    checked_media = require_media_type(media_type, "source capture.media_type")
    if checked_media not in policy.allowed_media_types:
        raise ValueError("source capture media type is absent from retrieval policy")
    size = require_integer(payload_size, "source capture.payload_size")
    if size > policy.maximum_bytes:
        raise ValueError("source capture payload exceeds retrieval policy")
    return {
        "schema_version": SOURCE_PROVENANCE_SCHEMA_VERSION,
        "requested_uri": requested,
        "final_uri": final,
        "redirect_count": redirects,
        "http_status": status,
        "media_type": checked_media,
        "retrieved_at": require_utc_timestamp(retrieved_at, "source capture.retrieved_at"),
        "payload_size": size,
        "payload_digest": require_digest(payload_digest, "source capture.payload_digest"),
        "retrieval_policy": policy.to_dict(),
        "retrieval_policy_digest": policy.policy_digest,
        "retriever_name": require_identifier(retriever_name, "source capture.retriever_name"),
        "retriever_version": require_semantic_version(
            retriever_version,
            "source capture.retriever_version",
        ),
        "retriever_executable_digest": require_digest(
            retriever_executable_digest,
            "source capture.retriever_executable_digest",
        ),
    }


@dataclass(frozen=True, init=False)
class SourceCapture:
    """Raw-byte identity and bounded acquisition metadata for one HTTPS response."""

    requested_uri: str
    final_uri: str
    redirect_count: int
    http_status: int
    media_type: str
    retrieved_at: str
    payload_size: int
    payload_digest: str
    retrieval_policy: SourceRetrievalPolicy
    retrieval_policy_digest: str
    retriever_name: str
    retriever_version: str
    retriever_executable_digest: str
    capture_digest: str

    @classmethod
    def record(
        cls,
        payload: bytes,
        *,
        requested_uri: str,
        final_uri: str,
        redirect_count: int,
        http_status: int,
        media_type: str,
        retrieved_at: str,
        retrieval_policy: SourceRetrievalPolicy,
        retriever_name: str,
        retriever_version: str,
        retriever_executable_digest: str,
    ) -> SourceCapture:
        """Record exact retained response bytes and caller-supplied acquisition metadata."""
        fields = _capture_fields(
            requested_uri=requested_uri,
            final_uri=final_uri,
            redirect_count=redirect_count,
            http_status=http_status,
            media_type=media_type,
            retrieved_at=retrieved_at,
            payload_size=len(payload),
            payload_digest=hashlib.sha256(payload).hexdigest(),
            retrieval_policy=retrieval_policy,
            retriever_name=retriever_name,
            retriever_version=retriever_version,
            retriever_executable_digest=retriever_executable_digest,
        )
        return cls._from_fields(fields)

    @classmethod
    def _from_fields(cls, fields: dict[str, object]) -> SourceCapture:
        """Construct one capture from its validated canonical body."""
        policy = SourceRetrievalPolicy.from_dict(fields["retrieval_policy"])
        capture = object.__new__(cls)
        for name in (
            "requested_uri",
            "final_uri",
            "redirect_count",
            "http_status",
            "media_type",
            "retrieved_at",
            "payload_size",
            "payload_digest",
            "retriever_name",
            "retriever_version",
            "retriever_executable_digest",
        ):
            object.__setattr__(capture, name, fields[name])
        object.__setattr__(capture, "retrieval_policy", policy)
        object.__setattr__(capture, "retrieval_policy_digest", policy.policy_digest)
        object.__setattr__(capture, "capture_digest", canonical_digest(fields))
        return capture

    def to_dict(self) -> dict[str, object]:
        """Serialise acquisition metadata without embedding source bytes."""
        return {**self._body(), "capture_digest": self.capture_digest}

    def _body(self) -> dict[str, object]:
        """Return the canonical content covered by ``capture_digest``."""
        return {
            "schema_version": SOURCE_PROVENANCE_SCHEMA_VERSION,
            "requested_uri": self.requested_uri,
            "final_uri": self.final_uri,
            "redirect_count": self.redirect_count,
            "http_status": self.http_status,
            "media_type": self.media_type,
            "retrieved_at": self.retrieved_at,
            "payload_size": self.payload_size,
            "payload_digest": self.payload_digest,
            "retrieval_policy": self.retrieval_policy.to_dict(),
            "retrieval_policy_digest": self.retrieval_policy_digest,
            "retriever_name": self.retriever_name,
            "retriever_version": self.retriever_version,
            "retriever_executable_digest": self.retriever_executable_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> SourceCapture:
        """Parse capture metadata and recompute every derived identity."""
        data = require_mapping(value, "source capture")
        require_exact_fields(data, _CAPTURE_FIELDS, "source capture")
        if data.get("schema_version") != SOURCE_PROVENANCE_SCHEMA_VERSION:
            raise ValueError("unsupported source-provenance schema version")
        policy = SourceRetrievalPolicy.from_dict(data.get("retrieval_policy"))
        if data.get("retrieval_policy_digest") != policy.policy_digest:
            raise ValueError("source capture retrieval-policy digest does not match")
        fields = _capture_fields(
            requested_uri=require_string(
                data.get("requested_uri"), "source capture.requested_uri"
            ),
            final_uri=require_string(data.get("final_uri"), "source capture.final_uri"),
            redirect_count=require_integer(
                data.get("redirect_count"), "source capture.redirect_count"
            ),
            http_status=require_integer(data.get("http_status"), "source capture.http_status"),
            media_type=require_string(data.get("media_type"), "source capture.media_type"),
            retrieved_at=require_utc_timestamp(
                data.get("retrieved_at"), "source capture.retrieved_at"
            ),
            payload_size=require_integer(data.get("payload_size"), "source capture.payload_size"),
            payload_digest=require_digest(
                data.get("payload_digest"), "source capture.payload_digest"
            ),
            retrieval_policy=policy,
            retriever_name=require_identifier(
                data.get("retriever_name"), "source capture.retriever_name"
            ),
            retriever_version=require_semantic_version(
                data.get("retriever_version"), "source capture.retriever_version"
            ),
            retriever_executable_digest=require_digest(
                data.get("retriever_executable_digest"),
                "source capture.retriever_executable_digest",
            ),
        )
        capture = cls._from_fields(fields)
        if data.get("capture_digest") != capture.capture_digest:
            raise ValueError("source capture digest does not match its content")
        return capture


def read_source_payload(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one single-link regular payload through no-follow descriptors."""
    limit = require_integer(maximum_bytes, "source payload maximum_bytes", minimum=1)
    if limit > MAX_SOURCE_BYTES:
        raise ValueError(f"source payload maximum_bytes must be <= {MAX_SOURCE_BYTES}")
    absolute = path.absolute()
    parent = open_directory_no_follow(absolute.parent)
    try:
        result = read_stable_regular_file_at(
            parent,
            absolute.name,
            str(absolute),
            buffer_limit=limit,
            require_single_link=True,
        )
    finally:
        os.close(parent)
    if result.payload is None:
        raise ValueError("source payload exceeds the configured byte limit")
    return result.payload
