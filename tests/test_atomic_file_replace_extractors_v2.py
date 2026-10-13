# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — first built-in extractor tests
"""Exercise exact invocation and extraction through real path observations."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.tier0_builtin import (
    extract_content_byte_count,
    extract_fixed_variant,
    extract_path_target,
)
from rigor_foundry.tier0_builtin.atomic_file_replace_extraction import (
    extract_atomic_file_replace_for_scope_v2,
    extract_atomic_file_replace_v2,
)
from rigor_foundry.tier0_builtin.atomic_file_replace_invocation import (
    MAX_ATOMIC_INVOCATION_BYTES,
    MAX_ATOMIC_PATH_BYTES,
    MAX_REPLACEMENT_CONTENT_BYTES,
    AtomicFileReplaceInvocationV2,
)
from rigor_foundry.tier0_builtin.path_admission_v2 import PinnedDirectoryV2, PinnedPathScopeV2


def _body(path: Path, content: bytes = b"new content\n") -> dict[str, object]:
    """Build the exact one-operation invocation for adversarial changes."""
    return {
        "operation_id": "local-file-write.atomic-replace",
        "path": str(path),
        "content_b64": base64.b64encode(content).decode("ascii"),
        "declared": {
            "target_ref": {"form": "path", "value": str(path)},
            "byte_count": len(content),
            "operation_variant": "replace-or-create",
        },
    }


def _payload(body: dict[str, object]) -> bytes:
    """Encode one restricted canonical invocation without aliases."""
    return json.dumps(
        body, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _observed_path(value: str) -> object:
    """Observe a test path without following a symlink in any component."""
    path = Path(value)
    parts = path.parts
    current = Path(parts[0])
    for component in parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            if current != path:
                raise PermissionError("atomic replacement parent is absent") from None
            break
        if stat.S_ISLNK(mode):
            raise PermissionError("atomic replacement symlink is forbidden")
        if current != path and not stat.S_ISDIR(mode):
            raise PermissionError("atomic replacement parent is not a directory")
        if current == path and not stat.S_ISREG(mode):
            raise PermissionError("atomic replacement target is not a regular file")
    return {"form": "path", "value": value}


def test_real_path_observation_and_all_three_extractors(tmp_path: Path) -> None:
    """Creation and replacement use the same checked values and exact content."""
    target = tmp_path / "result.txt"
    payload = _payload(_body(target))
    extracted = extract_atomic_file_replace_v2(payload, canonicalize_path=_observed_path)
    assert extracted.target_ref == {"form": "path", "value": str(target)}
    assert extracted.byte_count == len(b"new content\n")
    assert extracted.operation_variant == "replace-or-create"
    assert extracted.content == b"new content\n"
    assert (
        extract_path_target.extract(payload, canonicalize_path=_observed_path)
        == extracted.target_ref
    )
    assert extract_content_byte_count.extract(payload) == extracted.byte_count
    assert extract_fixed_variant.extract(payload) == extracted.operation_variant
    target.write_bytes(b"old content\n")
    assert extract_atomic_file_replace_v2(payload, canonicalize_path=_observed_path) == extracted


@pytest.mark.parametrize("field", ["target_ref", "byte_count", "operation_variant"])
def test_declared_values_cannot_change_extracted_decision(tmp_path: Path, field: str) -> None:
    """A caller's target, count or variant mismatch refuses before any effect."""
    body = _body(tmp_path / "result.txt")
    declared = cast(dict[str, object], body["declared"])
    replacement: object = {
        "target_ref": {"form": "path", "value": str(tmp_path / "other.txt")},
        "byte_count": 0,
        "operation_variant": "append",
    }[field]
    declared[field] = replacement
    with pytest.raises(PermissionError, match="declared values differ"):
        extract_atomic_file_replace_v2(_payload(body), canonicalize_path=_observed_path)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("operation_id", "other", "operation id"),
        ("path", "relative", "canonical absolute"),
        ("path", "/srv/../other", "canonical absolute"),
        ("path", "/srv/", "canonical absolute"),
        ("path", 7, "must be text"),
        ("content_b64", "%%%%", "base64"),
        ("content_b64", None, "standard base64"),
        ("content_b64", "YQ", "base64"),
        ("content_b64", "YQ==\n", "base64"),
        ("content_b64", "YR==", "canonical bounded base64"),
    ],
)
def test_malformed_invocation_refuses(
    tmp_path: Path, field: str, value: object, reason: str
) -> None:
    """The first operation accepts one canonical ID, path and base64 spelling."""
    body = _body(tmp_path / "result.txt")
    body[field] = value
    with pytest.raises(ValueError, match=reason):
        AtomicFileReplaceInvocationV2.from_bytes(_payload(body))


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        (
            "target_ref",
            {"form": "remote", "value": "https://example.test/file"},
            "target must be a path",
        ),
        ("byte_count", True, "byte count"),
        ("byte_count", -1, "byte count"),
        ("operation_variant", None, "variant"),
    ],
)
def test_malformed_declarations_refuse(
    tmp_path: Path, field: str, value: object, reason: str
) -> None:
    """A declaration must be closed and well-typed before comparison."""
    body = _body(tmp_path / "result.txt")
    cast(dict[str, object], body["declared"])[field] = value
    with pytest.raises(ValueError, match=reason):
        AtomicFileReplaceInvocationV2.from_bytes(_payload(body))


def test_closed_and_canonical_json_refuses(tmp_path: Path) -> None:
    """Missing, extra, duplicate and alternate whitespace bytes do not parse."""
    with pytest.raises(ValueError, match="must be bytes"):
        AtomicFileReplaceInvocationV2.from_bytes(cast(bytes, "not bytes"))
    body = _body(tmp_path / "result.txt")
    with pytest.raises(ValueError, match="fields differ"):
        AtomicFileReplaceInvocationV2.from_bytes(_payload({**body, "extra": 1}))
    body.pop("declared")
    with pytest.raises(ValueError, match="fields differ"):
        AtomicFileReplaceInvocationV2.from_bytes(_payload(body))
    with pytest.raises(ValueError, match="strict JSON"):
        AtomicFileReplaceInvocationV2.from_bytes(b'{"path":"/x","path":"/y"}')
    with pytest.raises(ValueError, match="not canonical JSON"):
        AtomicFileReplaceInvocationV2.from_bytes(b" " + _payload(_body(tmp_path / "result.txt")))
    malformed = _body(tmp_path / "result.txt")
    malformed["path"] = "/srv/\x00bad"
    with pytest.raises(ValueError, match="PCS-CANON-1"):
        AtomicFileReplaceInvocationV2.from_bytes(
            json.dumps(malformed, sort_keys=True, separators=(",", ":")).encode()
        )
    malformed = _body(tmp_path / "result.txt")
    malformed["declared"] = None
    with pytest.raises(ValueError, match="declared fields"):
        AtomicFileReplaceInvocationV2.from_bytes(_payload(malformed))


def test_real_symlink_and_directory_target_refuse(tmp_path: Path) -> None:
    """A host no-follow result never blesses a symlink or directory target."""
    target = tmp_path / "result.txt"
    target.symlink_to(tmp_path / "missing")
    with pytest.raises(PermissionError, match="symlink"):
        extract_atomic_file_replace_v2(_payload(_body(target)), canonicalize_path=_observed_path)
    with pytest.raises(PermissionError, match="regular file"):
        extract_atomic_file_replace_v2(_payload(_body(tmp_path)), canonicalize_path=_observed_path)


def test_host_canonicalizer_cannot_rebind_request_path(tmp_path: Path) -> None:
    """A changed or non-path host result refuses before declaration comparison."""
    payload = _payload(_body(tmp_path / "result.txt"))
    with pytest.raises(PermissionError, match="canonical path differs"):
        extract_path_target.extract(
            payload,
            canonicalize_path=lambda _: {"form": "path", "value": str(tmp_path / "other.txt")},
        )
    with pytest.raises(PermissionError, match="canonical path differs"):
        extract_path_target.extract(
            payload,
            canonicalize_path=lambda _: {"form": "project", "value": "RIGOR-FOUNDRY"},
        )


def test_maximum_content_bound_refuses_one_extra_byte(tmp_path: Path) -> None:
    """The 16 MiB operation boundary applies to decoded content bytes."""
    target = tmp_path / "result.txt"
    maximum = b"x" * MAX_REPLACEMENT_CONTENT_BYTES
    parsed = AtomicFileReplaceInvocationV2.from_bytes(_payload(_body(target, maximum)))
    assert len(parsed.content) == MAX_REPLACEMENT_CONTENT_BYTES
    with pytest.raises(ValueError, match="16 MiB"):
        AtomicFileReplaceInvocationV2.from_bytes(_payload(_body(target, maximum + b"x")))
    with pytest.raises(ValueError, match="16 MiB"):
        AtomicFileReplaceInvocationV2.from_bytes(_payload(_body(target, maximum + b"xxx")))


def test_total_payload_bound_refuses_before_json_parse() -> None:
    """Oversized hostile input never reaches the JSON decoder."""
    with pytest.raises(ValueError, match="invocation exceeds its byte bound"):
        AtomicFileReplaceInvocationV2.from_bytes(b"x" * (MAX_ATOMIC_INVOCATION_BYTES + 1))


def test_path_byte_bound_applies_to_both_copies(tmp_path: Path) -> None:
    """Both requested and declared paths respect the filesystem byte limit."""
    path = "/" + "x" * MAX_ATOMIC_PATH_BYTES
    body = _body(tmp_path / "result.txt")
    body["path"] = path
    with pytest.raises(ValueError, match="path exceeds PATH_MAX"):
        AtomicFileReplaceInvocationV2.from_bytes(_payload(body))
    body = _body(tmp_path / "result.txt")
    cast(dict[str, object], body["declared"])["target_ref"] = {
        "form": "path",
        "value": path,
    }
    with pytest.raises(ValueError, match="declared path exceeds PATH_MAX"):
        AtomicFileReplaceInvocationV2.from_bytes(_payload(body))


@pytest.mark.parametrize("content", [b"", b"a", b"hello\n", bytes(range(256))])
def test_invocation_json_matches_shared_canonical_encoder(tmp_path: Path, content: bytes) -> None:
    """The operation wire has the same canonical spelling as PCS-CANON-1."""
    body = _body(tmp_path / "result.txt", content)
    payload = _payload(body)
    assert payload == canonical_journal_json_v2(body)
    assert AtomicFileReplaceInvocationV2.from_bytes(payload).payload == payload


def test_canonicalizer_callback_is_not_an_admission_capability(tmp_path: Path) -> None:
    """An identity callback can bless a symlink; the binder must supply a pinned one."""
    target = tmp_path / "link.txt"
    target.symlink_to(tmp_path / "outside.txt")
    payload = _payload(_body(target))
    extracted = extract_atomic_file_replace_v2(
        payload,
        canonicalize_path=lambda value: {"form": "path", "value": value},
    )
    assert extracted.target_ref["value"] == str(target)
    with pytest.raises(PermissionError, match="symlink"):
        extract_atomic_file_replace_v2(payload, canonicalize_path=_observed_path)


def test_protected_scope_extraction_uses_descriptor_path_check(tmp_path: Path) -> None:
    """The composed extractor refuses a real symlink before returning a target."""
    mono = tmp_path / "mono"
    project = mono / "project"
    project.mkdir(parents=True)
    project_pin = PinnedDirectoryV2(str(project))
    scope = PinnedPathScopeV2(
        PinnedDirectoryV2(str(mono)),
        project_pin,
        str(project),
        (project_pin,),
        (),
    )
    target = project / "new.txt"
    payload = _payload(_body(target))
    assert extract_atomic_file_replace_for_scope_v2(payload, scope=scope).target_ref == {
        "form": "path",
        "value": str(target),
    }
    target.symlink_to(tmp_path / "outside.txt")
    with pytest.raises(PermissionError, match="extraction refused"):
        extract_atomic_file_replace_for_scope_v2(payload, scope=scope)
    with pytest.raises(PermissionError, match="extraction refused"):
        extract_atomic_file_replace_for_scope_v2(b"invalid", scope=scope)
