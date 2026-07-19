# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA protocol primitives
"""Provide strict shared primitives for offline CRA preparation records."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Literal, TypeAlias, cast

from .model_primitives import require_unique_strings
from .models import require_string

CRA_SCHEMA_VERSION = "1.0"

Track = Literal["vulnerability", "incident"]
Stage = Literal["early-warning", "notification", "final-report", "intermediate"]
EventStatus = Literal["triaged", "fixing", "fix-available", "disclosed", "closed"]
Sensitivity = Literal["normal", "sensitive"]
SuspectedCause = Literal["unlawful-or-malicious", "not-suspected", "unknown"]
SevereProng = Literal["data-or-functions", "malicious-code"]
EstablishmentBasis = Literal[
    "decisions",
    "employees",
    "auth-rep",
    "importer",
    "distributor",
    "users",
]
JsonObject: TypeAlias = dict[str, object]

TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
MEMBER_STATE_PATTERN = re.compile(r"[A-Z]{2}\Z")
STAGE_ORDER: dict[Stage, int] = {
    "early-warning": 0,
    "notification": 1,
    "final-report": 2,
    "intermediate": 3,
}
STATUS_TRANSITIONS: dict[EventStatus, frozenset[EventStatus]] = {
    "triaged": frozenset({"fixing", "fix-available", "closed"}),
    "fixing": frozenset({"fix-available", "closed"}),
    "fix-available": frozenset({"disclosed", "closed"}),
    "disclosed": frozenset({"closed"}),
    "closed": frozenset(),
}


def json_text(value: object) -> str:
    """Return deterministic, finite, human-readable JSON."""
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def require_cra_timestamp(value: object, field: str) -> str:
    """Require an exact UTC timestamp with whole-second precision."""
    text = require_string(value, field)
    if TIMESTAMP_PATTERN.fullmatch(text) is None:
        raise ValueError(f"{field} must use UTC whole seconds as YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid UTC timestamp") from exc
    return text


def parse_cra_timestamp(value: str) -> datetime:
    """Parse one already validated CRA timestamp as a UTC datetime."""
    return datetime.strptime(
        require_cra_timestamp(value, "timestamp"), "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=UTC)


def optional_timestamp(value: object, field: str) -> str | None:
    """Return an optional exact CRA timestamp."""
    return None if value is None else require_cra_timestamp(value, field)


def optional_string(value: object, field: str) -> str | None:
    """Return an optional non-empty string."""
    return None if value is None else require_string(value, field)


def require_enum(value: object, field: str, supported: frozenset[str]) -> str:
    """Require one exact member of a closed string vocabulary."""
    text = require_string(value, field)
    if text not in supported:
        raise ValueError(f"{field} is unsupported")
    return text


def require_track(value: object, field: str = "track") -> Track:
    """Require one CRA event track."""
    return cast(
        Track,
        require_enum(value, field, frozenset({"vulnerability", "incident"})),
    )


def require_stage(value: object, field: str = "stage") -> Stage:
    """Require one CRA reporting stage."""
    return cast(Stage, require_enum(value, field, frozenset(STAGE_ORDER)))


def require_status(value: object) -> EventStatus:
    """Require one supported event lifecycle state."""
    return cast(EventStatus, require_enum(value, "status", frozenset(STATUS_TRANSITIONS)))


def require_member_states(value: object) -> tuple[str, ...]:
    """Require unique uppercase alpha-2 Member State identifiers."""
    items = require_unique_strings(value, "member_states")
    if any(MEMBER_STATE_PATTERN.fullmatch(item) is None for item in items):
        raise ValueError("member_states items must be ISO-style uppercase alpha-2 codes")
    return items


def require_relative_path(value: object, field: str) -> str:
    """Require one canonical repository-relative POSIX path."""
    text = require_string(value, field)
    path = PurePosixPath(text)
    if path.is_absolute() or not path.parts or ".." in path.parts or text != path.as_posix():
        raise ValueError(f"{field} must be a canonical repository-relative path")
    return text


def record_fields(record: object) -> JsonObject:
    """Return JSON-compatible frozen-dataclass fields."""
    return {
        key: list(value) if isinstance(value, tuple) else value
        for key, value in vars(record).items()
    }
