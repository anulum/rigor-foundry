# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — clause semantics set body
"""Parse the closed, separately signed v2 clause-semantics body."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Final, cast

from .clause_semantics_scope_v2 import validate_clause_scope_v2
from .effect_journal_records_v2 import canonical_journal_json_v2
from .model_primitives import require_digest, require_identifier
from .project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json

_BODY_FIELDS: Final = frozenset(
    {
        "schema",
        "project_id",
        "predecessor_acceptance_digest",
        "previous_semantics_set_digest",
        "supersedes_failed_completion",
        "rule_projection_digest",
        "successor_clause_digests",
        "scope_digest",
        "effect_vocabulary_digest",
        "effect_target_table_digest",
        "evaluator_registry_digest",
        "resolver_version",
        "entries",
    }
)
_ENTRY_FIELDS: Final = frozenset(
    {"clause_digest", "statement_digest", "successor_id", "subject", "effect_class", "scope"}
)
_SCOPE_FIELDS: Final = frozenset({"schema", "targets", "exclusions"})
_EVALUATOR_FIELDS: Final = frozenset({"id"})
_RATE_FIELDS: Final = frozenset({"limit", "window_seconds", "count_basis"})
_WINDOW_FIELDS: Final = frozenset({"utc_ranges"})
_RANGE_FIELDS: Final = frozenset({"weekdays", "start", "end"})
_ROUTE_FIELDS: Final = frozenset({"provider", "account_ref", "cost_ceiling", "privacy_class"})
_PRECONDITION_FIELDS: Final = frozenset({"condition"})
_WEEKDAYS: Final = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_PROVIDER: Final = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_ACCOUNT: Final = re.compile(r"ref:[a-z0-9][a-z0-9_.:-]{0,120}\Z")
_CURRENCY: Final = re.compile(r"(?:[A-Z]{3}|0)\Z")
_AMOUNT: Final = re.compile(r"(?:0|[1-9][0-9]{0,15})(?:\.[0-9]{1,6})?\Z")
_HOUR: Final = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]\Z")
_CONDITIONS: Final = frozenset(
    {
        "verify-passed",
        "pre-commit-audit-passed",
        "repo-lease-held",
        "sha256-manifest",
        "compute-policy-limits",
    }
)


def _closed(value: object, fields: frozenset[str], label: str) -> dict[str, object]:
    """Require one object with only and all of its named fields."""
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields differ")
    return cast(dict[str, object], value)


def _text(value: object, label: str) -> str:
    """Require non-empty text after canonical JSON validation."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be non-empty text")
    return value


def _digest_or_none(value: object, label: str) -> str | None:
    """Allow only null or a lowercase SHA-256 digest."""
    return None if value is None else require_digest(value, label)


def _ordered_text(value: object, label: str, *, nonempty: bool) -> tuple[str, ...]:
    """Require byte-sorted unique text, with optional non-empty bound."""
    if not isinstance(value, list) or (nonempty and not value):
        raise ValueError(f"{label} must be an ordered array")
    items = tuple(_text(item, label) for item in cast(list[object], value))
    if items != tuple(sorted(set(items), key=lambda item: item.encode("utf-8"))):
        raise ValueError(f"{label} must be byte-sorted and unique")
    return items


def _evaluator(value: object, *, subject: str) -> None:
    """Bind the constraint to its sole fixed built-in evaluator id."""
    item = _closed(value, _EVALUATOR_FIELDS, "semantics evaluator")
    if item["id"] != f"builtin.{subject}.v2":
        raise ValueError("semantics evaluator subject differs")


def _rate(value: object) -> None:
    """Check rate limits without accepting bools as integers."""
    item = _closed(value, _RATE_FIELDS, "semantics rate")
    for name, maximum in (("limit", 10000), ("window_seconds", 604800)):
        amount = item[name]
        if type(amount) is not int or not 1 <= amount <= maximum:
            raise ValueError(f"semantics rate.{name} is outside its range")
    if item["count_basis"] != "operation-intent":
        raise ValueError("semantics rate count_basis differs")


def _window(value: object) -> None:
    """Require ordered UTC ranges with no overlap on any weekday."""
    item = _closed(value, _WINDOW_FIELDS, "semantics window")
    raw = item["utc_ranges"]
    if not isinstance(raw, list) or not raw:
        raise ValueError("semantics utc_ranges must be non-empty")
    previous_order: tuple[int, str] | None = None
    occupied: dict[str, list[tuple[str, str]]] = {day: [] for day in _WEEKDAYS}
    for value_range in cast(list[object], raw):
        interval = _closed(value_range, _RANGE_FIELDS, "semantics UTC range")
        days = interval["weekdays"]
        if not isinstance(days, list) or not days:
            raise ValueError("semantics UTC weekdays must be non-empty")
        parsed_days = tuple(_text(day, "semantics weekday") for day in days)
        if any(day not in _WEEKDAYS for day in parsed_days) or parsed_days != tuple(
            sorted(set(parsed_days), key=_WEEKDAYS.index)
        ):
            raise ValueError("semantics UTC weekdays must use calendar order")
        start = _text(interval["start"], "semantics window start")
        end = _text(interval["end"], "semantics window end")
        if _HOUR.fullmatch(start) is None or _HOUR.fullmatch(end) is None or end <= start:
            raise ValueError("semantics UTC range differs")
        order = (_WEEKDAYS.index(parsed_days[0]), start)
        if previous_order is not None and order <= previous_order:
            raise ValueError("semantics UTC ranges are not sorted")
        previous_order = order
        for day in parsed_days:
            if any(start < old_end and old_start < end for old_start, old_end in occupied[day]):
                raise ValueError("semantics UTC ranges overlap")
            occupied[day].append((start, end))


def _route(value: object) -> None:
    """Check the exact route constraint fields and decimal ceiling text."""
    item = _closed(value, _ROUTE_FIELDS, "semantics route")
    for field in ("provider", "privacy_class"):
        if _PROVIDER.fullmatch(_text(item[field], f"semantics route.{field}")) is None:
            raise ValueError(f"semantics route.{field} differs")
    if _ACCOUNT.fullmatch(_text(item["account_ref"], "semantics route.account_ref")) is None:
        raise ValueError("semantics route.account_ref differs")
    ceiling = _closed(item["cost_ceiling"], frozenset({"amount", "currency"}), "cost ceiling")
    if _AMOUNT.fullmatch(_text(ceiling["amount"], "cost ceiling amount")) is None:
        raise ValueError("semantics cost ceiling amount differs")
    if _CURRENCY.fullmatch(_text(ceiling["currency"], "cost ceiling currency")) is None:
        raise ValueError("semantics cost ceiling currency differs")


def _entry(value: object, *, project_id: str) -> str:
    """Parse a closed clause entry and return its sort key."""
    if not isinstance(value, dict):
        raise ValueError("semantics entry must be an object")
    item = cast(dict[str, object], value)
    subject = _text(item.get("subject"), "semantics subject")
    fields = _ENTRY_FIELDS
    if subject == "admit":
        fields |= frozenset({"supersedes"})
    elif subject in {"rate", "window", "route", "precondition"}:
        fields |= frozenset({"params", "evaluator"})
    elif subject != "veto":
        raise ValueError("semantics subject is unknown")
    _closed(item, fields, "semantics entry")
    digest = require_digest(item["clause_digest"], "semantics clause_digest")
    require_digest(item["statement_digest"], "semantics statement_digest")
    require_identifier(item["successor_id"], "semantics successor_id")
    require_identifier(item["effect_class"], "semantics effect_class")
    scope = _closed(item["scope"], _SCOPE_FIELDS, "semantics scope")
    if scope["schema"] != "rigor.clause-scope-selector.v2":
        raise ValueError("semantics scope schema differs")
    _ordered_text(scope["targets"], "semantics scope.targets", nonempty=True)
    _ordered_text(scope["exclusions"], "semantics scope.exclusions", nonempty=False)
    validate_clause_scope_v2(
        scope,
        subject=subject,
        effect_class=cast(str, item["effect_class"]),
        project_id=project_id,
    )
    if subject == "admit":
        for edge in _ordered_text(item["supersedes"], "semantics supersedes", nonempty=False):
            require_digest(edge, "semantics superseded clause")
    elif subject != "veto":
        _evaluator(item["evaluator"], subject=subject)
        if subject == "rate":
            _rate(item["params"])
        elif subject == "window":
            _window(item["params"])
        elif subject == "route":
            _route(item["params"])
        else:
            condition = _closed(item["params"], _PRECONDITION_FIELDS, "semantics precondition")
            if (
                _text(condition["condition"], "semantics precondition condition")
                not in _CONDITIONS
            ):
                raise ValueError("semantics precondition is unknown")
    return digest


@dataclass(frozen=True)
class ClauseSemanticsSetV2:
    """One canonical unsigned semantics body.

    Attributes
    ----------
    body_bytes : bytes
        Exact canonical UTF-8 JSON retained without mutable mappings.
    body_digest : str
        SHA-256 of those exact bytes; signatures are verified by consumers.
    """

    body_bytes: bytes
    body_digest: str

    @classmethod
    def from_bytes(cls, payload: bytes) -> ClauseSemanticsSetV2:
        """Parse the closed body without authenticating its digest references.

        Parameters
        ----------
        payload : bytes
            Canonical UTF-8 JSON with the complete v2 field set.

        Returns
        -------
        ClauseSemanticsSetV2
            Immutable original bytes and their SHA-256 digest.

        Raises
        ------
        ValueError
            Encoding, fields, scope or subject parameters violate the format.
        """
        if not isinstance(payload, bytes):
            raise ValueError("semantics body must be bytes")
        try:
            parsed = project_registry_strict_json(payload)
            if canonical_journal_json_v2(parsed) != payload:
                raise ValueError("semantics body bytes are not canonical")
        except ProjectRegistryInvalid as exc:
            raise ValueError("semantics body is not strict JSON") from exc
        body = _closed(parsed, _BODY_FIELDS, "semantics body")
        if body["schema"] != "rigor.clause-semantics-set.v2":
            raise ValueError("semantics body schema differs")
        project_id = require_identifier(body["project_id"], "semantics project_id")
        for field in (
            "predecessor_acceptance_digest",
            "rule_projection_digest",
            "scope_digest",
            "effect_vocabulary_digest",
            "effect_target_table_digest",
            "evaluator_registry_digest",
        ):
            require_digest(body[field], f"semantics {field}")
        for field in ("previous_semantics_set_digest", "supersedes_failed_completion"):
            _digest_or_none(body[field], f"semantics {field}")
        raw_successors = body["successor_clause_digests"]
        if not isinstance(raw_successors, list):
            raise ValueError("semantics successors must be an array")
        successors = tuple(
            require_digest(item, "semantics successor clause") for item in raw_successors
        )
        if len(set(successors)) != len(successors):
            raise ValueError("semantics successor clauses repeat")
        if body["resolver_version"] not in ("registry-v1-interim", "pcs-k2-v1"):
            raise ValueError("semantics resolver_version differs")
        entries = body["entries"]
        if not isinstance(entries, list):
            raise ValueError("semantics entries must be an array")
        digests = tuple(
            _entry(item, project_id=project_id) for item in cast(list[object], entries)
        )
        if digests != tuple(sorted(set(digests))):
            raise ValueError("semantics entries must be sorted and unique")
        return cls(payload, sha256(payload).hexdigest())

    def to_dict(self) -> dict[str, object]:
        """Decode the retained body into an independent mapping.

        Returns
        -------
        dict[str, object]
            Newly parsed fields; mutations do not alter the retained bytes.
        """
        return cast(dict[str, object], project_registry_strict_json(self.body_bytes))
