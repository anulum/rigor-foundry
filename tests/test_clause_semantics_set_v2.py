# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — clause semantics set body tests
"""Exercise the public canonical semantics body parser with hostile wires."""

from __future__ import annotations

from copy import deepcopy
from typing import cast

import pytest

from rigor_foundry.clause_semantics_set_v2 import ClauseSemanticsSetV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.effect_target_table_v2 import EffectTargetTableV2


def _entry(number: int, subject: str) -> dict[str, object]:
    """Make one valid signed-body entry for a specific subject."""
    entry: dict[str, object] = {
        "clause_digest": f"{number:064x}",
        "statement_digest": f"{number + 16:064x}",
        "successor_id": f"successor-{number}",
        "subject": subject,
        "effect_class": "local-file-write",
        "scope": {
            "schema": "rigor.clause-scope-selector.v2",
            "targets": ["path:/tmp/rigor"],
            "exclusions": [],
        },
    }
    if subject == "admit":
        entry["supersedes"] = []
    elif subject in {"rate", "window", "route", "precondition"}:
        entry["evaluator"] = {"id": f"builtin.{subject}.v2"}
        entry["params"] = {
            "rate": {"limit": 4, "window_seconds": 60, "count_basis": "operation-intent"},
            "window": {
                "utc_ranges": [{"weekdays": ["mon", "tue"], "start": "09:00", "end": "17:00"}]
            },
            "route": {
                "provider": "local",
                "account_ref": "ref:owner.local",
                "cost_ceiling": {"amount": "0", "currency": "0"},
                "privacy_class": "internal",
            },
            "precondition": {"condition": "verify-passed"},
        }[subject]
    return entry


def _body() -> dict[str, object]:
    """Make a closed body spanning every supported subject."""
    entries = [
        _entry(index, subject)
        for index, subject in enumerate(
            ("admit", "veto", "rate", "window", "route", "precondition"), start=1
        )
    ]
    return {
        "schema": "rigor.clause-semantics-set.v2",
        "project_id": "RIGOR-FOUNDRY",
        "predecessor_acceptance_digest": "1" * 64,
        "previous_semantics_set_digest": None,
        "supersedes_failed_completion": None,
        "rule_projection_digest": "2" * 64,
        "successor_clause_digests": ["3" * 64],
        "scope_digest": "4" * 64,
        "effect_vocabulary_digest": "5" * 64,
        "effect_target_table_digest": EffectTargetTableV2.build().table_digest,
        "evaluator_registry_digest": "6" * 64,
        "resolver_version": "registry-v1-interim",
        "entries": entries,
    }


def _parse(body: dict[str, object]) -> ClauseSemanticsSetV2:
    """Parse one body through its public bytes entry point."""
    return ClauseSemanticsSetV2.from_bytes(canonical_journal_json_v2(body))


def test_canonical_body_round_trip_and_fresh_mapping() -> None:
    """Every subject survives one exact canonical byte round trip."""
    body = _body()
    parsed = _parse(body)
    assert parsed.to_dict() == body
    copy = parsed.to_dict()
    copy["schema"] = "changed"
    assert parsed.to_dict() == body
    assert len(parsed.body_digest) == 64


def test_noncanonical_and_duplicate_key_wires_refuse() -> None:
    """Whitespace aliases and duplicate JSON keys cannot sign a second meaning."""
    valid = canonical_journal_json_v2(_body())
    with pytest.raises(ValueError, match="not canonical"):
        ClauseSemanticsSetV2.from_bytes(valid + b"\n")
    with pytest.raises(ValueError, match="strict JSON"):
        ClauseSemanticsSetV2.from_bytes(b'{"schema":"a","schema":"b"}')


def test_unknown_field_and_wrong_subject_shape_refuse() -> None:
    """An added body key or a constraint disguised as an admit is refused."""
    body = _body()
    body["permission"] = "owner"
    with pytest.raises(ValueError, match="body fields"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    entries[0]["params"] = {"limit": 100}
    with pytest.raises(ValueError, match="entry fields"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    entries[0]["subject"] = "permission"
    with pytest.raises(ValueError, match="subject is unknown"):
        _parse(body)


def test_missing_or_invalid_target_table_pin_refuses() -> None:
    """The revised closed body binds the reviewed target-table object."""
    body = _body()
    del body["effect_target_table_digest"]
    with pytest.raises(ValueError, match="body fields"):
        _parse(body)
    body["effect_target_table_digest"] = "not-a-digest"
    with pytest.raises(ValueError, match="SHA-256 digest"):
        _parse(body)


def test_rate_bool_and_route_alias_refuse() -> None:
    """A boolean limit and non-canonical route strings cannot bypass constraints."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    rate = cast(dict[str, object], entries[2]["params"])
    rate["limit"] = True
    with pytest.raises(ValueError, match=r"rate\.limit"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    route = cast(dict[str, object], entries[4]["params"])
    route["provider"] = "lоcal"
    with pytest.raises(ValueError, match=r"route\.provider"):
        _parse(body)


def test_window_order_and_overlap_refuse() -> None:
    """UTC windows have calendar weekday order and no shared time span."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    window = cast(dict[str, object], entries[3]["params"])
    ranges = cast(list[dict[str, object]], window["utc_ranges"])
    ranges[0]["weekdays"] = ["tue", "mon"]
    with pytest.raises(ValueError, match="calendar order"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    window = cast(dict[str, object], entries[3]["params"])
    ranges = cast(list[dict[str, object]], window["utc_ranges"])
    ranges.append({"weekdays": ["tue"], "start": "10:00", "end": "11:00"})
    with pytest.raises(ValueError, match="overlap"):
        _parse(body)


def test_scope_and_entry_order_refuse() -> None:
    """Ambiguous target ordering and duplicate clause entries are refused."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[0]["scope"])
    scope["targets"] = ["path:/tmp/z", "path:/tmp/a"]
    with pytest.raises(ValueError, match="byte-sorted"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    entries.append(deepcopy(entries[0]))
    with pytest.raises(ValueError, match="sorted and unique"):
        _parse(body)


def test_veto_is_closed_and_completion_marker_is_digest() -> None:
    """A veto carries no evaluator, and failure replacement uses a digest."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    entries[1]["evaluator"] = {"id": "fake", "code_digest": "a" * 64}
    with pytest.raises(ValueError, match="entry fields"):
        _parse(body)
    body = _body()
    body["supersedes_failed_completion"] = "wrong"
    with pytest.raises(ValueError, match="SHA-256 digest"):
        _parse(body)


def test_builtin_evaluator_id_is_subject_bound_and_legacy_shape_refuses() -> None:
    """A constraint cannot borrow another built-in or retain a code digest."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    entries[2]["evaluator"] = {"id": "builtin.window.v2"}
    with pytest.raises(ValueError, match="evaluator subject differs"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    entries[2]["evaluator"] = {
        "id": "builtin.rate.v2",
        "code_digest": "a" * 64,
    }
    with pytest.raises(ValueError, match="evaluator fields"):
        _parse(body)


@pytest.mark.parametrize(
    "target",
    [
        "project-root:RIGOR-FOUNDRY",
        "group-workspace:AGENTIC-COORDINATION-ASSURANCE-AND-CONTINUITY-SYSTEMS/RIGOR-FOUNDRY",
        "group-workspace:AGENTIC-COORDINATION-ASSURANCE-AND-CONTINUITY-SYSTEMS",
        "endpoint:synapse:hub-local",
        "remote:https://example.org/review",
        "path:/",
    ],
)
def test_exact_target_string_forms_parse(target: str) -> None:
    """The substituted canonical target strings pass without brace placeholders.

    Parameters
    ----------
    target : str
        Candidate selector tested against its clause or registry role.
    """
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[0]["scope"])
    scope["targets"] = [target]
    assert _parse(body).to_dict() == body


@pytest.mark.parametrize(
    "target",
    [
        "project-root:{RIGOR-FOUNDRY}",
        "project-root:OTHER",
        "project-root:RIGOR-FOUNDRY/extra",
        "group-workspace:GROUP/OTHER",
        "group-workspace:GROUP/RIGOR-FOUNDRY/extra",
        "remote:https://user@example.org/review",
        "remote:https://example.org/review#fragment",
        "endpoint:synapse:",
        "endpoint:host:ml350",
        "host:ML350",
        "path:/tmp/../other",
        "path:/tmp//other",
        "path-glob:/tmp/*",
        "any-remote",
    ],
)
def test_forbidden_admit_target_strings_refuse(target: str) -> None:
    """Placeholders, foreign projects, malformed URLs and veto forms fail closed.

    Parameters
    ----------
    target : str
        Candidate selector tested against its clause or registry role.
    """
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[0]["scope"])
    scope["targets"] = [target]
    with pytest.raises(ValueError, match="semantics"):
        _parse(body)


@pytest.mark.parametrize(
    "selector",
    [
        "path-glob:/tmp/r?gor/*",
        "path-glob:/tmp/r[ia]gor/*",
        "path-glob:/tmp/r*gor/*",
        "path-glob:/tmp/**",
        "path-glob:/tmp/./rigor",
    ],
)
def test_forbidden_glob_grammar_refuses_at_body_parse(selector: str) -> None:
    """A signed constraint cannot carry a second glob interpretation.

    Parameters
    ----------
    selector : str
        Candidate exclusion glob with an ambiguous grammar.
    """
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[2]["scope"])
    scope["exclusions"] = [selector]
    with pytest.raises(ValueError, match="semantics"):
        _parse(body)


def test_veto_any_and_exclusion_rules() -> None:
    """A veto can cover unknown remotes but cannot hide a path-glob hole."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[1]["scope"])
    scope["targets"] = ["any-remote"]
    assert _parse(body).to_dict() == body
    scope["exclusions"] = ["path-glob:/tmp/*"]
    with pytest.raises(ValueError, match="never veto"):
        _parse(body)


def test_inbox_and_read_roots_are_effect_specific() -> None:
    """Inbox and monorepo scopes cannot transfer to another effect class."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[0]["scope"])
    scope["targets"] = ["group-exchange-inbox:SCPN-REACTOR-SYSTEMS"]
    with pytest.raises(ValueError, match="inbox class"):
        _parse(body)
    entries[0]["effect_class"] = "exchange-record-create"
    assert _parse(body).to_dict() == body
    scope["targets"] = ["monorepo-read-root"]
    with pytest.raises(ValueError, match="monorepo-read-root"):
        _parse(body)
    entries[0]["effect_class"] = "read"
    assert _parse(body).to_dict() == body


def test_body_types_and_successor_replay_refuse() -> None:
    """A signed body cannot smuggle alternate versions or successor aliases."""
    with pytest.raises(ValueError, match="must be bytes"):
        ClauseSemanticsSetV2.from_bytes(cast(bytes, "not bytes"))
    body = _body()
    body["schema"] = "rigor.clause-semantics-set.v1"
    with pytest.raises(ValueError, match="schema differs"):
        _parse(body)
    body = _body()
    body["successor_clause_digests"] = ["3" * 64, "3" * 64]
    with pytest.raises(ValueError, match="repeat"):
        _parse(body)
    body["successor_clause_digests"] = "3" * 64
    with pytest.raises(ValueError, match="must be an array"):
        _parse(body)
    body = _body()
    body["resolver_version"] = "latest"
    with pytest.raises(ValueError, match="resolver_version"):
        _parse(body)
    body = _body()
    body["entries"] = "not an array"
    with pytest.raises(ValueError, match="entries must be an array"):
        _parse(body)


def test_entry_scope_supersession_and_precondition_refuse() -> None:
    """Clause identity, scope and constraint names stay inside closed sets."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    entries[0]["scope"] = {"schema": "old", "targets": ["path:/tmp"], "exclusions": []}
    with pytest.raises(ValueError, match="scope schema"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[0]["scope"])
    scope["targets"] = []
    with pytest.raises(ValueError, match="ordered array"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    entries[0]["supersedes"] = ["bad"]
    with pytest.raises(ValueError, match="SHA-256 digest"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    precondition = cast(dict[str, object], entries[5]["params"])
    precondition["condition"] = "shell-command"
    with pytest.raises(ValueError, match="precondition is unknown"):
        _parse(body)


def test_rate_and_route_bounds_refuse() -> None:
    """A signer cannot change fixed rate basis or disguise route cost text."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    rate = cast(dict[str, object], entries[2]["params"])
    rate["count_basis"] = "ledger-consumption"
    with pytest.raises(ValueError, match="count_basis"):
        _parse(body)
    rate["count_basis"] = "operation-intent"
    rate["window_seconds"] = 604801
    with pytest.raises(ValueError, match="window_seconds"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    route = cast(dict[str, object], entries[4]["params"])
    route["account_ref"] = "owner-local"
    with pytest.raises(ValueError, match="account_ref"):
        _parse(body)
    route["account_ref"] = "ref:owner.local"
    ceiling = cast(dict[str, object], route["cost_ceiling"])
    ceiling["amount"] = "01.00"
    with pytest.raises(ValueError, match="ceiling amount"):
        _parse(body)
    ceiling["amount"] = "0"
    ceiling["currency"] = "usd"
    with pytest.raises(ValueError, match="ceiling currency"):
        _parse(body)


def test_window_empty_bad_time_and_wrong_order_refuse() -> None:
    """UTC windows reject an empty policy and time aliases across weekdays."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    window = cast(dict[str, object], entries[3]["params"])
    window["utc_ranges"] = []
    with pytest.raises(ValueError, match="utc_ranges"):
        _parse(body)
    ranges: list[dict[str, object]] = [{"weekdays": [], "start": "09:00", "end": "17:00"}]
    window["utc_ranges"] = ranges
    with pytest.raises(ValueError, match="weekdays must be non-empty"):
        _parse(body)
    ranges[0]["weekdays"] = ["mon"]
    ranges[0]["start"] = "25:00"
    with pytest.raises(ValueError, match="UTC range differs"):
        _parse(body)
    ranges[0]["start"] = "09:00"
    ranges.append({"weekdays": ["mon"], "start": "08:00", "end": "08:30"})
    with pytest.raises(ValueError, match="not sorted"):
        _parse(body)


def test_exclusion_grammar_and_veto_hole_refuse() -> None:
    """A path-glob may narrow an admit but cannot conceal a veto hole."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[0]["scope"])
    scope["exclusions"] = ["path-glob:/tmp/*"]
    assert _parse(body).to_dict() == body
    scope["exclusions"] = ["path-glob:/tmp/a*b"]
    with pytest.raises(ValueError, match="full segments"):
        _parse(body)
    scope["exclusions"] = ["any-remote"]
    with pytest.raises(ValueError, match="veto-only"):
        _parse(body)


def test_host_and_unknown_target_forms_refuse() -> None:
    """A host id is exact, and unknown or suffixless forms cannot enter scope."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[0]["scope"])
    scope["targets"] = ["host:compute-1"]
    assert _parse(body).to_dict() == body
    for target in ("host:/invalid", "unknown:value", "missing-colon"):
        scope["targets"] = [target]
        with pytest.raises(ValueError, match="semantics"):
            _parse(body)


def test_missing_subject_and_non_object_entry_refuse() -> None:
    """An entry without a subject or a JSON object is never a clause."""
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    entries[0]["subject"] = ""
    with pytest.raises(ValueError, match="non-empty text"):
        _parse(body)
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    cast(list[object], entries)[0] = "not an entry"
    with pytest.raises(ValueError, match="entry must be an object"):
        _parse(body)


@pytest.mark.parametrize("condition", [None, [], {}, 42])
def test_precondition_non_text_values_refuse_as_format_errors(condition: object) -> None:
    """Malformed condition values raise the parser's declared format error.

    Parameters
    ----------
    condition : object
        Non-text condition decoded from a valid JSON body.
    """
    body = _body()
    entries = cast(list[dict[str, object]], body["entries"])
    params = cast(dict[str, object], entries[5]["params"])
    params["condition"] = condition
    with pytest.raises(ValueError, match="semantics precondition condition"):
        _parse(body)
