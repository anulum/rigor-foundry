# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline CRA command-line workflow
"""Wire the offline CRA evidence workflow into the RIGOR-FOUNDRY CLI."""

from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from .cra_advisories import FixedVulnerabilityAdvisory
from .cra_events import SecurityEventRevision
from .cra_p1_cli import add_cra_p1_commands, add_osv_register_arguments, bind_osv_awareness
from .cra_pack_cli import add_cra_pack_command
from .cra_payloads import prepare_stage_payload, prepare_user_notice
from .cra_protocol import (
    EstablishmentBasis,
    EventStatus,
    Sensitivity,
    SevereProng,
    Stage,
    SuspectedCause,
    Track,
    json_text,
    require_cra_timestamp,
    require_relative_path,
)
from .cra_registration import ProductRegistration
from .cra_store import CraRepository
from .cra_submissions import StageSkip, SubmissionReceipt, UserNoticeDraft
from .cra_timeline import ReportingTimeline, compute_reporting_timeline
from .git_inventory import (
    StableReadError,
    open_directory_no_follow,
    read_stable_regular_file_at,
)

_EVIDENCE_LIMIT = 64 * 1024 * 1024


def _timestamp(value: str | None) -> str:
    """Return a validated explicit timestamp or current UTC whole seconds."""
    if value is None:
        return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    return require_cra_timestamp(value, "timestamp")


def _evidence_digest(path: Path, *, label: str = "receipt evidence") -> str:
    """Hash one bounded regular single-link evidence file without symlink traversal."""
    absolute = Path(os.path.abspath(path))
    parent = open_directory_no_follow(absolute.parent)
    try:
        try:
            observed = read_stable_regular_file_at(
                parent,
                absolute.name,
                label,
                buffer_limit=0,
                maximum_bytes=_EVIDENCE_LIMIT,
                require_single_link=True,
            )
        except StableReadError as exc:
            if exc.reason == "limit-exceeded":
                raise ValueError(f"{label} exceeds the 64 MiB limit") from exc
            raise ValueError(f"{label} must be a stable single-link regular file") from exc
    finally:
        os.close(parent)
    return observed.content_digest


def _repository_evidence(
    repository: CraRepository,
    path: Path,
    *,
    label: str,
) -> tuple[str, str]:
    """Return one repository-relative evidence path and its stable digest."""
    candidate = path if path.is_absolute() else repository.repository_root / path
    absolute = Path(os.path.abspath(candidate))
    try:
        relative = absolute.relative_to(repository.repository_root).as_posix()
    except ValueError as exc:
        raise ValueError(f"{label} must be inside the repository") from exc
    reference = require_relative_path(relative, f"{label} path")
    return reference, _evidence_digest(
        repository.repository_root / reference,
        label=label,
    )


def _registration(args: argparse.Namespace) -> ProductRegistration:
    """Build the initial product registration from explicit CLI declarations."""
    return ProductRegistration.build(
        product_key=args.product_key,
        product_name=args.product_name,
        manufacturer_name=args.manufacturer_name,
        main_establishment_ms=args.main_establishment_ms,
        establishment_basis=cast(EstablishmentBasis, args.establishment_basis),
        csirt_endpoint_id=args.csirt_endpoint_id,
        user_notice_channel=args.user_notice_channel,
        support_period_months=args.support_period_months,
        expected_use_months=args.expected_use_months,
        expected_use_evidence_ref=args.expected_use_evidence_ref,
        registered_at=_timestamp(args.registered_at),
    )


def _bootstrap(args: argparse.Namespace) -> int:
    """Create fresh ignored CRA state and one product registration."""
    registration = _registration(args)
    repository = CraRepository.bootstrap(args.root, registration)
    print(
        f"created offline CRA state at {repository.storage_root}; "
        f"registration={registration.registration_digest}"
    )
    return 0


def _event(args: argparse.Namespace) -> SecurityEventRevision:
    """Build an initial or successor event revision from explicit declarations."""
    repository = CraRepository.open(args.root)
    try:
        previous = repository.current_event(args.event_key)
    except ValueError as exc:
        if str(exc) != "event has no verified revisions":
            raise
        previous = None
    recorded_at = _timestamp(args.recorded_at)
    aware_evidence, external_ids, affected_components = bind_osv_awareness(
        args,
        recorded_at=recorded_at,
    )
    return SecurityEventRevision.build(
        event_key=args.event_key,
        product_key=args.product_key,
        track=cast(Track, args.track),
        aware_at=args.aware_at,
        aware_evidence_ref=aware_evidence,
        exploitation_evidence=tuple(args.exploitation_evidence),
        severe_prong=cast(SevereProng | None, args.severe_prong),
        severe_evidence_ref=args.severe_evidence,
        suspected_cause=cast(SuspectedCause | None, args.suspected_cause),
        external_ids=external_ids,
        affected_components=affected_components,
        severity_value=args.severity_value,
        severity_source_ref=args.severity_source,
        member_states=tuple(args.member_state),
        sensitivity=cast(Sensitivity, args.sensitivity),
        status=cast(EventStatus, args.status),
        corrective_measure_available_at=args.corrective_measure_available_at,
        intermediate_requested_at=args.intermediate_requested_at,
        intermediate_due_at=args.intermediate_due_at,
        intermediate_evidence_ref=args.intermediate_evidence,
        recorded_at=recorded_at,
        previous_revision_digest=(None if previous is None else previous.revision_digest),
    )


def _register(args: argparse.Namespace) -> int:
    """Append one vulnerability or severe-incident revision."""
    repository = CraRepository.open(args.root)
    event = _event(args)
    path = repository.append_event(event)
    print(f"stored {event.track} revision {event.revision_digest} at {path}")
    return 0


def _timeline(repository: CraRepository, event_key: str, now: str) -> ReportingTimeline:
    """Compute one timeline from verified current storage state."""
    state = repository.event_state(event_key)
    return compute_reporting_timeline(
        state.event,
        drafts=state.drafts,
        receipts=state.receipts,
        skips=state.skips,
        now=now,
        accepted_revision_digests=state.revision_digests,
    )


def _timeline_command(args: argparse.Namespace) -> int:
    """Print one deterministic current event timeline."""
    timeline = _timeline(CraRepository.open(args.root), args.event_key, _timestamp(args.now))
    print(timeline.to_json(), end="")
    return 1 if timeline.alerted else 0


def _draft(args: argparse.Namespace) -> int:
    """Prepare and persist one deterministic stage payload pair."""
    repository = CraRepository.open(args.root)
    event = repository.current_event(args.event_key)
    registration = repository.current_registration(event.product_key)
    generated_at = _timestamp(args.generated_at)
    stage = cast(Stage, args.stage)
    payload = prepare_stage_payload(
        registration,
        event,
        stage=stage,
        generated_at=generated_at,
    )
    draft = repository.append_draft(event, stage, generated_at, payload)
    print(f"stored offline draft {draft.draft_digest}; payload={draft.payload_digest}")
    return 0


def _receipt(args: argparse.Namespace) -> int:
    """Bind operator-declared submission evidence to one exact current draft."""
    repository = CraRepository.open(args.root)
    state = repository.event_state(args.event_key)
    matches = tuple(draft for draft in state.drafts if draft.stage == args.stage)
    if len(matches) != 1:
        raise ValueError("receipt stage must select exactly one current draft")
    draft = matches[0]
    if args.draft_digest is not None and args.draft_digest != draft.draft_digest:
        raise ValueError("--draft-digest does not match the selected current draft")
    receipt = SubmissionReceipt.build(
        product_key=draft.product_key,
        event_key=draft.event_key,
        track=draft.track,
        stage=draft.stage,
        draft_digest=draft.draft_digest,
        payload_digest=draft.payload_digest,
        submitted_at=args.submitted_at,
        platform_ref=args.platform_ref,
        csirt_endpoint_id=args.csirt_endpoint_id,
        evidence_sha256=_evidence_digest(args.evidence),
        bound_at=_timestamp(args.bound_at),
    )
    path = repository.append_receipt(receipt)
    print(
        "bound operator-declared receipt evidence; no authority acceptance is claimed: "
        f"{receipt.receipt_digest} at {path}"
    )
    return 0


def _skip(args: argparse.Namespace) -> int:
    """Append one explicit already-provided notification or final-report skip."""
    repository = CraRepository.open(args.root)
    state = repository.event_state(args.event_key)
    matches = tuple(
        receipt for receipt in state.receipts if receipt.stage == args.provided_in_stage
    )
    if len(matches) != 1:
        raise ValueError("provided stage must select exactly one current receipt")
    receipt = matches[0]
    if (
        args.provided_in_receipt_digest is not None
        and args.provided_in_receipt_digest != receipt.receipt_digest
    ):
        raise ValueError("--provided-in-receipt-digest does not match the selected receipt")
    skip = StageSkip.build(
        product_key=state.event.product_key,
        event_key=state.event.event_key,
        track=state.event.track,
        stage=cast(Literal["notification", "final-report"], args.stage),
        provided_in_stage=cast(Stage, args.provided_in_stage),
        provided_in_receipt_digest=receipt.receipt_digest,
        reason=args.reason,
        evidence_ref=args.evidence_ref,
        skipped_at=_timestamp(args.skipped_at),
    )
    path = repository.append_skip(skip)
    print(f"stored explicit already-provided skip {skip.skip_digest} at {path}")
    return 0


def _notice(args: argparse.Namespace) -> int:
    """Prepare and persist one offline Article 14(8) user notice."""
    repository = CraRepository.open(args.root)
    event = repository.current_event(args.event_key)
    registration = repository.current_registration(event.product_key)
    generated_at = _timestamp(args.generated_at)
    audience = cast(Literal["impacted", "all"], args.audience)
    payload = prepare_user_notice(
        registration,
        event,
        audience=audience,
        machine_readable=args.machine_readable,
        generated_at=generated_at,
    )
    notice = UserNoticeDraft.build(
        product_key=event.product_key,
        event_key=event.event_key,
        track=event.track,
        revision_digest=event.revision_digest,
        audience=audience,
        machine_readable=args.machine_readable,
        json_payload_digest=payload.json_digest,
        markdown_payload_digest=payload.markdown_digest,
        generated_at=generated_at,
    )
    path = repository.append_user_notice(event, notice, payload)
    print(f"stored prepare-only user notice {notice.notice_digest} at {path}")
    return 0


def _advisory_draft(args: argparse.Namespace) -> int:
    """Record an operator-prepared fixed-vulnerability advisory draft."""
    repository = CraRepository.open(args.root)
    event = repository.current_event(args.event_key)
    if event.track != "vulnerability":
        raise ValueError("fixed-vulnerability advisory requires vulnerability track")
    advisory_path = require_relative_path(args.advisory_path, "advisory_path")
    advisory = FixedVulnerabilityAdvisory.build(
        product_key=event.product_key,
        event_key=event.event_key,
        revision_digest=event.revision_digest,
        state="draft",
        security_update_ref=args.security_update_ref,
        advisory_path=advisory_path,
        advisory_sha256=_evidence_digest(
            repository.repository_root / advisory_path,
            label="advisory content",
        ),
        drafted_at=_timestamp(args.drafted_at),
    )
    path = repository.append_advisory(advisory)
    print(f"stored prepare-only advisory draft {advisory.advisory_digest} at {path}")
    return 0


def _advisory_successor(
    args: argparse.Namespace,
    *,
    state: Literal["published", "justified-delay"],
) -> int:
    """Append operator-declared publication or justified-delay evidence."""
    repository = CraRepository.open(args.root)
    event = repository.current_event(args.event_key)
    previous = repository.advisory(args.event_key)
    if previous is None:
        raise ValueError("advisory successor requires an existing draft")
    evidence_path, evidence_digest = _repository_evidence(
        repository,
        args.evidence,
        label=(
            "advisory publication evidence" if state == "published" else "advisory delay evidence"
        ),
    )
    advisory = FixedVulnerabilityAdvisory.build(
        product_key=event.product_key,
        event_key=event.event_key,
        revision_digest=event.revision_digest,
        state=state,
        security_update_ref=previous.security_update_ref,
        advisory_path=previous.advisory_path,
        advisory_sha256=previous.advisory_sha256,
        drafted_at=previous.drafted_at,
        published_at=_timestamp(args.published_at) if state == "published" else None,
        publication_evidence_path=evidence_path if state == "published" else None,
        publication_evidence_sha256=(evidence_digest if state == "published" else None),
        delay_reason=args.reason if state == "justified-delay" else None,
        delay_review_at=args.review_at if state == "justified-delay" else None,
        delay_evidence_path=evidence_path if state == "justified-delay" else None,
        delay_evidence_sha256=(evidence_digest if state == "justified-delay" else None),
        previous_advisory_digest=previous.advisory_digest,
    )
    path = repository.append_advisory(advisory)
    boundary = (
        "operator-declared publication evidence; RIGOR-FOUNDRY did not publish"
        if state == "published"
        else "operator-declared justified-delay evidence; no legal sufficiency is claimed"
    )
    print(f"stored {boundary}: {advisory.advisory_digest} at {path}")
    return 0


def _advisory_publish(args: argparse.Namespace) -> int:
    """Record operator-declared publication evidence without publishing."""
    return _advisory_successor(args, state="published")


def _advisory_delay(args: argparse.Namespace) -> int:
    """Record operator-declared justified-delay evidence without adjudicating it."""
    return _advisory_successor(args, state="justified-delay")


def _status(args: argparse.Namespace) -> int:
    """Print all requested current timelines and return their aggregate alert state."""
    repository = CraRepository.open(args.root)
    now = _timestamp(args.now)
    keys = (args.event_key,) if args.event_key is not None else repository.event_keys()
    timelines = tuple(_timeline(repository, key, now) for key in keys)
    if args.json:
        print(
            json_text({"events": [timeline.to_dict() for timeline in timelines], "now": now}),
            end="",
        )
    else:
        for timeline in timelines:
            print(timeline.to_json(), end="")
    return 1 if any(timeline.alerted for timeline in timelines) else 0


def _root(parser: argparse.ArgumentParser) -> None:
    """Add the shared explicit repository-root option."""
    parser.add_argument("--root", type=Path, required=True)


def add_cra_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the complete offline CRA P0 command surface.

    Parameters
    ----------
    subparsers:
        Main RIGOR-FOUNDRY argparse subparser collection.

    """
    bootstrap = subparsers.add_parser(
        "cra-bootstrap",
        help="Create fresh ignored offline CRA state and a product registration.",
    )
    _root(bootstrap)
    bootstrap.add_argument("--product-key", required=True)
    bootstrap.add_argument("--product-name", required=True)
    bootstrap.add_argument("--manufacturer-name", required=True)
    bootstrap.add_argument("--main-establishment-ms", required=True)
    bootstrap.add_argument(
        "--establishment-basis",
        choices=("decisions", "employees", "auth-rep", "importer", "distributor", "users"),
        required=True,
    )
    bootstrap.add_argument("--csirt-endpoint-id", required=True)
    bootstrap.add_argument("--user-notice-channel", required=True)
    bootstrap.add_argument("--support-period-months", type=int, required=True)
    bootstrap.add_argument("--expected-use-months", type=int)
    bootstrap.add_argument("--expected-use-evidence-ref")
    bootstrap.add_argument("--registered-at")
    bootstrap.set_defaults(handler=_bootstrap)

    register = subparsers.add_parser(
        "vuln-register",
        help="Append a vulnerability or severe-incident evidence revision.",
    )
    register.add_argument("event_key")
    _root(register)
    register.add_argument("--product-key", required=True)
    register.add_argument("--track", choices=("vulnerability", "incident"), required=True)
    register.add_argument("--aware-at", required=True)
    register.add_argument("--aware-evidence")
    register.add_argument("--exploitation-evidence", action="append", default=[])
    register.add_argument("--severe-prong", choices=("data-or-functions", "malicious-code"))
    register.add_argument("--severe-evidence")
    register.add_argument(
        "--suspected-cause",
        choices=("unlawful-or-malicious", "not-suspected", "unknown"),
    )
    register.add_argument("--external-id", action="append", default=[])
    register.add_argument("--component", action="append", default=[])
    register.add_argument("--severity-value")
    register.add_argument("--severity-source")
    register.add_argument("--member-state", action="append", default=[])
    register.add_argument("--sensitivity", choices=("normal", "sensitive"), default="normal")
    register.add_argument(
        "--status",
        choices=("triaged", "fixing", "fix-available", "disclosed", "closed"),
        default="triaged",
    )
    register.add_argument("--corrective-measure-available-at")
    register.add_argument("--intermediate-requested-at")
    register.add_argument("--intermediate-due-at")
    register.add_argument("--intermediate-evidence")
    register.add_argument("--recorded-at")
    add_osv_register_arguments(register)
    register.set_defaults(handler=_register)

    timeline = subparsers.add_parser("vuln-timeline", help="Print one verified CRA timeline.")
    timeline.add_argument("event_key")
    _root(timeline)
    timeline.add_argument("--now")
    timeline.set_defaults(handler=_timeline_command)

    draft = subparsers.add_parser("cra-draft", help="Prepare an offline stage payload pair.")
    draft.add_argument("event_key")
    _root(draft)
    draft.add_argument(
        "--stage",
        choices=("early-warning", "notification", "final-report", "intermediate"),
        required=True,
    )
    draft.add_argument("--generated-at")
    draft.set_defaults(handler=_draft)

    receipt = subparsers.add_parser(
        "cra-receipt",
        help="Bind operator-declared submission evidence; never contact an authority.",
    )
    receipt.add_argument("event_key")
    _root(receipt)
    receipt.add_argument(
        "--stage",
        choices=("early-warning", "notification", "final-report", "intermediate"),
        required=True,
    )
    receipt.add_argument("--draft-digest")
    receipt.add_argument("--submitted-at", required=True)
    receipt.add_argument("--platform-ref", required=True)
    receipt.add_argument("--csirt-endpoint-id", required=True)
    receipt.add_argument("--evidence", type=Path, required=True)
    receipt.add_argument("--bound-at")
    receipt.set_defaults(handler=_receipt)

    skip = subparsers.add_parser(
        "cra-skip",
        help="Record that an earlier receipt already provided a later stage's information.",
    )
    skip.add_argument("event_key")
    _root(skip)
    skip.add_argument("--stage", choices=("notification", "final-report"), required=True)
    skip.add_argument(
        "--provided-in-stage",
        choices=("early-warning", "notification", "intermediate"),
        required=True,
    )
    skip.add_argument("--provided-in-receipt-digest")
    skip.add_argument("--reason", required=True)
    skip.add_argument("--evidence-ref", required=True)
    skip.add_argument("--skipped-at")
    skip.set_defaults(handler=_skip)

    notice = subparsers.add_parser(
        "user-notice",
        help="Prepare an offline Article 14(8) user-notice payload pair.",
    )
    notice.add_argument("event_key")
    _root(notice)
    notice.add_argument("--audience", choices=("impacted", "all"), required=True)
    notice.add_argument("--machine-readable", action="store_true")
    notice.add_argument("--generated-at")
    notice.set_defaults(handler=_notice)

    advisory_draft = subparsers.add_parser(
        "advisory-draft",
        help="Record a prepare-only fixed-vulnerability advisory draft.",
    )
    advisory_draft.add_argument("event_key")
    _root(advisory_draft)
    advisory_draft.add_argument("--security-update-ref", required=True)
    advisory_draft.add_argument("--advisory-path", required=True)
    advisory_draft.add_argument("--drafted-at")
    advisory_draft.set_defaults(handler=_advisory_draft)

    advisory_publish = subparsers.add_parser(
        "advisory-publish",
        help="Bind operator-declared advisory publication evidence without publishing.",
    )
    advisory_publish.add_argument("event_key")
    _root(advisory_publish)
    advisory_publish.add_argument("--published-at")
    advisory_publish.add_argument("--evidence", type=Path, required=True)
    advisory_publish.set_defaults(handler=_advisory_publish)

    advisory_delay = subparsers.add_parser(
        "advisory-delay",
        help="Bind operator-declared justified-delay evidence without a legal verdict.",
    )
    advisory_delay.add_argument("event_key")
    _root(advisory_delay)
    advisory_delay.add_argument("--reason", required=True)
    advisory_delay.add_argument("--review-at", required=True)
    advisory_delay.add_argument("--evidence", type=Path, required=True)
    advisory_delay.set_defaults(handler=_advisory_delay)

    status = subparsers.add_parser("cra-status", help="Print aggregate offline CRA status.")
    _root(status)
    status.add_argument("--event-key")
    status.add_argument("--now")
    status.add_argument("--json", action="store_true")
    status.set_defaults(handler=_status)
    add_cra_p1_commands(subparsers)
    add_cra_pack_command(subparsers)
