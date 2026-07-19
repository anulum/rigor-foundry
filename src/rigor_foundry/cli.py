# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — reusable repository-audit CLI
"""Command-line workflow for scanning, reviewing, and promoting findings."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from .adapters import run_native_audits
from .bootstrap import bootstrap_repository
from .campaign_identity import InferenceIdentity
from .campaign_promotion import validate_promotion_campaign
from .campaign_workflow import (
    compare_campaign_runs,
    create_campaign,
    execute_campaign,
)
from .candidate_anchor import Candidate, RepositoryTreeAnchor
from .coverage_residuals import (
    DEFAULT_COVERAGE_RESIDUAL_MANIFEST,
    coverage_residual_errors,
)
from .cra_cli import add_cra_commands
from .enforcement import evaluate_enforcement
from .git_provenance import (
    DEFAULT_MAXIMUM_GIT_VERSION_EXCLUSIVE,
    DEFAULT_MINIMUM_GIT_VERSION,
    GitRunner,
    GitTrustPolicy,
)
from .incremental_scan import resolve_changed_paths, select_changed_candidates
from .models import (
    AuditReport,
    ReviewRecord,
    reviews_from_path,
    reviews_to_json,
)
from .oscal_cli import add_oscal_commands
from .review import (
    append_todo_entry,
    render_todo_entry,
    review_templates,
    validate_reviews,
)
from .rule_maturity import RuleMaturityReport
from .rule_maturity_manifest import evaluate_rule_maturity_manifest
from .safe_output import write_new_output
from .sarif import report_sarif
from .scanner import scan_repository
from .source_provenance_cli import add_source_provenance_commands
from .version import __version__


def report_markdown(report: AuditReport) -> str:
    """Render a report summary that labels every result as a candidate.

    Parameters
    ----------
    report:
        Integrity-verified audit report.

    Returns
    -------
    str
        Markdown summary with category/rule counts and verification caveat.

    """
    categories = Counter(candidate.category for candidate in report.candidates)
    rules = Counter(candidate.rule_id for candidate in report.candidates)
    lines = [
        "# Repository audit candidate report",
        "",
        "> Static candidates are not defect verdicts. Verify each candidate against the real",
        "> production surface before promoting it into a TODO or changing code.",
        "",
        f"- Repository: `{report.repository_root}`",
        f"- HEAD: `{report.head}`",
        f"- HEAD tree: `{report.head_tree}`",
        f"- Git object format: `{report.git_object_format}`",
        f"- Branch: `{report.branch}`",
        f"- Tracked-content digest: `{report.tracked_content_digest}`",
        f"- Git version: `{report.git_provenance.version}`",
        f"- Git executable digest: `{report.git_provenance.executable_digest}`",
        f"- Git trust-policy digest: `{report.git_provenance.trust_policy_digest}`",
        f"- Policy digest: `{report.policy_digest}`",
        f"- Ignored-inventory digest: `{report.ignored_inventory_digest}`",
        f"- Report digest: `{report.report_digest}`",
        f"- Tracked files: {report.tracked_file_count}",
        f"- Dirty tracked paths: {len(report.dirty_paths)}",
        f"- Declared ignored paths: {len(report.ignored_inventory_evidence)}",
        f"- Candidates: {len(report.candidates)}",
        "",
        "## Categories",
        "",
    ]
    lines.extend(f"- `{category}`: {categories[category]}" for category in sorted(categories))
    lines.extend(("", "## Rules", ""))
    lines.extend(f"- `{rule}`: {rules[rule]}" for rule in sorted(rules))
    lines.extend(("", "## Ignored inventory", ""))
    if not report.ignored_inventory_evidence:
        lines.append("- No ignored paths were declared.")
    for item in report.ignored_inventory_evidence:
        lines.append(
            f"- `{item.evidence_id}`: `{item.path}`; capture `{item.capture}`; "
            f"status `{item.status}`; kind `{item.observed_kind or '-'}`; "
            f"bytes `{item.byte_size if item.byte_size is not None else '-'}`; "
            f"SHA-256 `{item.content_sha256 or '-'}`; reason `{item.reason}`"
        )
    lines.extend(("", "## Candidates", ""))
    for candidate in report.candidates:
        anchor = candidate.anchor
        location = (
            f"{anchor.path}:{anchor.line_start}"
            if anchor.line_start == anchor.line_end
            else f"{anchor.path}:{anchor.line_start}-{anchor.line_end}"
        )
        anchor_identity = (
            f"tree `{anchor.tree_oid}`; tracked content SHA-256 `{anchor.tracked_content_sha256}`"
            if isinstance(anchor, RepositoryTreeAnchor)
            else f"blob `{anchor.blob_oid}`; content SHA-256 `{anchor.content_sha256}`"
        )
        lines.extend(
            (
                f"### `{candidate.candidate_id}`",
                "",
                f"- Rule: `{candidate.rule_id}` (`{candidate.category}`, "
                f"confidence hint `{candidate.confidence}`)",
                f"- Location: `{location}` ({anchor.kind})",
                f"- Anchor: {anchor_identity}",
                f"- Evidence: {candidate.evidence}",
                f"- Why review: {candidate.rationale}",
                f"- Verification: {candidate.verification}",
                "",
            )
        )
    return "\n".join(lines).rstrip() + "\n"


def _write_explicit(path: Path, text: str) -> None:
    """Create one explicitly requested output without overwriting adopter bytes."""
    write_new_output(path, text)


def _git_trust_policy(args: argparse.Namespace) -> GitTrustPolicy:
    """Build the explicit runtime trust policy shared by Git-using commands."""
    roots = tuple(str(path) for path in args.git_trust_root)
    executable = str(args.git_executable)
    if Path(executable).is_absolute() and not roots:
        raise ValueError("an absolute --git-executable requires --git-trust-root")
    return GitTrustPolicy(
        executable=executable,
        trusted_roots=roots,
        minimum_version=str(args.git_min_version),
        maximum_version_exclusive=str(args.git_max_version_exclusive),
    )


def _add_git_trust_arguments(parser: argparse.ArgumentParser) -> None:
    """Add portable, fail-closed Git provenance controls to one command."""
    parser.add_argument(
        "--git-executable",
        default="git",
        help="Absolute executable or basename searched only below trusted roots.",
    )
    parser.add_argument(
        "--git-trust-root",
        action="append",
        type=Path,
        default=[],
        help="Normalised absolute executable root; repeat to declare ordered roots.",
    )
    parser.add_argument("--git-min-version", default=DEFAULT_MINIMUM_GIT_VERSION)
    parser.add_argument(
        "--git-max-version-exclusive",
        default=DEFAULT_MAXIMUM_GIT_VERSION_EXCLUSIVE,
    )


def _scan_command(args: argparse.Namespace) -> int:
    """Execute the read-only scan command."""
    trust_policy = _git_trust_policy(args)
    report = scan_repository(args.root, args.policy, git_trust_policy=trust_policy)
    gating_candidates = report.candidates
    changed_summary: str | None = None
    if args.changed_since is not None:
        changed_paths = resolve_changed_paths(
            GitRunner(trust_policy), args.root, args.changed_since
        )
        gating_candidates = select_changed_candidates(report.candidates, changed_paths)
        changed_summary = _changed_scan_summary(
            args.changed_since, report, changed_paths, gating_candidates
        )
    wrote_output = False
    if args.json_out is not None:
        _write_explicit(args.json_out, report.to_json())
        wrote_output = True
    if args.markdown_out is not None:
        _write_explicit(args.markdown_out, report_markdown(report))
        wrote_output = True
    if changed_summary is not None:
        print(changed_summary)
    elif not wrote_output:
        print(report.to_json(), end="")
    if args.fail_on_candidates and gating_candidates:
        return 1
    return 0


def _changed_scan_summary(
    reference: str,
    report: AuditReport,
    changed_paths: frozenset[str],
    gating_candidates: tuple[Candidate, ...],
) -> str:
    """Return a deterministic human summary of the changed-files scan view."""
    header = (
        f"changed-files view since {reference}: {len(gating_candidates)} of "
        f"{len(report.candidates)} candidate(s) in {len(changed_paths)} changed file(s) "
        f"(report digest {report.report_digest})"
    )
    lines = [
        f"- {candidate.rule_id} {candidate.path}:{candidate.line}"
        for candidate in gating_candidates
    ]
    return "\n".join([header, *lines])


def _review_template_command(args: argparse.Namespace) -> int:
    """Write deliberately non-promotable review templates."""
    report = AuditReport.from_path(args.report)
    _write_explicit(args.output, reviews_to_json(review_templates(report)))
    return 0


def _validate_review_command(args: argparse.Namespace) -> int:
    """Validate review evidence against its exact report."""
    report = AuditReport.from_path(args.report)
    reviews = reviews_from_path(args.review)
    errors = validate_reviews(report, reviews)
    if errors:
        print("repository audit review: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print("repository audit review: PASS")
    return 0


def _sarif_command(args: argparse.Namespace) -> int:
    """Export one verified report and optional review ledger as SARIF."""
    report = AuditReport.from_path(args.report)
    reviews = () if args.review is None else reviews_from_path(args.review)
    output = report_sarif(report, reviews)
    if args.output is None:
        print(output, end="")
    else:
        _write_explicit(args.output, output)
    return 0


def _selected_review(reviews: tuple[ReviewRecord, ...], candidate_id: str) -> ReviewRecord:
    """Return one uniquely selected review."""
    matches = tuple(review for review in reviews if review.candidate_id == candidate_id)
    if len(matches) != 1:
        raise ValueError("candidate-id must select exactly one review")
    return matches[0]


def _promote_command(args: argparse.Namespace) -> int:
    """Preview or explicitly append one current verified finding."""
    report = AuditReport.from_path(args.report)
    reviews = reviews_from_path(args.review)
    review = _selected_review(reviews, args.candidate_id)
    errors = validate_reviews(report, (review,))
    if errors:
        raise ValueError("review validation failed: " + "; ".join(errors))
    validate_promotion_campaign(
        args.campaign,
        args.comparison,
        report,
        review,
    )
    git_trust_policy = _git_trust_policy(args)
    current = scan_repository(
        args.root,
        args.policy,
        git_trust_policy=git_trust_policy,
    )
    if Path(report.repository_root).resolve() != Path(current.repository_root).resolve():
        raise ValueError("report belongs to a different repository root")
    if current.head != report.head:
        raise ValueError("report HEAD is stale; rescan and re-review before promotion")
    if current.tracked_content_digest != report.tracked_content_digest:
        raise ValueError("report tracked content is stale; rescan and re-review before promotion")
    if current.policy_digest != report.policy_digest:
        raise ValueError("report policy is stale; rescan and re-review before promotion")
    if (
        current.ignored_inventory_evidence != report.ignored_inventory_evidence
        or current.ignored_inventory_digest != report.ignored_inventory_digest
    ):
        raise ValueError(
            "report ignored inventory is stale; rescan and re-review before promotion"
        )
    if current.git_provenance.identity_digest != report.git_provenance.identity_digest:
        raise ValueError("report Git executable provenance is stale; rescan before promotion")
    if review.candidate_id not in {candidate.candidate_id for candidate in current.candidates}:
        raise ValueError("candidate is absent or changed in the current tracked tree")
    entry = render_todo_entry(report, review)
    if not args.apply:
        print(entry, end="")
        return 0
    append_todo_entry(
        Path(current.repository_root),
        args.todo,
        entry,
        review.candidate_id,
        git_trust_policy=git_trust_policy,
        expected_git_provenance=current.git_provenance,
    )
    print(f"promoted verified finding {review.candidate_id} to {args.todo}")
    return 0


def _gate_command(args: argparse.Namespace) -> int:
    """Evaluate the current report, review ledger, and native audits."""
    git_trust_policy = _git_trust_policy(args)
    report = scan_repository(
        args.root,
        args.policy,
        git_trust_policy=git_trust_policy,
    )
    policy = report.policy
    repository = Path(report.repository_root)
    requested_mode = args.mode or policy.enforcement_mode
    ranks = {"observe": 0, "ratchet": 1, "zero": 2}
    if ranks[requested_mode] < ranks[policy.enforcement_mode]:
        raise ValueError("command-line mode cannot weaken repository enforcement")
    ledger_path = args.review or repository / policy.review_ledger
    if ledger_path.is_file():
        reviews = reviews_from_path(ledger_path)
    else:
        reviews = ()
    adapter_results = run_native_audits(
        repository,
        policy.native_audits,
        args.scope,
        trusted=args.allow_native_audits,
        git_trust_policy=git_trust_policy,
        expected_tracked_content_digest=report.tracked_content_digest,
    )
    maturity = RuleMaturityReport.from_path(args.maturity) if args.maturity is not None else None
    result = evaluate_enforcement(
        report,
        reviews,
        requested_mode,
        maturity=maturity,
        adapter_results=adapter_results,
    )
    output = json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(output, end="")
    else:
        _write_explicit(args.output, output)
    return 0 if result.passed else 1


def _maturity_evaluate_command(args: argparse.Namespace) -> int:
    """Evaluate explicit adjudicated cases into per-rule maturity decisions."""
    report = evaluate_rule_maturity_manifest(args.cases)
    output = report.to_json()
    if args.output is None:
        print(output, end="")
    else:
        _write_explicit(args.output, output)
    return 0


def _campaign_create_command(args: argparse.Namespace) -> int:
    """Freeze one exact audit input contract for independent agents."""
    path, campaign = create_campaign(
        args.root,
        args.policy,
        audit_root=args.audit_root,
        project=args.project,
        campaign_id=args.campaign_id,
        actor=args.actor,
        expected_runs=args.expected_runs,
        purpose=args.purpose,
        required_model_witnesses=args.required_model_witnesses,
        git_trust_policy=_git_trust_policy(args),
    )
    print(f"created audit campaign {campaign.contract_digest} at {path}")
    return 0


def _campaign_run_command(args: argparse.Namespace) -> int:
    """Execute and attest one independent full-scope audit run."""
    path, attestation = execute_campaign(
        args.campaign,
        run_id=args.run_id,
        agent_identity=args.agent,
        session_identity=args.session,
        inference_identity=InferenceIdentity.build(
            provider=args.provider,
            model=args.model,
            model_family=args.model_family,
            operator=args.operator,
        ),
        trusted_native_audits=args.allow_native_audits,
        git_trust_policy=_git_trust_policy(args),
    )
    print(f"stored audit run {attestation.attestation_digest} at {path}")
    return 1 if attestation.limitations or attestation.omitted_domains else 0


def _campaign_compare_command(args: argparse.Namespace) -> int:
    """Persist one independent-run convergence and diligence comparison."""
    path, comparison = compare_campaign_runs(
        args.campaign,
        comparison_id=args.comparison_id,
        actor=args.actor,
        git_trust_policy=_git_trust_policy(args),
    )
    print(f"stored audit comparison {comparison.comparison_digest} at {path}")
    return 1 if comparison.unresolved else 0


def _residuals_check_command(args: argparse.Namespace) -> int:
    """Validate classified residual evidence and preregistered negative searches."""
    errors = coverage_residual_errors(args.root, args.manifest)
    if errors:
        print("coverage residuals: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print("coverage residuals: PASS")
    return 0


def _bootstrap_command(args: argparse.Namespace) -> int:
    """Create one explicit adopter policy and canonical ignored TODO."""
    result = bootstrap_repository(
        args.root,
        policy_path=args.policy,
        todo_path=args.todo,
        review_ledger_path=args.review_ledger,
        source_roots=tuple(args.source_root),
        test_roots=tuple(args.test_root),
        source_line_threshold=args.source_line_threshold,
        test_line_threshold=args.test_line_threshold,
        git_trust_policy=_git_trust_policy(args),
    )
    print(
        "created adopter bootstrap: "
        f"policy={result.policy_path}; TODO={result.todo_path}; "
        f"policy_digest={result.policy_digest}"
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"rigor {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    bootstrap = subparsers.add_parser(
        "bootstrap",
        help="Create an explicit policy and ignored canonical TODO without overwrite.",
    )
    bootstrap.add_argument("--root", type=Path, required=True)
    bootstrap.add_argument("--policy", type=Path, required=True)
    bootstrap.add_argument("--todo", type=Path, required=True)
    bootstrap.add_argument("--review-ledger", type=Path, required=True)
    bootstrap.add_argument("--source-root", type=Path, action="append", required=True)
    bootstrap.add_argument("--test-root", type=Path, action="append", required=True)
    bootstrap.add_argument("--source-line-threshold", type=int, default=700)
    bootstrap.add_argument("--test-line-threshold", type=int, default=1000)
    _add_git_trust_arguments(bootstrap)
    bootstrap.set_defaults(handler=_bootstrap_command)

    scan = subparsers.add_parser("scan", help="Emit read-only static audit candidates.")
    scan.add_argument("--root", type=Path, required=True)
    scan.add_argument("--policy", type=Path)
    scan.add_argument("--json-out", type=Path)
    scan.add_argument("--markdown-out", type=Path)
    scan.add_argument("--fail-on-candidates", action="store_true")
    scan.add_argument(
        "--changed-since",
        help=(
            "Report and gate only candidates in files changed between this Git "
            "revision and HEAD; the full report output is unchanged."
        ),
    )
    _add_git_trust_arguments(scan)
    scan.set_defaults(handler=_scan_command)

    template = subparsers.add_parser(
        "review-template",
        help="Create needs-evidence review records for a report.",
    )
    template.add_argument("--report", type=Path, required=True)
    template.add_argument("--output", type=Path, required=True)
    template.set_defaults(handler=_review_template_command)

    validate = subparsers.add_parser(
        "validate-review",
        help="Validate evidence decisions against a report.",
    )
    validate.add_argument("--report", type=Path, required=True)
    validate.add_argument("--review", type=Path, required=True)
    validate.set_defaults(handler=_validate_review_command)

    sarif = subparsers.add_parser(
        "sarif",
        help="Export candidates and optional review verdicts as deterministic SARIF 2.1.0.",
    )
    sarif.add_argument("--report", type=Path, required=True)
    sarif.add_argument("--review", type=Path)
    sarif.add_argument("--output", type=Path)
    sarif.set_defaults(handler=_sarif_command)

    promote = subparsers.add_parser(
        "promote",
        help="Preview or append one current verified finding to a canonical TODO.",
    )
    promote.add_argument("--root", type=Path, required=True)
    promote.add_argument("--policy", type=Path)
    promote.add_argument("--report", type=Path, required=True)
    promote.add_argument("--review", type=Path, required=True)
    promote.add_argument("--campaign", type=Path, required=True)
    promote.add_argument("--comparison", type=Path, required=True)
    promote.add_argument("--candidate-id", required=True)
    promote.add_argument("--todo", type=Path, required=True)
    promote.add_argument("--apply", action="store_true")
    _add_git_trust_arguments(promote)
    promote.set_defaults(handler=_promote_command)

    gate = subparsers.add_parser(
        "gate",
        help="Evaluate reviewed candidates and repository-native audits.",
    )
    gate.add_argument("--root", type=Path, required=True)
    gate.add_argument("--policy", type=Path)
    gate.add_argument("--review", type=Path)
    gate.add_argument(
        "--maturity",
        type=Path,
        help="Content-addressed per-rule maturity report required by ratchet and zero modes.",
    )
    gate.add_argument("--mode", choices=("observe", "ratchet", "zero"))
    gate.add_argument("--scope", choices=("staged", "full"), default="full")
    gate.add_argument(
        "--allow-native-audits",
        action="store_true",
        help="Consent to run declared commands in the read-only native sandbox.",
    )
    gate.add_argument("--output", type=Path)
    _add_git_trust_arguments(gate)
    gate.set_defaults(handler=_gate_command)

    maturity = subparsers.add_parser(
        "maturity-evaluate",
        help="Derive probation or active rule status from adjudicated review cases.",
    )
    maturity.add_argument("--cases", type=Path, required=True)
    maturity.add_argument("--output", type=Path)
    maturity.set_defaults(handler=_maturity_evaluate_command)

    campaign_create = subparsers.add_parser(
        "campaign-create",
        help="Freeze one internal input contract for independent audit agents.",
    )
    campaign_create.add_argument("--root", type=Path, required=True)
    campaign_create.add_argument("--policy", type=Path, required=True)
    campaign_create.add_argument(
        "--audit-root",
        type=Path,
        default=Path(".rigor/audits"),
    )
    campaign_create.add_argument("--project", required=True)
    campaign_create.add_argument("--campaign-id", required=True)
    campaign_create.add_argument("--actor", required=True)
    campaign_create.add_argument("--expected-runs", type=int, default=2)
    campaign_create.add_argument(
        "--purpose",
        choices=("diagnostic", "promotion"),
        default="diagnostic",
    )
    campaign_create.add_argument("--required-model-witnesses", type=int)
    _add_git_trust_arguments(campaign_create)
    campaign_create.set_defaults(handler=_campaign_create_command)

    campaign_run = subparsers.add_parser(
        "campaign-run",
        help="Execute and attest one independent campaign run.",
    )
    campaign_run.add_argument("--campaign", type=Path, required=True)
    campaign_run.add_argument("--run-id", required=True)
    campaign_run.add_argument("--agent", required=True)
    campaign_run.add_argument("--session", required=True)
    campaign_run.add_argument("--provider", required=True)
    campaign_run.add_argument("--model", required=True)
    campaign_run.add_argument("--model-family", required=True)
    campaign_run.add_argument("--operator", required=True)
    campaign_run.add_argument(
        "--allow-native-audits",
        action="store_true",
        help="Consent to run declared commands in the read-only native sandbox.",
    )
    _add_git_trust_arguments(campaign_run)
    campaign_run.set_defaults(handler=_campaign_run_command)

    campaign_compare = subparsers.add_parser(
        "campaign-compare",
        help="Compare campaign runs and reviews for diligence and divergence.",
    )
    campaign_compare.add_argument("--campaign", type=Path, required=True)
    campaign_compare.add_argument("--comparison-id", required=True)
    campaign_compare.add_argument("--actor", required=True)
    _add_git_trust_arguments(campaign_compare)
    campaign_compare.set_defaults(handler=_campaign_compare_command)

    residuals = subparsers.add_parser(
        "residuals-check",
        help="Validate expiring classified coverage residuals.",
    )
    residuals.add_argument("--root", type=Path, required=True)
    residuals.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_COVERAGE_RESIDUAL_MANIFEST,
    )
    residuals.set_defaults(handler=_residuals_check_command)
    add_source_provenance_commands(subparsers)
    add_oscal_commands(subparsers)
    add_cra_commands(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the repository-audit command-line workflow.

    Parameters
    ----------
    argv:
        Optional arguments excluding the executable name.

    Returns
    -------
    int
        Zero for a successful command, one for a candidate/review gate failure,
        and two for invalid input or unsafe repository state.

    """
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        handler = args.handler
        if not callable(handler):
            raise ValueError("command has no handler")
        return int(handler(args))
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"repository audit error: {exc}", file=sys.stderr)
        return 2
