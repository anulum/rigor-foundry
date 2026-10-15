# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — GitHub Actions workflow security candidates
"""Inspect executable YAML positions without running actions or expressions."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .candidate_anchor import RepositoryTreeAnchor, TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .models import Candidate
from .workflow_expressions import has_untrusted_run_interpolation, selects_pull_request_code
from .workflow_yaml import WorkflowFormatError, WorkflowValue, parse_workflow_yaml

_ACTION_PIN = re.compile(
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-fA-F]{40}\Z"
)
_DOCKER_PIN = re.compile(r"docker://[^\s@]+@sha256:[0-9a-f]{64}\Z")
_CHECKOUT = re.compile(r"actions/checkout@", re.IGNORECASE)
MAX_ACTION_EXECUTION_POSITIONS = 4_096
_RULES = {
    "GA001-unpinned-action-reference": (
        "An executable action or reusable workflow reference lacks a full commit or image digest.",
        "Inspect the action owner and exact upstream object, then pin a reviewed full commit SHA "
        "or Docker SHA-256 digest. Local repository actions do not need external revision pins.",
    ),
    "GA002-run-context-interpolation": (
        "A run script directly interpolates event data, a branch name or an input.",
        "Trace the exact trigger and value into the generated script. Prefer an intermediate "
        "environment variable with shell-appropriate quoting. This signal is not an exploit proof.",
    ),
    "GA003-pull-request-target-checkout": (
        "A pull_request_target checkout selects PR code or an unresolved dynamic source.",
        "Review token permissions, secrets, downstream execution and the checkout version's fork "
        "protections, including allow-unsafe-pr-checkout. Prefer trusted base checkout; this "
        "configuration candidate does not prove that untrusted code was executed.",
    ),
}


@dataclass
class _ExecutionBudget:
    """Bound repeated executable positions independently of YAML alias allocation."""

    positions: int = 0

    def consume(self, value: WorkflowValue) -> None:
        """Refuse before analysing an amplified job or step occurrence."""
        self.positions += 1
        if self.positions > MAX_ACTION_EXECUTION_POSITIONS:
            raise WorkflowFormatError("actions-execution-position-limit", value.line)


def _source_candidate(
    item: TrackedFile,
    value: WorkflowValue,
    rule: str,
    symbol: str,
) -> Candidate:
    """Bind a security signal to exact blob lines with digest-only evidence."""
    rationale, verification = _RULES[rule]
    lines = (item.text or "").splitlines(keepends=True)
    span = "".join(lines[value.line - 1 : value.end_line]).encode("utf-8")
    return Candidate.build(
        category="github-actions",
        rule_id=rule,
        anchor=TrackedBlobAnchor.build(item, line_start=value.line, line_end=value.end_line),
        symbol=symbol,
        evidence=f"file_sha256={item.content_digest}; span_sha256={hashlib.sha256(span).hexdigest()}",
        confidence="medium",
        rationale=rationale,
        verification=verification,
    )


def _unscanned(
    inventory: GitInventory, item: TrackedFile, error: WorkflowFormatError
) -> Candidate:
    """Represent every incomplete workflow analysis without claiming cleanliness."""
    line = max(1, min(error.line, max(1, len((item.text or "").splitlines()))))
    return Candidate.build(
        category="governance",
        rule_id="GV006-unscanned-github-actions",
        anchor=(
            RepositoryTreeAnchor.build(inventory, path=item.path)
            if item.scanned_blob_id is None
            else TrackedBlobAnchor.build(item, line_start=line)
        ),
        symbol=error.reason,
        evidence=f"file_sha256={item.content_digest}; reason={error.reason}",
        confidence="high",
        rationale="A tracked GitHub Actions owner could not be completely analysed.",
        verification="Read the exact tracked blob, resolve the bounded parser or structural "
        "limitation, and rerun. An unexplained incomplete owner cannot support a clean claim.",
    )


def _pinned(reference: str) -> bool:
    """Accept local references and immutable external action/image revisions."""
    if reference.startswith("./"):
        return ".." not in PurePosixPath(reference).parts and "${{" not in reference
    return (
        _ACTION_PIN.fullmatch(reference) is not None
        or _DOCKER_PIN.fullmatch(reference) is not None
    )


def _target_event(root: dict[str, WorkflowValue]) -> bool:
    """Distinguish target events across scalar, sequence and mapping declarations."""
    trigger = root.get("on")
    if trigger is None:
        raise WorkflowFormatError("missing-workflow-trigger")
    if trigger.kind == "scalar":
        return trigger.text == "pull_request_target"
    if trigger.kind == "sequence":
        events = tuple(value.scalar() for value in trigger.items)
        return "pull_request_target" in events
    return "pull_request_target" in trigger.mapping()


def _steps(
    item: TrackedFile,
    values: WorkflowValue,
    *,
    target: bool,
    scope: str,
    budget: _ExecutionBudget,
) -> tuple[Candidate, ...]:
    """Inspect only actual executable step positions and checkout input mappings."""
    candidates: list[Candidate] = []
    for index, value in enumerate(values.sequence()):
        budget.consume(value)
        step = value.mapping()
        symbol = f"{scope}/step/{index}"
        uses = step.get("uses")
        run = step.get("run")
        if uses is not None and run is not None:
            raise WorkflowFormatError("conflicting-step-execution", value.line)
        if uses is None and run is None:
            raise WorkflowFormatError("missing-step-execution", value.line)
        if uses is not None:
            reference = uses.scalar()
            if not _pinned(reference):
                candidates.append(
                    _source_candidate(item, uses, "GA001-unpinned-action-reference", symbol)
                )
            if target and _CHECKOUT.match(reference):
                inputs = step.get("with")
                if inputs is not None:
                    for key, selector in inputs.mapping().items():
                        if key in {"ref", "repository"} and selects_pull_request_code(
                            selector.scalar()
                        ):
                            candidates.append(
                                _source_candidate(
                                    item,
                                    selector,
                                    "GA003-pull-request-target-checkout",
                                    f"{symbol}/{key}",
                                )
                            )
        if run is not None and has_untrusted_run_interpolation(run.scalar()):
            candidates.append(
                _source_candidate(item, run, "GA002-run-context-interpolation", symbol)
            )
    return tuple(candidates)


def _workflow_candidates(item: TrackedFile, document: WorkflowValue) -> tuple[Candidate, ...]:
    """Read job-level reusable actions and concrete job steps from one workflow."""
    root = document.mapping()
    target = _target_event(root)
    jobs = root.get("jobs")
    if jobs is None:
        raise WorkflowFormatError("missing-workflow-jobs")
    candidates: list[Candidate] = []
    budget = _ExecutionBudget()
    for index, value in enumerate(jobs.mapping().values()):
        budget.consume(value)
        job = value.mapping()
        scope = f"job/{index}"
        uses = job.get("uses")
        steps = job.get("steps")
        if uses is not None and steps is not None:
            raise WorkflowFormatError("conflicting-job-execution", value.line)
        if uses is not None:
            if not _pinned(uses.scalar()):
                candidates.append(
                    _source_candidate(item, uses, "GA001-unpinned-action-reference", scope)
                )
        elif steps is not None:
            candidates.extend(_steps(item, steps, target=target, scope=scope, budget=budget))
        else:
            raise WorkflowFormatError("missing-job-execution", value.line)
    return tuple(candidates)


def _action_candidates(item: TrackedFile, document: WorkflowValue) -> tuple[Candidate, ...]:
    """Inspect composite metadata while leaving native JavaScript/Docker actions alone."""
    runs = document.mapping().get("runs")
    if runs is None:
        raise WorkflowFormatError("missing-action-runs")
    fields = runs.mapping()
    using = fields.get("using")
    if using is None:
        raise WorkflowFormatError("missing-action-runtime", runs.line)
    if using.scalar() != "composite":
        return ()
    steps = fields.get("steps")
    if steps is None:
        raise WorkflowFormatError("missing-composite-steps", runs.line)
    return _steps(item, steps, target=False, scope="composite", budget=_ExecutionBudget())


def scan_github_actions(inventory: GitInventory) -> tuple[Candidate, ...]:
    """Return candidates for tracked workflow YAML and action metadata.

    Only direct .github/workflows YAML files and action.yml/action.yaml owners
    are inspected. A composite action is analysed independently: caller event
    propagation, reusable workflow execution and shell data-flow are not inferred.
    """
    candidates: list[Candidate] = []
    for item in inventory.files:
        path = PurePosixPath(item.path)
        workflow = path.parent.as_posix() == ".github/workflows" and path.suffix in {
            ".yml",
            ".yaml",
        }
        action = path.name in {"action.yml", "action.yaml"}
        if not workflow and not action:
            continue
        if item.text is None:
            candidates.append(
                _unscanned(inventory, item, WorkflowFormatError("unreadable-actions-owner"))
            )
            continue
        try:
            document = parse_workflow_yaml(item.text)
            candidates.extend(
                _workflow_candidates(item, document)
                if workflow
                else _action_candidates(item, document)
            )
        except WorkflowFormatError as exc:
            candidates.append(_unscanned(inventory, item, exc))
    return tuple(candidates)
