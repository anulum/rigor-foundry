# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — pre-effect campaign admission
"""Hold host-provided admission across real campaign creation.

This opt-in cooperative boundary does not authenticate its provider or replace
the existing local API. Install providers only from trusted host composition.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path

from .campaign_models import AuditCampaign, CampaignPurpose
from .campaign_workflow import create_campaign
from .git_provenance import GitTrustPolicy


@dataclass(frozen=True)
class CampaignCreation:
    """Bind every creation argument before requesting a host admission lease.

    Relative policy and audit paths retain create_campaign's repository-relative
    semantics. An absolute repository root prevents a changed current directory
    from changing the requested repository. This object does not pin filesystem
    identity or itself grant permission; existing workflow custody checks remain.
    """

    repository_root: Path
    policy_path: Path
    audit_root: Path
    project: str
    campaign_id: str
    actor: str
    expected_runs: int
    purpose: CampaignPurpose = "diagnostic"
    required_model_witnesses: int | None = None
    git_trust_policy: GitTrustPolicy | None = None

    def __post_init__(self) -> None:
        """Reject ambient-cwd-dependent repository selection without filesystem IO."""
        if not self.repository_root.is_absolute():
            raise ValueError("admitted campaign requires an absolute repository root")


AdmissionLease = Callable[[CampaignCreation], AbstractContextManager[None]]


def create_admitted_campaign(
    request: CampaignCreation,
    *,
    admission: AdmissionLease,
) -> tuple[Path, AuditCampaign]:
    """Create a campaign only inside a successfully acquired host admission lease.

    The trusted provider must check current exact scope, grants and adapter facts
    before entering, and retain its synchronization until exit. Acquisition errors
    propagate without entering the existing workflow. Revocation during an already
    admitted operation and hostile same-process callers are not contained here.
    The provider must not suppress workflow exceptions; suppression is refused
    explicitly instead of returning an apparent successful result.

    No lease or decision is cached or inferred from a role, tool name or prior
    invocation. This API adds no serialized grant format or publication authority.
    """
    with admission(request):
        result = create_campaign(
            request.repository_root,
            request.policy_path,
            audit_root=request.audit_root,
            project=request.project,
            campaign_id=request.campaign_id,
            actor=request.actor,
            expected_runs=request.expected_runs,
            purpose=request.purpose,
            required_model_witnesses=request.required_model_witnesses,
            git_trust_policy=request.git_trust_policy,
        )
        return result
    raise RuntimeError("admission provider suppressed a campaign failure")
