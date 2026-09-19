# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed native audit consumer
"""Admit native preparation, then bind each actual invocation to signed expectations."""

from __future__ import annotations

import json
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from pathlib import Path

from .adapter_runtime import BWRAP, OUTPUT_LIMIT
from .adapter_workspace import MAX_PROFILE_FILE_BYTES, MAX_PROFILE_INPUT_BYTES
from .adapters import AdapterInvocation, run_adapter
from .effective_profile import AdapterLock
from .git_provenance import GitTrustPolicy
from .instruction_dispatch import DispatchRequest, DispatchResult, dispatch_instruction_action
from .instruction_scope import ActionScope
from .model_primitives import require_digest, require_identifier
from .models import AdapterSpec, canonical_digest, require_string
from .signed_instruction_dispatch import (
    SignedDispatchState,
    dispatch_request_digest,
    instruction_policy_digest,
    signed_dispatch_lease,
)


@dataclass(frozen=True)
class NativeAuditOperation:
    """Host-registered in-process operation with complete expected stage identities.

    Expectations must come from separately authorised registration evidence,
    never an unauthorised preliminary scan. Runtime generation is an opaque
    host identity; the state lease must check that it is current. The existing
    executor enforces input, output and time bounds, not CPU/RAM or billing.
    Required additional constraints must be enforced by the host or refused.
    """

    repository: Path
    workspace_parent: Path
    spec: AdapterSpec
    tracked_content_digest: str
    runtime_generation: str
    git_trust_policy: GitTrustPolicy
    version_invocation: AdapterInvocation
    audit_invocation: AdapterInvocation

    def __post_init__(self) -> None:
        """Validate immutable operation consistency without filesystem reads or launches."""
        for path in (
            self.repository,
            self.workspace_parent,
            Path(self.git_trust_policy.executable),
            Path(self.audit_invocation.executable_path),
        ):
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError("native dispatch requires explicit absolute canonical paths")
        if self.spec.profile is None or AdapterSpec.from_dict(self.spec.to_dict(), 0) != self.spec:
            raise ValueError("native dispatch requires a canonical built-in profile")
        require_digest(self.tracked_content_digest, "native.tracked_content_digest")
        require_identifier(self.runtime_generation, "native.runtime_generation")
        if self.workspace_parent.is_relative_to(self.repository):
            raise ValueError("native workspace allocation must be outside the source repository")
        version, audit = self.version_invocation, self.audit_invocation
        for observation in (version, audit):
            for value in (
                observation.spec_digest,
                observation.executable_digest,
                observation.configuration_digest,
                observation.input_digest,
                observation.command_digest,
                observation.environment_digest,
            ):
                require_digest(value, "native.invocation_digest")
        require_digest(audit.sandbox_digest, "native.audit_sandbox_digest")
        if (
            version.stage != "version"
            or audit.stage != "audit"
            or version.version is not None
            or version.sandbox_digest is not None
            or audit.version is None
            or version.spec_digest != canonical_digest(self.spec.to_dict())
            or audit.spec_digest != version.spec_digest
            or version.executable_path != audit.executable_path
            or version.executable_digest != audit.executable_digest
            or version.configuration_digest != audit.configuration_digest
            or version.input_digest != audit.input_digest
        ):
            raise ValueError("native invocation expectations are inconsistent")

    @property
    def adapter(self) -> AdapterLock:
        """Bind the expected real audit command to the existing exact adapter contract."""
        expected = self.audit_invocation
        return AdapterLock.build(
            adapter_id=self.spec.name,
            version=require_string(expected.version, "native.audit_version"),
            executable_digest=expected.executable_digest,
            config_digest=expected.configuration_digest,
            command_digest=expected.command_digest,
            environment_digest=expected.environment_digest,
            domains=self.spec.domains,
        )

    @property
    def payload(self) -> bytes:
        """Encode every execution argument and existing bound for exact signature binding.

        This is an in-process comparison encoding, not a public wire parser.
        No request-supplied callback, environment or arbitrary argv is executed.
        """
        return json.dumps(
            {
                "operation": "native-profile-audit",
                "repository": str(self.repository),
                "workspace_parent": str(self.workspace_parent),
                "spec": self.spec.to_dict(),
                "tracked_content_digest": self.tracked_content_digest,
                "runtime_generation": self.runtime_generation,
                "git_trust_policy": self.git_trust_policy.to_dict(),
                "version_invocation": asdict(self.version_invocation),
                "audit_invocation": asdict(self.audit_invocation),
                "input_bytes": MAX_PROFILE_INPUT_BYTES,
                "input_file_bytes": MAX_PROFILE_FILE_BYTES,
                "audit_output_bytes": OUTPUT_LIMIT,
                "version_output_bytes": 8192,
                "version_timeout_seconds": min(self.spec.timeout_seconds, 30),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def request(self, context: ActionScope) -> DispatchRequest:
        """Derive required preparation/read/write/cleanup/process effects from this operation.

        Targets denote host-owned operation scopes, not arbitrary recursive
        filesystem permissions. Cleanup is limited to the unique created child.
        Hosts remain responsible for ancillary runtime reads and OS capabilities.
        """
        if context.runtime != self.runtime_generation:
            raise ValueError("native request runtime differs from registered generation")
        effects = (
            ("read", str(self.repository)),
            ("write", str(self.workspace_parent)),
            ("delete-owned-workspace", str(self.workspace_parent)),
            ("execute", self.git_trust_policy.executable),
            ("execute", str(BWRAP)),
            ("execute", self.audit_invocation.executable_path),
        )
        actions = tuple(
            dict.fromkeys(
                replace(context, effect=effect, target=target) for effect, target in effects
            )
        )
        return DispatchRequest(
            actions,
            self.adapter,
            context.provider,
            context.account,
            context.cost_class,
            context.privacy_class,
            self.payload,
        )


def dispatch_native_audit(
    operation: NativeAuditOperation,
    request: DispatchRequest,
    *,
    state: Callable[[DispatchRequest], AbstractContextManager[SignedDispatchState]],
    clock: Callable[[], datetime],
) -> DispatchResult:
    """Authenticate before preparation and revalidate before each real native invocation.

    The host state factory must authenticate registration, enforce any required
    additional resource constraints and hold source/allocation/runtime custody.
    Its supplied generic execute callback is never invoked: this consumer runs
    the existing built-in adapter owner with the exact signed operation instead.
    A receipt binds the admitted request digest to the actual adapter result.
    Legacy native APIs are unchanged; this function does not activate a gate.
    """
    if not request.actions or operation.request(request.actions[0]) != request:
        raise ValueError("native request does not bind the complete operation and effects")
    with signed_dispatch_lease(request, state=state, clock=clock) as lease:

        def guard(observed: AdapterInvocation) -> None:
            """Compare actual held identities, then check current host authority and signature."""
            expected = (
                operation.version_invocation
                if observed.stage == "version"
                else operation.audit_invocation
            )
            if observed != expected:
                raise PermissionError("actual native invocation differs from signed expectation")
            lease.revalidate(request)

        def execute(_payload: bytes) -> bytes:
            """Run only the bound native operation and return its source-linked receipt."""
            if operation.repository.resolve(strict=True) != operation.repository:
                raise ValueError("native source repository must not be a path alias")
            result = run_adapter(
                operation.repository,
                operation.spec,
                trusted=True,
                git_trust_policy=operation.git_trust_policy,
                expected_tracked_content_digest=operation.tracked_content_digest,
                workspace_parent=operation.workspace_parent,
                invocation_guard=guard,
            )
            return json.dumps(
                {
                    "cleanup": "owned-workspace-removed",
                    "policy_digest": instruction_policy_digest(lease.policy),
                    "request_digest": dispatch_request_digest(request),
                    "runtime_generation": operation.runtime_generation,
                    "result": result.to_dict(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")

        return dispatch_instruction_action(
            request, state=lambda _: nullcontext(replace(lease, execute=execute))
        )
    raise RuntimeError("native host lease suppressed a failure")
