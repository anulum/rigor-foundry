# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit remediation execution authority
"""Grant explicit, independent, budget-bounded authority to execute a plan."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_utc_timestamp,
)
from .models import canonical_digest, require_integer, require_mapping, require_string
from .remediation_plan import ProcedureStep, RemediationPlan

AUTHORITY_SCHEMA_VERSION = "1.0"

ExecutionMode = Literal["observe", "execute"]
_MODES: frozenset[str] = frozenset({"observe", "execute"})

_WALL_SECONDS_CEILING = 86_400
_CPU_SECONDS_CEILING = 86_400
_MEMORY_MB_CEILING = 65_536
_MAX_STEPS_CEILING = 1_000

AUTHORITY_NOTICE = (
    "This record grants bounded authority to execute an independently approved "
    "remediation plan; it does not itself execute anything. Execution remains an "
    "explicit, separately attested act, and observe authority forbids any "
    "mutating step."
)


@dataclass(frozen=True)
class ExecutionBudget:
    """An aggregate wall, CPU, memory, and step ceiling for one execution.

    Parameters
    ----------
    wall_seconds:
        Maximum cumulative wall-clock seconds the whole execution may consume.
    cpu_seconds:
        Maximum cumulative CPU seconds the whole execution may consume.
    memory_mb:
        Maximum peak resident memory, in mebibytes, any single step may reach.
    max_steps:
        Maximum number of steps that may actually execute.

    """

    wall_seconds: int
    cpu_seconds: int
    memory_mb: int
    max_steps: int
    budget_digest: str

    @classmethod
    def build(
        cls,
        *,
        wall_seconds: int,
        cpu_seconds: int,
        memory_mb: int,
        max_steps: int,
    ) -> ExecutionBudget:
        """Build one validated, content-addressed aggregate budget ceiling."""
        fields: dict[str, object] = {
            "schema_version": AUTHORITY_SCHEMA_VERSION,
            "wall_seconds": require_integer(wall_seconds, "budget.wall_seconds", minimum=1),
            "cpu_seconds": require_integer(cpu_seconds, "budget.cpu_seconds", minimum=1),
            "memory_mb": require_integer(memory_mb, "budget.memory_mb", minimum=16),
            "max_steps": require_integer(max_steps, "budget.max_steps", minimum=1),
        }
        for field, ceiling in (
            ("wall_seconds", _WALL_SECONDS_CEILING),
            ("cpu_seconds", _CPU_SECONDS_CEILING),
            ("memory_mb", _MEMORY_MB_CEILING),
            ("max_steps", _MAX_STEPS_CEILING),
        ):
            if cast(int, fields[field]) > ceiling:
                raise ValueError(f"budget.{field} exceeds the aggregate ceiling")
        return cls(
            wall_seconds=cast(int, fields["wall_seconds"]),
            cpu_seconds=cast(int, fields["cpu_seconds"]),
            memory_mb=cast(int, fields["memory_mb"]),
            max_steps=cast(int, fields["max_steps"]),
            budget_digest=canonical_digest(fields),
        )

    def admits_step(self, step: ProcedureStep) -> bool:
        """Return whether one plan step's declared budget fits this ceiling."""
        return (
            step.timeout_seconds <= self.wall_seconds
            and step.cpu_seconds <= self.cpu_seconds
            and step.memory_mb <= self.memory_mb
        )

    def within(
        self,
        *,
        wall_seconds: int,
        cpu_seconds: int,
        peak_memory_mb: int,
        executed_steps: int,
    ) -> bool:
        """Return whether an attested aggregate consumption stays within budget."""
        return (
            wall_seconds <= self.wall_seconds
            and cpu_seconds <= self.cpu_seconds
            and peak_memory_mb <= self.memory_mb
            and executed_steps <= self.max_steps
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one aggregate budget."""
        return {
            "schema_version": AUTHORITY_SCHEMA_VERSION,
            "wall_seconds": self.wall_seconds,
            "cpu_seconds": self.cpu_seconds,
            "memory_mb": self.memory_mb,
            "max_steps": self.max_steps,
            "budget_digest": self.budget_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ExecutionBudget:
        """Parse and integrity-check one aggregate budget."""
        data = require_mapping(value, "budget")
        if data.get("schema_version") != AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported budget schema version")
        budget = cls.build(
            wall_seconds=require_integer(
                data.get("wall_seconds"), "budget.wall_seconds", minimum=1
            ),
            cpu_seconds=require_integer(data.get("cpu_seconds"), "budget.cpu_seconds", minimum=1),
            memory_mb=require_integer(data.get("memory_mb"), "budget.memory_mb", minimum=16),
            max_steps=require_integer(data.get("max_steps"), "budget.max_steps", minimum=1),
        )
        if data.get("budget_digest") != budget.budget_digest:
            raise ValueError("budget digest does not match its content")
        return budget


@dataclass(frozen=True)
class ExecutionAuthority:
    """One explicit, independent grant to execute an exact approved plan.

    Parameters
    ----------
    authority_id:
        Unique authority identifier.
    repository_id:
        Repository whose claims the execution is confined to.
    plan_digest:
        The exact approved plan this authority binds.
    lock_digest:
        The effective-profile lock the plan resolved against.
    granted_by:
        Independent identity granting the authority; never the plan author.
    granted_at:
        UTC grant time.
    expires_at:
        UTC expiry after which the authority no longer authorises execution.
    mode:
        ``observe`` authorises a non-mutating dry run only; ``execute``
        authorises attested mutation.
    budget:
        The aggregate resource ceiling the execution may consume.

    """

    authority_id: str
    repository_id: str
    plan_digest: str
    lock_digest: str
    granted_by: str
    granted_at: str
    expires_at: str
    mode: ExecutionMode
    budget: ExecutionBudget
    authority_digest: str

    @classmethod
    def build(
        cls,
        plan: RemediationPlan,
        budget: ExecutionBudget,
        *,
        authority_id: str,
        repository_id: str,
        granted_by: str,
        granted_at: str,
        expires_at: str,
        mode: ExecutionMode,
    ) -> ExecutionAuthority:
        """Grant authority over an independently approved plan, author excluded."""
        if plan.state != "approved" or plan.approval is None:
            raise ValueError("execution authority requires an independently approved plan")
        grantor = require_string(granted_by, "authority.granted_by")
        if grantor == plan.created_by:
            raise ValueError("the plan author cannot authorise its own execution")
        return cls._assemble(
            authority_id=authority_id,
            repository_id=repository_id,
            plan_digest=plan.plan_digest,
            lock_digest=plan.lock_digest,
            granted_by=grantor,
            granted_at=granted_at,
            expires_at=expires_at,
            mode=mode,
            budget=budget,
        )

    @classmethod
    def _assemble(
        cls,
        *,
        authority_id: str,
        repository_id: str,
        plan_digest: str,
        lock_digest: str,
        granted_by: str,
        granted_at: str,
        expires_at: str,
        mode: ExecutionMode,
        budget: ExecutionBudget,
    ) -> ExecutionAuthority:
        """Assemble and content-address an authority from validated fields."""
        if mode not in _MODES:
            raise ValueError("authority.mode is unsupported")
        granted = require_utc_timestamp(granted_at, "authority.granted_at")
        expires = require_utc_timestamp(expires_at, "authority.expires_at")
        if parse_utc_timestamp(expires, "authority.expires_at") <= parse_utc_timestamp(
            granted,
            "authority.granted_at",
        ):
            raise ValueError("authority.expires_at must be later than granted_at")
        body: dict[str, object] = {
            "schema_version": AUTHORITY_SCHEMA_VERSION,
            "authority_id": require_identifier(authority_id, "authority.authority_id"),
            "repository_id": require_identifier(repository_id, "authority.repository_id"),
            "plan_digest": require_digest(plan_digest, "authority.plan_digest"),
            "lock_digest": require_digest(lock_digest, "authority.lock_digest"),
            "granted_by": require_string(granted_by, "authority.granted_by"),
            "granted_at": granted,
            "expires_at": expires,
            "mode": mode,
            "budget": budget.to_dict(),
        }
        return cls(
            authority_id=cast(str, body["authority_id"]),
            repository_id=cast(str, body["repository_id"]),
            plan_digest=cast(str, body["plan_digest"]),
            lock_digest=cast(str, body["lock_digest"]),
            granted_by=cast(str, body["granted_by"]),
            granted_at=granted,
            expires_at=expires,
            mode=mode,
            budget=budget,
            authority_digest=canonical_digest(body),
        )

    def authorises(self, plan: RemediationPlan) -> bool:
        """Return whether this authority binds the exact approved plan."""
        return (
            plan.state == "approved"
            and plan.approval is not None
            and plan.plan_digest == self.plan_digest
            and plan.lock_digest == self.lock_digest
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one execution authority."""
        return {
            "schema_version": AUTHORITY_SCHEMA_VERSION,
            "authority_id": self.authority_id,
            "repository_id": self.repository_id,
            "plan_digest": self.plan_digest,
            "lock_digest": self.lock_digest,
            "granted_by": self.granted_by,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "mode": self.mode,
            "budget": self.budget.to_dict(),
            "authority_digest": self.authority_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ExecutionAuthority:
        """Parse and integrity-check one execution authority.

        Structural integrity and the content digest are re-verified. The
        author-exclusion check is a grant-time gate in :meth:`build`; it is not
        re-checkable here because the plan author is not stored in the record.
        """
        data = require_mapping(value, "authority")
        if data.get("schema_version") != AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported authority schema version")
        authority = cls._assemble(
            authority_id=require_string(data.get("authority_id"), "authority.authority_id"),
            repository_id=require_string(data.get("repository_id"), "authority.repository_id"),
            plan_digest=require_digest(data.get("plan_digest"), "authority.plan_digest"),
            lock_digest=require_digest(data.get("lock_digest"), "authority.lock_digest"),
            granted_by=require_string(data.get("granted_by"), "authority.granted_by"),
            granted_at=require_utc_timestamp(data.get("granted_at"), "authority.granted_at"),
            expires_at=require_utc_timestamp(data.get("expires_at"), "authority.expires_at"),
            mode=cast(ExecutionMode, require_string(data.get("mode"), "authority.mode")),
            budget=ExecutionBudget.from_dict(data.get("budget")),
        )
        if data.get("authority_digest") != authority.authority_digest:
            raise ValueError("authority digest does not match its content")
        return authority
