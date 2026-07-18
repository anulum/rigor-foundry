# Remediation execution authority and ledger

An approved remediation plan is advisory until it is both explicitly authorised
and actually executed. RigorFoundry separates those two acts. The
`remediation_authority` module grants bounded, independent authority to execute
an exact approved plan; the `remediation_executor` module records an attested
execution ledger against that authority. Neither module runs a procedure, spawns
a process, or mutates a repository — execution happens elsewhere, under the
authority, and its attested outcome is only validated and content-addressed here.

## Execution authority

An `ExecutionAuthority` binds an independently approved `RemediationPlan` to an
`ExecutionBudget` and an explicit grant:

- **Approved plan only.** Authority requires a plan in the `approved` state with
  an independent approval; an advisory plan cannot be authorised.
- **Author excluded.** The grantor is never the plan's author, so authoring a
  plan never authorises its own execution.
- **Bounded validity.** The grant has a UTC window (`granted_at` before
  `expires_at`) and a `mode`: `observe` authorises a non-mutating dry run only,
  while `execute` authorises attested mutation.
- **Aggregate budget.** `ExecutionBudget` caps cumulative wall and CPU seconds,
  peak memory, and the number of executed steps. Every plan step's declared
  per-step budget must fit within the aggregate ceiling.

```python
from rigor_foundry.remediation_authority import ExecutionAuthority, ExecutionBudget

budget = ExecutionBudget.build(
    wall_seconds=3600, cpu_seconds=3600, memory_mb=1024, max_steps=10
)
authority = ExecutionAuthority.build(
    approved_plan,
    budget,
    authority_id="authority-1",
    repository_id="repo-a",
    granted_by="release-owner",
    granted_at="2026-07-15T12:10:00Z",
    expires_at="2026-07-15T18:10:00Z",
    mode="execute",
)
```

`authority.authorises(plan)` is true only for the exact approved plan the grant
binds.

## Attested execution ledger

`ExecutionLedger.admit` records an attested execution against a plan, an
authority, and covering isolation claims. It proves the execution invariants and
never performs the work:

- **Authority and order.** The authority must bind the exact approved plan, the
  window must not run backwards, and the lane executions must follow the plan's
  dependency- and conflict-safe batches exactly.
- **Isolation.** Each lane names one in-repository `ExecutionClaim` whose write
  set covers the lane's write set; claims are unique.
- **Step fidelity.** Each `StepOutcome` matches its plan step, carries the plan
  step's idempotency key, fits the authority budget, and — when executed —
  captures evidence covering the step's declared outputs. A rolled-back step
  must correspond to a step that declared a rollback.
- **Budget, idempotency, mode.** Cumulative consumption stays within the
  aggregate budget, an idempotency key never attests two divergent outcomes, and
  observe authority admits no executed step.
- **Failure propagation.** A lane is skipped exactly when a prerequisite lane
  failed; a lane whose prerequisite failed may not have run.

The ledger resolves to `succeeded`, `failed`, or `rolled-back` and is
content-addressed.

```python
from rigor_foundry.remediation_executor import ExecutionLedger

ledger = ExecutionLedger.admit(
    plan=approved_plan,
    authority=authority,
    lane_executions=(base_execution, dependent_execution),
    claims=(base_claim, dependent_claim),
    started_at="2026-07-15T12:15:00Z",
    finished_at="2026-07-15T12:20:00Z",
)
print(ledger.resolution)
```

`ExecutionLedger.from_dict` re-verifies structural integrity, the resolution, and
the self-contained mode, budget, and idempotency invariants; the plan-bound
checks are the admission gate in `admit`. Both surfaces are reachable via
submodule import (`rigor_foundry.remediation_authority` and
`rigor_foundry.remediation_executor`).
