<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Apache License 2.0; see LICENSE. -->
<!-- © Concepts 1996–2026 Miroslav Šotek. All rights reserved. -->
<!-- © Code 2020–2026 Miroslav Šotek. All rights reserved. -->
<!-- ORCID: 0009-0009-3560-0851 -->
<!-- Contact: www.anulum.li | protoscience@anulum.li -->
<!-- RigorFoundry — selected dispatch applicability -->

# Selected dispatch applicability

`evaluate_selected_dispatch_applicability_v2()` composes actual request
extraction and clause evaluation under one selected source context. The
application supplies its authenticated semantics verifier, installed constraint
reader, and the lock and projection digests observed by that task's boot.
The request cannot choose these sources.

```python
from rigor_foundry.selected_dispatch_applicability_v2 import (
    evaluate_selected_dispatch_applicability_v2,
)

# These values come from the application's installed providers and current boot.
evaluated = evaluate_selected_dispatch_applicability_v2(
    request,
    verifier=installed_semantics_verifier,
    observed_lock_digest=task_lock_digest,
    observed_projection_digest=task_projection_digest,
    context_for=installed_constraint_reader,
)
assert evaluated.guard_admissible is False
```

The function enters `HostSelectedClauseSemanticsVerifierV2.verified_context()`
once. That context yields the selected semantics, the actual held chain state,
and its verified proof. Extraction and evaluation use that same chain, without
reopening the chain provider. The function returns only after closing source
checks succeed. The older two-value `verified_lease()` API retains its existing
shape and closing checks.

## Actual extraction and applicability

The selected extractor checks the complete canonical invocation against the
selected adapter, operation catalogue, extractor registry, path scope, lock and
projection. The first operation is `local-file-write.atomic-replace`. Its
decoded content, target and fixed variant must match the declarations. Its
descriptor-backed path check closes before extraction returns.

Every ordered part then requires an active covering admit. A covering veto
refuses. All applicable constraints must pass the fixed evaluator boundary.
Concrete selector containment respects path component boundaries and exclusions.
The first operation has no registered route extractor: an applicable route
constraint refuses before reading an installed route context.

The four public built-in evaluators use the canonical semantics parameter
rules, including closed fields, valid UTC ranges and finite decimal ceilings.
The window evaluator validates every range before testing applicability; a
matching early range cannot hide a malformed later range. Precondition context
is host-computed evidence. The selected authority requirement determines which
effect classes require enforced custody; a cooperative check cannot satisfy
that requirement for those classes.

`SelectedDispatchApplicabilityV2` retains actual extraction, the semantics
proof and the ordered `StageBResultV2` results. Direct record construction does
not reproduce verification. No new stable CLI command or wire version is
introduced by this module-level Python API.

## Journal-backed rate context

An installed `EffectJournalRateSourceV2` binds the actual extracted part before
reading its rate clauses. The application holds a real `EffectJournalStoreV2`
exclusive lease for those reads and independently supplies the complete-history
origin, fresh UTC clock, verified honoured closures and each historical
operation's original catalogue.

The source rescans the retained descriptor for every rate read. It checks full
frame consistency and operation replay, including records appended beyond an
earlier selected prefix. Missing history or catalogue, changed bytes, overlapping
open targets and unusable clock data refuse. An operation intent still counts
after its independently honoured closure. The signed window includes its start
boundary. A new journal header cannot prove that the whole window was retained.

Journal reads and append durability use shared internal descriptor I/O. They
do not import the permit-consumption ledger or select grant accounting.
This operation replay contract refuses event kinds whose semantics it does not
implement, including partial-operation, target-reconciliation, trust-activation
and key-revocation events. A frame accepted by the journal parser does not make
such history usable by this consumer; it cannot silently ignore those events.

## Execution boundary

Applicability leaves the target file unchanged and supplies no grant, reserved
use, effect permit or handler capability. `guard_admissible` is always false.
The application still needs protected installed-code and source custody,
current grants and permits, transaction accounting, final revalidation and a
qualified handler before performing an effect. Fixture signatures and native
format transcripts demonstrate test integrity; they establish no owner
ratification or protected deployment.

See [canonical clause semantics](clause-semantics.md) and
[rule-chain candidate inspection](rule-chain-candidate.md) for the underlying
source and native-capture boundaries.
