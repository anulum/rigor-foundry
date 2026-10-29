<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
RigorFoundry — Interpreter test partitions and coverage
-->

# Interpreter tests and coverage

Each advertised Python interpreter runs the complete pytest collection in eight
deterministic partitions. The final collection, after ordinary collection hooks,
is the sole membership source. A longest-first schedule assigns whole modules
to the least loaded partition using `.github/test-timings.json`. Item order,
parameters and fixture context stay with the original pytest items. New modules
receive the median across all valid historical module durations; removed modules are never collected
from timing hints. The explicit
`item-round-robin-v1` strategy permits a no-profile cold start; the CI-declared
`module-lpt-v1` strategy requires its profile. Missing, empty, malformed, linked
or unreadable expected profiles fail the run. Every
partition installs the original hash-locked test, native and security tools and
the separate documentation renderer.

The workflow invokes `python -m tools.run_test_shard --index 0 --count 8` for
each index from zero through seven. This launcher requires the GitHub repository,
run, attempt and head identity. It refuses existing output at `.rigor-test-shard`
and activates the partition plugin only on its actual pytest command. Child
pytest invocations retain their own arguments. Filters, collect-only and early
termination cannot produce a successful shard.

A successful receipt requires actual process exit zero after finalisation,
complete setup/call/teardown observations for the selected cases, matching
JUnit counts and usable branch coverage. Existing skip and expected-failure
semantics remain valid. The receipt binds the exact command, full Python
version, source/configuration bytes, ordered collection, index/count and hashes
of retained observations, JUnit and the raw `.coverage` database. A provisional
observation file alone is never success evidence.

All partitions and consumers use the same versioned timing snapshot from their
checkout. Its normalized content is bound into the source identity and retained
observations in schema version 2; the launcher and union reject a different
profile, strategy, algorithm version or legacy receipt. Costs use positive
integer microseconds (nearest-even rounding, minimum one), doubled internally
to represent even-sized medians exactly. Duration ties use module path order;
load ties use the lowest shard index. Timing hints
cannot remove tests or become coverage evidence. The initial snapshot aggregates
all four Python 3.12 JUnit shards from workflow run `40844337454` at revision
`1ba6c7893ef43102ca391aa7f621f7f19895c620`, containing 6,473 tests across
374 modules. Durations are advisory seconds including setup and teardown.
Refresh the snapshot from a complete successful collection and review the diff;
independently restored mutable caches must never choose partition membership.
Eight partitions reduce predicted per-job test work, but hosted runtime, queue
delay and runner-minute changes require measurement after publication.

Each interpreter's union job downloads only artifacts from the same run attempt.
`python -m tools.combine_test_shards --directory test-shards --count 8` requires
exactly `shard-0` through `shard-7`, validates every input and refuses missing,
corrupt, incomplete or mismatched evidence. Failed-job-only reruns cannot reuse
successful partitions from an earlier attempt; rerun the complete workflow.
The raw databases remain available after combining. Existing subprocess
measurement and checkout/installed-package path aliases apply to the union.

The complete union must reach the existing 98% package threshold and 100%
native-dispatch threshold on **every** advertised interpreter. A partial shard
has no independent package coverage threshold. Python 3.12 alone exports the
original `coverage-python-3.12` artifact with exactly `coverage.xml`, which the
separate coverage workflow publishes through OIDC with search disabled and
upload errors fatal.

The protected `quality`, `distribution`, `coverage` and three interpreter check
names are strict top-level aggregates. They accept only success of their complete
execution categories; failure, cancellation, skipping or an absent result fails
the aggregate. The final CI gate additionally requires every aggregate. The
versioned workflow inventory and source guard check both execution jobs and the
complete caller graph. The quality workflow tests the partition infrastructure
and its owning tests with whole-file statement and branch coverage of 100%.

An independent quality step exercises the fixed context resolver and retained
source lifetimes. It measures the complete resolver and both owning test files
at 100% statement and branch coverage, including all supported context formats,
the separate component/corpus parser domains and reference-budget refusal.
Keeping its coverage process separate preserves the documentation renderer's
native dependency initialization. The source guard rejects removal, duplication,
conditional execution, a lower threshold or a reduced measured owner set.
