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

Each advertised Python interpreter runs the complete pytest collection in four
deterministic partitions. Partition `i` executes items at positions `i, i+4, …`
in the final ordered collection, after ordinary collection hooks. Class,
parameter and fixture behavior stays with the original pytest items. Every
partition installs the original hash-locked test, native and security tools and
the separate documentation renderer.

The workflow invokes `python -m tools.run_test_shard --index 0 --count 4` for
each index from zero through three. This launcher requires the GitHub repository,
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

Each interpreter's union job downloads only artifacts from the same run attempt.
`python -m tools.combine_test_shards --directory test-shards --count 4` requires
exactly `shard-0` through `shard-3`, validates every input and refuses missing,
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
