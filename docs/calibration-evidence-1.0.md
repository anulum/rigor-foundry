<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
-->

# Calibration evidence for the 1.0 stable contract

RigorFoundry keeps a rule in `probation` unless adjudicated field evidence
satisfies an explicit maturity policy. This page publishes the bounded evidence
used for the first rule admitted to the 1.0 stable enforcement set. It is a
measurement report, not a certification or a claim that every surfaced
candidate is a vulnerability.

## Frozen corpus and method

The corpus contains ten exact, detached Git trees from distinct product
repositories. RigorFoundry scanned those trees read-only with scanner `0.3.0`
and rule pack `rigor-foundry/1.17.0`. The complete reports contain 23,119
anchored candidates across all 63 rules.

Only `AS001-dynamic-code-execution` was preregistered for possible stable
activation. Its twelve cases span three repositories and retain the exact
candidate IDs and anchors selected before the earlier calibration attempt.
Every case was reviewed again against the current report digest; no old label
or elapsed time was rebound.

Two independent reviewers received alternating cases. Each review interval
started before exact Git-blob retrieval and ended after the decision. Intervals
were positive, sequential, and non-overlapping. Each record was validated
against its current content-addressed report using the shipped ReviewRecord
schema and review validator.

The frozen adopter policy requires at least six reviews, two repositories, two
reviewers, and five positive decisions. It permits at most 2,000 false-positive
basis points, a median review effort of 600 seconds, and a nearest-rank p90 of
1,200 seconds.

## Measured outcome

| Measure | Result |
| --- | ---: |
| Adjudicated cases | 12 |
| Distinct repositories | 3 |
| Distinct reviewers | 2 |
| Valid findings | 2 |
| Accepted protocol boundaries | 9 |
| Invalid candidates | 1 |
| Policy-positive decisions | 11 |
| Observed policy-positive precision | 91.7% (11/12) |
| False-positive rate | 8.3% (834 basis points) |
| Median active review effort | 17 seconds |
| Nearest-rank p90 active effort | 62 seconds |

`AS001-dynamic-code-execution` therefore has status `active` with no probation
reason under the frozen policy. The other 62 rules remain `probation`; candidate
volume, confidence, old reviews, or a clean scan cannot activate them.

The positive definition is deliberately explicit: both a valid finding and an
accepted, bounded protocol use count as positive. An accepted boundary does not
mean that arbitrary dynamic execution is safe; it means the exact occurrence
was justified by a specific test, generated-code, or validated-DSL boundary
with reopen triggers.

## Reproducibility anchors

| Artefact | SHA-256 or protocol digest |
| --- | --- |
| Current-pack corpus index | `24570943147d441d267719c3deda72c613cf84888e590bd038966e31f815a5cb` |
| Frozen AS001 selection | `ff3b93f942fa1689db0d1d6dd7a020787cc75518ebd787b79460c7442030318e` |
| Reviewer A six-case result | `5946815fadc8074ca68de4dc4be313b0550add9885deb6dcfc74f6a924f53201` |
| Reviewer B six-case result | `258c4cbfa981827b222e0f7a86675434f8de3248385bcbe53921c303bb4f51ab` |
| Maturity input manifest | `606dc3ec5273d53316dcd4737e4293da668e01a14ff86eae710f52d9e15e2f19` |
| Maturity report file | `3e7060250fea907949ac127e5b9d3ef107bb07fc978cfec30928d2a6bbfdc64e` |
| Maturity report identity | `32d07e3ef973065098c952dfbaacb55188ae65951a05fdde936353517b66264a` |
| Maturity policy identity | `afff5163c2c5c77425227e0de728717a10298e7ef0145edba33fc97f81403b81` |
| Rule-pack identity | `ff5ecbeb3b0df2034902eb8936bf66c746a4693090f8f520eb2e074549f4b835` |

Raw reports and reviews are retained as internal evidence because they contain
repository paths and case-level operational context. The aggregate numbers and
digests above expose the method and allow custody checks without publishing
adopter-sensitive details.

## Statistical and product limits

- The corpus is a deterministic convenience sample of ten product trees, not a
  random sample of all adopters. The 91.7% value must not be generalised to
  fleet-wide prevalence or unrelated codebases.
- Recall is **unmeasured** because the corpus has no independently constructed
  ground-truth inventory of every missed dynamic-execution occurrence.
- Twelve cases are too few for a broad universal-quality claim. The result is a
  bounded admission decision for one rule under one published policy.
- Candidate confidence is not probability. Deterministic replay establishes
  repeatability, not correctness.
- New rule-pack semantics, changed anchors, changed report digests, expired
  reviews, or a failed threshold require fresh evidence. No maturity credit is
  inherited merely because a rule identifier remains the same.
- This evidence grants no remediation, repository-write, fleet-activation,
  legal-conformity, or release authority.
