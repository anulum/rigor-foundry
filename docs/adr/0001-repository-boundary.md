<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
RigorFoundry — Repository boundary decision
-->

# Repository boundary

**Status:** Adopted. This record describes the maintained product architecture.

## Context

Adopters need repository evidence they can reproduce, compare and review
against their own policy. A scanner sees only the sources and tools within its
declared scope. A candidate can identify a problem, an intentional boundary or
a case that needs more evidence. The repository owner remains responsible for
deciding which policy applies and who can approve changes.

## Decision

RigorFoundry runs locally against an explicitly selected repository. Ordinary
scans read Git-tracked inputs, resolve the repository policy and emit candidates
bound to the scanned blobs or tree. Where policy declares ignored evidence,
that evidence is recorded separately with its own limits. Audit results carry
scope and provenance so callers can distinguish complete observations from
partial or unavailable evidence.

Review is a separate step. A review record binds a decision to the exact
candidate and report. A repository gate consumes the policy and the evidence
required by that gate. A remediation plan remains advisory until an
independent approval binds its exact inputs and scope. Execution, where
supported, requires a separately qualified host and an explicit authority
path. An audit, review, gate or plan cannot grant that authority by itself.

The repository owns the Python package, CLI, editor extension, contracted
report formats and supported adapters. Adopter repositories own their policy,
source, findings and decisions. Public distributions contain the product and
its documentation. Private adopter evidence and operational records stay in
their existing custody boundaries. Publication, deployment and fleet
activation require separate authorisation.

## Alternatives considered

A scanner with automatic remediation would shorten the path from a finding
to a change. It would also couple an incomplete observation to mutation. A
central hosted service could make cross-repository comparison easier. It
would introduce source transfer, shared credentials and dependence on service
availability for ordinary audits. The maintained design keeps the local
evidence path usable independently and admits additional authority only at
the boundary that needs it.

## Consequences

Callers can run audits and review evidence without authorising repository
changes. Exact source and policy identities make stale evidence detectable.
A changed scope or unsupported input can require another observation.
This separation adds explicit verification and approval steps before a
remediation can run.

Changes to the boundary must preserve the documented public CLI and schema
contracts. Qualify new read, write, host or publication behaviour through its
normal entry point and carry the resulting evidence into review.

See the [architecture](../architecture.md) for the evidence pipeline and
[security](../security.md) for the supported trust boundary.
