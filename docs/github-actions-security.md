# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — portable GitHub Actions candidate rules

# GitHub Actions security candidates

The read-only repository scanner inspects tracked YAML directly inside
.github/workflows and tracked action.yml/action.yaml metadata. It never runs a
workflow, resolves an action over the network, evaluates an expression, or
constructs Python objects from YAML. All four new rules enter the 1.19.0 rule
pack in probation. Passing author tests supplies no adjudicated calibration
evidence and does not activate enforcement.

| Rule | Source signal | Verification |
|---|---|---|
| GA001-unpinned-action-reference | Actual step action or job reusable-workflow reference lacks an immutable pin. | Review upstream ownership and the exact revision before choosing a full 40-digit commit SHA or Docker SHA-256 digest. |
| GA002-run-context-interpolation | A run value directly interpolates event data, a branch name or an input. | Trace the trigger and script language; prefer an intermediate environment variable with appropriate quoting. |
| GA003-pull-request-target-checkout | A target-event checkout selects PR head/merge/fork code or an unresolved dynamic source. | Review permissions, secrets, downstream execution and checkout protections. |
| GV006-unscanned-github-actions | A relevant tracked owner is unreadable, malformed, ambiguous, unsupported or over budget. | Resolve the exact incomplete owner before making a clean claim. |

## Structural and source boundaries

GA001 reads executable uses positions rather than every matching YAML key.
It includes composite action steps, local actions and reusable workflows.
Local relative references need no external revision pin; parent traversal and
expression-bearing local references are not accepted as immutable local pins.
External actions require a full commit SHA; Docker references require a full
SHA-256 digest. A pin establishes source identity, not upstream trust.

GA002 examines actual run values. Expressions in env, with, if and concurrency
are not inline scripts. Shell comments and quotes do not prevent GitHub's
earlier expression substitution. Constant expression strings and the known
commit SHA/PR-number/issue-number paths have distinct safe controls. Other
github.event paths, github.head_ref, github.ref_name, the whole github context
and inputs require review. Dot and constant bracket access are equivalent;
dynamic event access preserves its untrusted prefix.

GA003 distinguishes pull_request_target from pull_request and supports scalar,
sequence and mapping event declarations. Default checkout and known target
base identities are controls. PR head/fork selection, refs/pull selectors and
unresolved dynamic checkout contexts require review. A hardcoded revision's
origin cannot be inferred from its spelling. A candidate does not prove that
untrusted code ran: modern checkout versions have fork checkout protections,
including an explicit allow-unsafe-pr-checkout input.

An expression is a trusted base control only when the complete input is one
exact trusted context property or one literal string outside `refs/pull/`.
Functions, operators,
multiple substitutions and mixtures of literal text and substitutions remain
unresolved and require review. A trusted property inside a larger expression
does not establish the resulting checkout identity. For example,
`${{ format('refs/{0}/42/merge', 'pull') }}` and
`refs/${{ 'pull' }}/42/head` both require review. The scanner does not evaluate
these expressions; see GitHub's
[expression reference](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions).

YAML parsing retains literal on keys and physical inclusive line spans.
No YAML 1.1 boolean conversion can erase the event declaration. Backward,
acyclic aliases use immutable values anchored at their original definitions.
Duplicate keys/anchors, cycles/forward aliases, merge keys, custom tags,
tag-shape mismatches and multiple documents refuse explicitly. Parsing is
limited to 1 MiB UTF-8, 8192 events, 32 nested value levels and 128 aliases.
These limits apply before building a larger representation. The underlying
Git inventory's separate text/binary/symlink limits still apply.
Analysis also permits at most 4096 job/step occurrences per owner, counting
alias-expanded executable positions before inspection. This prevents a small
aliased YAML graph from multiplying scanner work or candidate allocations.

Candidates retain exact tracked blob identities and source spans. Their
evidence contains file/span digests and fixed diagnostic reasons, rather than
scripts or attacker-controlled values. Symbols use structural positions,
not user-supplied job names. JSON report and SARIF exports preserve candidate
state; confidence is not severity or an accepted finding.

## Verification and limitations

Dedicated public tests exercise real YAML, Git repositories, repository scan,
CLI failure status, report round trips, SARIF, source anchors, non-mutation,
probation and positive/negative controls for all three security rules.
The scanner does not implement the entire GitHub workflow schema, evaluate
expressions, resolve remote reusable workflows, propagate caller events into
local/composite actions, or perform shell/data-flow analysis. JavaScript and
Docker action execution bodies remain separate analysis surfaces. The
expression check is lexical and does not certify general expression validity.
An unexplained GV006 prevents claiming that its owner was completely scanned.

Rule-pack identity changes to 1.19.0. Existing rule introduction versions and
serialized record field layouts remain unchanged. Version-bound report and
maturity readers continue to require their exact scanner rule pack; retain the
matching reader with historical evidence. The published 1.0 calibration corpus
is historical and supplies no evidence for these new rules.

The implementation follows GitHub's
[script injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections),
[immutable action reference guidance](https://docs.github.com/en/actions/reference/security/secure-use)
and current
[target-event checkout guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).
PyYAML's [parser documentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
distinguishes event parsing from application object construction.
