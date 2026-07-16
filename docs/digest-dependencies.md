# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — normative digest-dependency graph

# Digest dependencies

The schema 1.1 graph returned by `digest_dependency_graph()` is the normative,
machine-readable registry of unconditional identity bindings between public
audit records. `digest_dependency_graph_digest()` identifies that graph using
the same canonical SHA-256 primitive as the records themselves.

An edge `A → B` means that rebuilding `B` after a semantic mutation of `A`
must change `B`'s digest. Records without a path from `A` must remain stable.
Conditional observations that only sometimes alter a comparison are described
separately and are not misrepresented as unconditional digest edges.

## Canonical identities

| Node | Identity | Owning module |
|---|---|---|
| Inventory | `tracked_content_digest` | `git_inventory` |
| Git provenance | `git_provenance.identity_digest` | `git_provenance` |
| Policy | `policy_digest` | `models` |
| Rule pack | `rule_pack_digest` | `rules` |
| Adapter lock | `adapter_digest` | `effective_profile` |
| Standard pack | `pack_digest` | `standard_pack` |
| Toolchain | `toolchain.identity_digest` | `campaign_models` |
| Effective profile | `lock_digest` | `effective_profile` |
| Report | `report_digest` | `models` |
| Review | `review_digest` | `models` |
| Campaign | `contract_digest` | `campaign_models` |
| Comparison | `comparison_digest` | `campaign_compare` |
| Task | `definition_digest` | `work_models` |
| Closure | `closure_digest` | `work_closure` |

`policy_digest` and `review_digest` are first-class properties over the entire
canonical serialisation. They remove caller-specific hashing conventions.
Rule-pack schema 1.0 and rule-pack version `rigor-foundry/1.1.0` bind the
registry version, ordered rule definitions, and every definition field into
one envelope. Existing rules retain their original introduction version.

Git provenance binds the resolved executable path, selected root, executable
SHA-256, observed version, complete trust policy, and trust-policy digest.
Toolchain identity binds Python implementation/version, platform, and
interpreter executable SHA-256. Campaign schema 1.4 embeds both complete
records; effective-profile locks bind the toolchain digest used for profile
resolution.

`WorkClosure` schema 1.0 binds `WorkTask.definition_digest` to the exact
`closed` event digest and its sequence number. The event digest already binds
the preceding event chain. Archiving a closed record therefore does not alter
the earlier closure identity, while substituting a different task definition
or closed event does. `WorkRecord` also rejects a proposal that differs from
the task baseline and a revalidation that names another candidate or report.

## Direct dependency graph

| Upstream | Downstream | Canonical binding |
|---|---|---|
| Inventory | Report | `tracked_content_digest` |
| Git provenance | Report | complete `git_provenance` record |
| Policy | Report | complete `policy` plus `policy_digest` |
| Rule pack | Report | `rule_pack_digest` |
| Adapter lock | Effective profile | complete `adapters[*]` record |
| Standard pack | Effective profile | `pack_digests[*]` plus verified pack-derived records |
| Toolchain | Effective profile | `toolchain_digest` |
| Report | Review | `report_digest` |
| Inventory | Campaign | `tracked_content_digest` |
| Git provenance | Campaign | complete `git_provenance` record |
| Policy | Campaign | `policy_digest` |
| Rule pack | Campaign | `rule_pack_digest` |
| Toolchain | Campaign | complete `toolchain` record |
| Campaign | Comparison | `input_contract_digest` |
| Inventory | Task | `baseline_tracked_content_digest` |
| Policy | Task | `source_policy_digest` |
| Rule pack | Task | `source_rule_pack_digest` |
| Report | Task | `source_report_digest` and selected candidate |
| Review | Task | `review_digest` |
| Task | Closure | `definition_digest` |

`direct_dependents()` and `transitive_dependents()` query this exact graph in
normative node order. `validate_digest_dependency_graph()` checks unique node
and identity names, unique edges, non-empty bindings, known endpoints, and the
absence of cycles.

## Deliberate stable non-edges

- A candidate-only report change does not change the campaign contract. A
  campaign freezes scanner inputs, not one scanner output. It does change the
  report, rebound review, task, and closure identities.
- Standard packs, adapter locks, and effective-profile locks form a separate
  desired-state subgraph. Current repository reports and campaigns do not bind
  that lock, although the same toolchain identity can independently affect a
  campaign contract and an effective-profile lock.
- A standard-pack mutation does not change an adapter lock, and an adapter-lock
  mutation does not change a standard pack. Both change an effective-profile
  lock that contains them.
- Review rationale, evidence, reviewer, and time can change a review and any
  resulting task without changing the source report or campaign.
- Comparison logic observes selected run, report, adapter-evidence, and review
  projections. Those inputs can affect divergence text conditionally, but the
  comparison record does not embed their complete digests. Only the campaign
  contract is an unconditional graph edge today.

These non-edges are compatibility contracts, not omissions hidden by the
diagram. Adding a new binding requires a schema/version migration and updated
mutation and non-interference vectors.

## Proof requirements

The owning schema tests rebuild production records through public constructors.
For each declared upstream class they assert both sides of the contract:

1. the upstream identity and every reachable dependent identity change; and
2. every unrelated identity in the exercised graph remains byte-for-byte
   stable.

The tests compare all 14 identities and cover inventory, Git provenance,
policy, rule-pack, toolchain, report, review, campaign, task, adapter-lock,
standard-pack, effective-profile, and closure mutations. Strict parsing
vectors reject altered closure schemas, fields, references, counts, and
digests. An archived work record and its original closed record reproduce the
same closure identity.
