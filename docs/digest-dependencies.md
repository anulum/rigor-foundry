# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — normative digest-dependency graph

# Digest dependencies

The schema 1.6 graph returned by `digest_dependency_graph()` is the normative,
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
| Ignored inventory | `ignored_inventory_digest` | `ignored_inventory` |
| Git provenance | `git_provenance.identity_digest` | `git_provenance` |
| Policy | `policy_digest` | `policy_models` |
| Rule pack | `rule_pack_digest` | `rules` |
| Maturity policy | `policy_digest` | `rule_maturity` |
| Rule maturity | `maturity_digest` | `rule_maturity` |
| Source claim | `claim_digest` | `source_provenance` |
| Source retrieval policy | `policy_digest` | `source_capture` |
| Source capture | `capture_digest` | `source_capture` |
| Source verification | `verification_digest` | `source_provenance` |
| Adapter profile | `evidence_digest` | `adapter_profiles` |
| Adapter lock | `adapter_digest` | `effective_profile` |
| Standard pack | `pack_digest` | `standard_pack` |
| Toolchain | `toolchain.identity_digest` | `campaign_models` |
| Effective profile | `lock_digest` | `effective_profile` |
| Report | `report_digest` | `models` |
| Review | `review_digest` | `models` |
| Campaign | `contract_digest` | `campaign_models` |
| Run attestation | `attestation_digest` | `campaign_models` |
| Comparison | `comparison_digest` | `campaign_compare` |
| Task | `definition_digest` | `work_models` |
| Closure | `closure_digest` | `work_closure` |

Identity-field names are scoped by their owning protocol record. Two distinct
owners may expose the same real field name, such as `policy_digest`; only a
duplicate owner/field pair is ambiguous.

`policy_digest` and `review_digest` are first-class properties over the entire
canonical serialisation. They remove caller-specific hashing conventions.
Rule-pack schema 1.0 and rule-pack version `rigor-foundry/1.6.0` bind the
registry version, ordered rule definitions, and every definition field into
one envelope. Existing rules retain their original introduction version.

Git provenance binds the resolved executable path, selected root, executable
SHA-256, observed version, complete trust policy, and trust-policy digest.
Toolchain identity binds Python implementation/version, platform, and
interpreter executable SHA-256. Campaign schema 1.9 embeds both complete
records plus the ignored evidence tuple and digest; effective-profile locks
bind the toolchain digest used for profile resolution.

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
| Ignored inventory | Report | complete evidence tuple plus `ignored_inventory_digest` |
| Git provenance | Report | complete `git_provenance` record |
| Policy | Report | complete `policy` plus `policy_digest` |
| Rule pack | Report | `rule_pack_digest` |
| Rule pack | Rule maturity | `rule_pack_digest` |
| Maturity policy | Rule maturity | complete policy plus `policy_digest` |
| Source claim | Source verification | complete claim |
| Source retrieval policy | Source capture | policy plus `retrieval_policy_digest` |
| Source capture | Source verification | complete capture |
| Inventory | Adapter profile | `input_digest` |
| Adapter profile | Run attestation | `adapter_evidence[*].profile_evidence` |
| Adapter lock | Effective profile | complete `adapters[*]` record |
| Standard pack | Effective profile | `pack_digests[*]` plus verified pack-derived records |
| Toolchain | Effective profile | `toolchain_digest` |
| Report | Review | `report_digest` |
| Inventory | Campaign | `tracked_content_digest` |
| Ignored inventory | Campaign | complete evidence tuple plus `ignored_inventory_digest` |
| Git provenance | Campaign | complete `git_provenance` record |
| Policy | Campaign | `policy_digest` |
| Rule pack | Campaign | `rule_pack_digest` |
| Toolchain | Campaign | complete `toolchain` record |
| Report | Run attestation | `report_digest` |
| Campaign | Run attestation | `input_contract_digest` |
| Toolchain | Run attestation | complete `toolchain` record |
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
- A maturity report may contain no adjudications, so report and review are not
  unconditional graph parents. Each populated maturity evidence row does bind
  its exact `report_digest`, candidate identifier, and `review_digest`; the
  report recomputes those conditional member identities. Likewise, observe-mode
  enforcement may omit maturity, while ratchet and zero require and bind it.
- External source provenance is a separate evidence subgraph. Current reports,
  profiles, waivers, and standard packs do not unconditionally consume it.
  Consumers must reference a specific verification digest in a separately
  versioned schema migration rather than infer authority from source presence.
- Comparison logic embeds the exact participating attestation, report, and
  review digests, plus the collapsed model-witness identities. The set of
  participating records is campaign-instance data rather than a fixed schema
  dependency, so only the campaign contract remains an unconditional normative
  comparison edge. A run attestation separately binds its campaign contract,
  report, toolchain, and any adapter-profile evidence; it is not part of the
  earlier campaign identity. Promotion reconstructs the conditional comparison
  bindings from durable records before accepting a selected report and review.

These non-edges are compatibility contracts, not omissions hidden by the
diagram. Adding a new binding requires a schema/version migration and updated
mutation and non-interference vectors.

## Proof requirements

The owning schema tests rebuild production records through public constructors.
For each declared upstream class they assert both sides of the contract:

1. the upstream identity and every reachable dependent identity change; and
2. every unrelated identity in the exercised graph remains byte-for-byte
   stable.

The tests compare all 23 identities and cover inventory, ignored inventory, Git
provenance, policy, rule-pack, maturity policy, rule maturity, toolchain,
adapter-profile, report, review, campaign, run attestation, task, adapter-lock,
standard-pack, effective-profile, closure, source claim, retrieval policy,
capture, and verification mutations.
Strict parsing vectors reject altered closure schemas, fields, references, counts, and
digests. An archived work record and its original closed record reproduce the
same closure identity.
