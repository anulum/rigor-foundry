<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
RigorFoundry — configured inventory domains
-->
# Configured inventory domains

The provisional `inventory_domain.InventoryDomain1` records the complete
declared roots and path-classification rules for one project. It uses schema
`1.0`, object kind `inventory-domain`, a domain/project ID, sorted root/rule
arrays and a digest over all other fields. Its typed source reference is
supported by the existing [fixed source parser and retained source
lease](context-source-ownership.md).

Each inline root contains its ID, canonical monorepo-relative path and source
kind: `git`, `ignored` or `generated`. Parsing a declaration does not open or
enrol any of those roots. Root IDs and paths are unique; every rule references
a declared root. Explicit source, rule and reference ceilings apply before
child parsing.

An inline classification rule contains `root_id`, `field`, `selector_kind`,
`selector` and `value`. Languages permit literal `exact` paths and lowercase
`suffix` selectors. Roles permit exact paths and whole-component `prefix`
selectors. Role values are `source`, `test`, `tool`, `fixture`, `example`,
`benchmark`, `generator`, `configuration` and `documentation`. Language values
are explicit identifiers; declaring one does not qualify its language adapter
or verify content syntax. Glob, regex, callback and loader selectors are absent.

`inventory_classification.classify_repository_file_inputs` preserves every
baseline/current [file input](repository-file-inputs.md). An exact path takes
precedence. Otherwise the longest matching lowercase filename suffix selects
the language, and the longest whole-component prefix selects the role.
Unmatched fields stay null. Unsupported and gitlink rows remain unknown;
their independent byte/root owners cannot be replaced by a filename label.
Deleted paths remain represented with their before identities available.

## Actual selected Git-root observations

`inventory_source_observations.observe_classified_git_root` uses actual borrowed
domain, registry and inventory-contract source leases, a host-selected monorepo
root, a prior complete package/interpreter observation, an actual Git runner
and explicit read budgets. It does not accept a request-appointed parser or
implementation loader.

The function compares every declared project root with the actual contract
root set, project/group ownership, canonical path and configured-scope digest.
The contract must describe the fixed `builtin.maintained-inventory.v1`
implementation and support the actual selected domain and registry formats.
Legacy descriptive inventory contracts remain parseable; omitting the domain
format cannot authorise this new observer. The actual installed package and
interpreter observation is checked before and after the file capture.

The selected Git root is read through the actual file-input API, then classified.
Sources are revalidated at closure, and the host-root pathname must retain its
original directory identity. The result retains the domain, registry and contract
references, complete selected-root input data and a source-selection snapshot.

This observes one Git root. It does not capture the declaration's other roots,
enumerate ignored/generated directories, establish complete maintained inventory,
authenticate a task/fact context or issue an owner/admission proof. All declared
roots remain bound by the domain reference; a complete owning consumer must
collect and verify them independently. Existing source-access, whole-host
resource, runtime, revocation and effect guards remain required.

[Configured inventory inputs](configured-inventory-inputs.md) composes the
shared retained-source selection with every declared Git and directory root.
It preserves original observations and explicit nested namespace ownership;
its declared-root completeness does not establish host admission or history.
