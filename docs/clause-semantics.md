<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Apache License 2.0; see LICENSE. -->
<!-- © Concepts 1996–2026 Miroslav Šotek. All rights reserved. -->
<!-- © Code 2020–2026 Miroslav Šotek. All rights reserved. -->
<!-- ORCID: 0009-0009-3560-0851 -->
<!-- Contact: www.anulum.li | protoscience@anulum.li -->
<!-- RigorFoundry — canonical clause semantics -->

# Canonical clause semantics

`ClauseSemanticsSetV2.from_bytes` parses a canonical UTF-8 JSON body for one
project. The closed `rigor.clause-semantics-set.v2` format records clause and
statement digests, predecessor and projection references, scope, vocabulary,
target-table and evaluator-registry digests, and the resolver version.
It accepts six subjects: `admit`, `veto`, `rate`, `window`, `route` and
`precondition`. Each subject has its own exact field set.

```python
from rigor_foundry.clause_semantics_set_v2 import ClauseSemanticsSetV2

body = ClauseSemanticsSetV2.from_bytes(retained_body_bytes)
body_digest = body.body_digest
independent_mapping = body.to_dict()
```

The digest is SHA-256 of the exact accepted bytes. `to_dict()` returns a fresh
mapping; changing it leaves the retained body unchanged. Duplicate JSON keys,
noncanonical encoding, unknown fields, duplicate clause entries, unsorted scopes,
placeholder targets and invalid constraint parameters raise `ValueError`.

Rate constraints count operation intents and require integer limits and windows.
Time constraints use ordered, nonoverlapping UTC weekday ranges. Route constraints
use explicit provider, account reference, decimal cost ceiling and privacy class.
Preconditions and evaluator identifiers come from fixed sets.

`EffectVocabularyV2` retains the fixed thirteen effect classes.
`EffectTargetTableV2` binds those classes to fifteen target-kind rows. Their
`build()` and `from_bytes()` APIs verify the fixed version's canonical content
and digest; changed mappings require another reviewed version. Use `contains()`,
`allows()` and `triples_for_class()` to inspect the mapping.

Scope syntax validation recognises canonical paths, repository paths, remotes,
endpoints, hosts and project/group selectors. Path globs are limited to full
segments in exclusions; veto scopes cannot hide a glob exclusion.
`bind_clause_scope_groups_v2()` separately checks owning and foreign inbox groups
against the caller's selected registry group set.

These APIs validate data. Digest references are checked for format here;
matching them to retained objects, checking effect applicability, authenticating
signatures and current registry custody belong to their consuming verifier.
Parsing a body or passing a group set grants no permission to execute an effect.
The body is unsigned, and this API does not change CLI or fleet enforcement.
