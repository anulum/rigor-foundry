# Policy source bytes

The provisional Python APIs read supplied local policy inputs and verify their
exact byte coordinates. Every input transaction supplies its allocation limits.
The three record kinds `policy-read-budget`, `source-span` and `source-region`
use schema `1.0`, closed fields and digests that include their kind and version.

```python
from pathlib import Path

from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document

budget = PolicyReadBudget1.build(
    max_document_bytes=65_536,
    max_source_bytes=1_048_576,
    max_total_source_bytes=4_194_304,
    max_sources=32,
    max_rules=256,
    max_references=2_048,
    max_depth=16,
)
document = read_policy_document(Path("rules.json"), budget=budget)
```

The reader rejects duplicate JSON keys, nonfinite numbers, invalid UTF8,
unpaired escaped surrogates, excessive nesting and oversized files. It uses
the existing stable single-link regular-file reader without following symlinks.
Nesting is checked before recursive JSON decoding. Numeric byte ceilings also
bound reading work; they do not merely limit retained buffering.

The fixed implementation ceilings are:

| Budget field | Maximum |
| --- | ---: |
| `max_document_bytes` | 8 MiB |
| `max_source_bytes` | 8 MiB |
| `max_total_source_bytes` | 64 MiB |
| `max_sources` | 4,096 |
| `max_rules` | 16,384 |
| `max_references` | 65,536 |
| `max_depth` | 32 |

All seven fields are explicit positive integers; Booleans are refused.
`read_policy_source_payloads(paths, budget=budget)` reads a complete supplied
source-ID/path mapping in source-ID order. It enforces the source count,
individual file bytes and combined payload bytes before returning any result.
An empty source remains a member of the supplied cohort.

`policy_source_spans.SourceSpan1` binds a nonempty half-open byte interval
`[start_byte, end_byte)` and its raw SHA-256. Its `build` method uses actual
bytes; `from_dict` checks structural identity; `verify(payload)` additionally
checks bounds and content. UTF8 character offsets and normalized newlines
cannot substitute for original source bytes.
`verify_policy_source_spans(paths, spans, budget=budget)` performs the bounded
file reads and checks every supplied span, retaining selection order.

`policy_source_regions.SourceRegion1` records an interval's declared
`normative`, `context`, `nonnormative`, `protected` or `unresolved`
disposition, exact rule/decision IDs and reason code.
`verify_policy_source_regions(paths, regions, budget=budget)` checks byte
digests and requires a complete, ordered partition of every supplied source.
Missing beginnings or tails, gaps, overlap, reordered regions and unresolved
source IDs are refused. Normative regions require rule IDs. Rule and decision
ID arrays are sorted and unique. Each region consumes one source reference
plus its rule and decision links; distinct referenced rule IDs also consume
the rule budget.

A valid partition proves byte accounting for the supplied cohort. It does
not prove that all governing sources were supplied, that extracted rules have
the correct meaning, that referenced rules/decisions have been accepted, or
that protected content may be read. Those checks belong to the corpus and
installed host owners. Protected and unresolved dispositions remain explicit
data after byte verification; neither becomes a ready-boot or effect grant.

The [retained source universe](source-universe.md) connects these original span
and region models to a complete fixed host-selected source cohort. It retains
actual metadata and raw descriptors through use/closure, verifies original
native pins and complete discovery snapshots, and consumes partitions over
those same held bytes. Held/excluded sources remain explicit; no locator
becomes a path and no byte check accepts extraction meaning.

[Rule declarations and original components](common-policy.md) retain these
original spans and conditions in explicit scope, semantic-decision and atomic-rule
records. Their parsers preserve declaration integrity; actual source and semantic
acceptance remain separate.
