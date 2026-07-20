# Content-addressed report differences

`rigor report-diff` compares two integrity-verified audit reports and emits one
schema-1.0, content-addressed evidence record. It never scans a repository and
never treats a missing historical report as an empty candidate set.

```bash
rigor report-diff \
  --before evidence/report-before.json \
  --after evidence/report-after.json \
  --output evidence/report-diff.json
```

Without `--output`, the deterministic JSON document is written to stdout. An
explicit output is created exclusively and its parent must already exist.

## Transition classes

The record binds both exact `report_digest` values and partitions candidate
identities into four classes:

- `retained_candidate_ids` contains exact candidate identities present in both
  reports;
- `appeared_candidate_ids` contains unmatched identities from the after report;
- `resolved_candidate_ids` contains unmatched identities from the before report;
- `anchor_changes` pairs candidates whose rule, path, symbol, evidence,
  confidence, rationale, and verification are identical while the exact anchor
  changed.

Changing evidence or any other semantic field is therefore one resolved plus
one appeared candidate, not an anchor relocation. The operator chooses the
before/after direction. The record does not prove Git ancestry or chronology.

## Ambiguous anchor changes

One unmatched semantic identity on each side is paired automatically. Multiple
possible pairings fail closed. Resolve that ambiguity with a separate strict
JSON document:

```json
{
  "schema_version": "1.0",
  "matches": [
    {
      "before_candidate_id": "<64 lowercase hex characters>",
      "after_candidate_id": "<64 lowercase hex characters>",
      "rationale": "Retained review evidence that establishes this relocation"
    }
  ]
}
```

Pass it with `--anchor-matches PATH`. Every declared candidate may be used once,
both candidates must exist in the unmatched sets, and their semantic identities
must agree. The pair and rationale become part of `diff_digest`.

## Compatibility declarations

Repository-root or Git-object-format, branch, policy, rule-pack, and scanner
changes are incompatible by default. A deliberate comparison must name every
actual change and include one non-empty justification:

```bash
rigor report-diff \
  --before evidence/old.json \
  --after evidence/new.json \
  --declare-policy-change \
  --declare-rule-pack-change \
  --justification "Reviewed migration from policy A to policy B"
```

Available flags are `--declare-repository-change`, `--declare-branch-change`,
`--declare-policy-change`, `--declare-rule-pack-change`, and
`--declare-scanner-change`. A missing declaration and a superfluous declaration
both fail. This prevents a caller from silently comparing unlike evidence or
pre-authorising differences that did not occur.

## Replay and interpretation boundary

`ReportDiff.from_dict` and `ReportDiff.from_path` require the exact before and
after reports. They rebuild the compatibility checks, transition partition,
automatic and declared anchor matches, and final digest. Rehashing a modified
JSON object is insufficient when it no longer replays from those parents.

The diff is an evidence primitive for measured trends and reviewer effort. An
appeared candidate is not automatically a regression, a resolved candidate is
not automatically a fix, and a retained candidate is not automatically valid.
Correctness still requires exact-report review evidence.
