# Conditions with partial observations

The provisional Python evaluator distinguishes an observed value, declared
absence and missing knowledge. It consumes the existing `ConditionExpression`
schema `1.1`; the expression digest and Boolean `evaluate` method retain their
existing behavior.

```python
from rigor_foundry.condition_evaluation import evaluate_condition_state
from rigor_foundry.condition_facts import ConditionFact, ConditionTruth
from rigor_foundry.condition_language import ConditionExpression

expression = ConditionExpression.build("exists", reference="project.enabled")

assert evaluate_condition_state(expression, {}) is ConditionTruth.UNKNOWN
assert evaluate_condition_state(
    expression, {"project.enabled": ConditionFact.known(None)}
) is ConditionTruth.TRUE
assert evaluate_condition_state(
    expression, {"project.enabled": ConditionFact.absent()}
) is ConditionTruth.FALSE
```

A known `None` is an observed JSON null, so `exists` is true. Declared absence
makes a leaf false. An omitted reference or `ConditionFact.unknown()` stays
unknown, including under negation. A parent observation never manufactures
observations for its missing descendants. A known descendant conflicting with
an observed scalar or absent parent refuses. An unobserved parent permits a
separately observed descendant; unknown is not evidence of a contradiction.

Facts contain finite JSON scalars or immutable flat scalar tuples. Parsing an
array copies its elements into a tuple. Nested objects, non-finite numbers,
malformed references and a value attached to absent/unknown refuse.
Observation equality and hashing preserve exact serialized data, including
the difference between Boolean true and numeric1.

Inputs are supplied operands. Authenticating their producer, snapshot and
maintained source/language scope belongs to the selected policy consumer.
The calculation supplies no permission or gate acceptance.

## Three-valued groups

| Left | Right | all | any |
|---|---|---|---|
| true | true | true | true |
| true | false | false | true |
| true | unknown | unknown | true |
| false | true | false | true |
| false | false | false | false |
| false | unknown | false | unknown |
| unknown | true | unknown | true |
| unknown | false | false | unknown |
| unknown | unknown | unknown | unknown |

Negation maps true to false, false to true, and unknown to unknown.
Every known operand is checked even after a decisive sibling: a bad numeric
comparison cannot disappear behind a true `any` or false `all`.

Known leaves use the original operator implementation, including numeric versus
Boolean identity and string/array containment. Explicit absence is false for
every leaf; unknown is never passed to the old evaluator as an empty mapping.

Compare results explicitly. `bool(ConditionTruth.FALSE)` and
`bool(ConditionTruth.UNKNOWN)` raise `TypeError`; the strings must not become
truthy guards. Trees retain the existing depth8/node64 limits. The evaluator
accepts at most65,536 observations.

## Module command

Run the separately versioned provisional command:

```console
python -m rigor_foundry.condition_evaluation_cli --expression expression.json --observations observations.json
```

`expression.json` is the complete digest-bound output of
`ConditionExpression.to_dict()`. Create one through the existing builder:

```python
import json
from pathlib import Path
from rigor_foundry.condition_language import ConditionExpression

expression = ConditionExpression.build("eq", reference="project.enabled", value=True)
Path("expression.json").write_text(json.dumps(expression.to_dict()), encoding="utf-8")
```

`observations.json` has exactly these fields:

```json
{
  "schema_version": "rigor.condition-observations.v1",
  "facts": {
    "project.enabled": {"state": "known", "value": true}
  }
}
```

Each fact has exactly `state` and `value`. States are `known`, `absent` and
`unknown`. The latter two require null. An empty facts object means missing
knowledge. This operand format is not an authenticated task or fact context;
extra provenance fields are rejected rather than trusted.

The JSON result uses `rigor.condition-evaluation.v1` and has exactly
`schema_version`, `evaluation_kind`, `expression_digest`,
`observations_digest`, `result` and `guard_admissible`.
`evaluation_kind` is `supplied-observations`; `guard_admissible` is always false.
The two digests identify the parsed expression and canonical operand data,
not trusted source custody. No raw observation values appear in output.

| Exit | Meaning |
|---|---|
| 0 | Supplied condition evaluates true |
| 1 | Supplied condition evaluates false |
| 2 | Invalid arguments, file, JSON, expression or operand |
| 3 | Supplied condition remains unknown |

Each explicit input is limited to64KiB and read through single-link regular-file,
no-follow descriptors. Duplicate keys, non-finite numbers, symlinks, hardlinks,
directories, stale expression digests and oversized files refuse. Diagnostic
`CE001` does not echo paths, values or raw exceptions. The command writes only
its result to stdout. It performs no audit, process dispatch, signing or source
discovery.

The frozen `rigor`1.0 command inventory remains unchanged. This module command
and the module-level Python APIs are provisional; their explicit record versions
remain independent of that older CLI inventory.
