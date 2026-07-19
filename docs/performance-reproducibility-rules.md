# Performance and reproducibility rules

Rule-pack `rigor-foundry/1.15.0` adds the bounded `performance` category
(prefix `PR`). Findings are anchored **needs-evidence candidates**, not proof
that a test is flaky, slow, or incorrect.

## Rules

| Rule | Signal | Confidence |
| --- | --- | :---: |
| `PR001-wall-clock-in-test` | an import-bound `time.time()` or `datetime.now()` call is evaluated by a Python test assertion without recognised local clock control | high |

PR001 resolves explicit module and direct imports of `time.time` and
`datetime.datetime.now`. It groups all uncontrolled clock reads in one test
function into one candidate anchored at the first call. Calls outside an
assertion, monotonic elapsed-time measurements, custom clocks, production
code, and unsupported wrappers are outside this deliberately narrow signal.

The rule recognises a `freezer` test fixture, import-bound `freezegun.freeze_time`
and `time_machine.travel` decorators or context managers, and a preceding
straight-line `monkeypatch.setattr` of the exact imported module/class binding.
A patch inside a conditional branch does not suppress a later assertion
outside that branch. `monkeypatch.undo()` restores candidate detection.
Directly imported callables remain candidates when only their source module is
patched because the copied local binding is unchanged. Arbitrary fixtures,
string suffixes, custom wrappers, and production-module patches are not
inferred as clock control.

Only tracked UTF-8 `.py` files classified as tests by repository policy or
test naming are parsed. Syntax-invalid Python yields no PR candidate because
the existing unparseable-test authenticity rule owns that condition. Evidence
contains exact tracked-blob and line/file digests plus bounded API identifiers;
it never copies assertion source.

Reviewers should inject a clock, freeze the exact assertion boundary, or prove
that the live-clock check has a bounded timing contract resilient to wall-clock
adjustment and scheduler delay. A candidate may be adjudicated invalid or an
accepted boundary when that evidence is retained.

The family contributes a portable control to
`performance-and-reproducibility`. PR001 enters maturity probation and cannot
drive enforcement until adjudicated cross-repository precision and
reviewer-effort evidence exists.
