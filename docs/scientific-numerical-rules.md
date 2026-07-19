# Scientific and numerical correctness rules

Rule-pack `rigor-foundry/1.13.0` adds the bounded `scientific` category (prefix
`SN`). Findings are anchored **needs-evidence candidates**, not proof that a
numerical result is wrong or a stochastic test is flaky.

## Rules

| Rule | Signal | Confidence |
| --- | --- | :---: |
| `SN001-exact-float-equality-in-test` | a Python test function compares a direct signed or unsigned float literal with `==` or `!=` | high |
| `SN002-unseeded-stochastic-test` | an explicitly imported supported `random` or `numpy.random` API is used before local deterministic seeding, or a supported generator is constructed without a seed | high |

SN001 is deliberately narrower than type inference. It ignores integer,
Decimal, container, and string comparisons, and explicit `approx` or `isclose`
operands. Reviewers should replace accidental exactness with a justified
absolute/relative tolerance, while preserving exact comparison when the test
really specifies binary identity, parsing, or serialisation.

SN002 resolves explicit module and direct imports for a bounded set of common
draw APIs. It treats `random.seed`, `numpy.random.seed`, `random.Random`, and
`numpy.random.default_rng` as deterministic only when a non-`None` seed is
supplied before the relevant draw. Module-level seeds, custom wrappers,
fixtures, and arbitrary generator data flow are not inferred. Reviewers should
seed locally before the first draw or prove that an external fixture establishes
the exact replay contract.

Only tracked UTF-8 `.py` files classified as tests by repository policy or
test naming are parsed. Invalid Python yields no SN candidate because the
existing unparseable-test authenticity rule owns that condition. Evidence
contains exact tracked-blob and line/file digests without copying source text.

The family contributes a portable control to the
`scientific-numerical-correctness` audit domain. Both rules enter maturity
probation; enforcement still requires adjudicated cross-repository precision,
false-positive, and reviewer-effort evidence.
