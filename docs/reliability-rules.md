# Reliability rules

Rule-pack `rigor-foundry/1.8.0` adds a bounded reliability category (prefix `RL`)
of high-precision, AST-backed rules over tracked Python. Like every RigorFoundry
rule, each `RL` finding is an anchored **needs-evidence candidate**, never a
verdict: it marks a real reliability-relevant surface for review, not a proven
defect. The rules are deliberately narrow to keep false positives low; breadth is
not an acceptance metric.

## Rules

| Rule | Signal | Confidence |
| --- | --- | :---: |
| `RL001-bare-except` | a bare `except:` handler with no exception type | high |
| `RL002-mutable-default-argument` | a function default that constructs a fresh `list`, `dict`, or `set` | high |

Both rules match on the Python AST, not on text. `RL001` flags an
`except` handler whose type is absent, which catches every exception — including
`SystemExit` and `KeyboardInterrupt` — and so hides real failures and blocks
interruption; a typed handler such as `except ValueError:` is not flagged.
`RL002` flags a default argument that is a `[...]`, `{...}`, or `{…}` literal, or
an empty `list()`, `dict()`, or `set()` constructor call: such a default is
created once and shared across every call, so state leaks between invocations. An
immutable default (`None`, a number, a string, a tuple), a constructor call with
arguments (`list([0])`, `dict(a=1)`), a non-builtin call (`make()`), and an
attribute call (`ns.factory()`) are deliberately not flagged.

Each candidate carries a repository-tree anchor (path, line, content SHA-256), a
neutral rationale, and a concrete verification procedure — for `RL001`, catch the
specific exception types the block can actually handle or re-raise after
recording context; for `RL002`, default the parameter to `None` and construct the
container inside the function body, or confirm the shared instance is genuinely
intended.

## Precision and applicability

Because the rules match on the AST, a mention inside a string or comment is not
flagged, and hardened equivalents are ignored by construction. The category
applies to every tracked Python file, because a reliability defect is not
test-only. It contributes a portable control toward the
`reliability-and-concurrency` audit domain over the tracked Python surface.

## Calibration

False-positive calibration against real repositories is deliberately separate
work: these rules ship with safe-and-vulnerable fixtures and precise AST matching,
but adjudicated false-positive and reviewer-effort evidence across adopter
repositories is the maturity-lifecycle step that promotes a rule from candidate
breadth to calibrated enforcement.
