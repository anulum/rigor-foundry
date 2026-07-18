# Application-security rules

Rule-pack `rigor-foundry/1.2.0` adds a bounded application-security category
(prefix `AS`) of high-precision, AST-backed rules over tracked Python. Like every
RigorFoundry rule, each `AS` finding is an anchored **needs-evidence candidate**,
never a verdict: it marks a real security-relevant surface for review, not a
proven vulnerability. The rules are deliberately narrow to keep false positives
low; breadth is not an acceptance metric.

## Rules

| Rule | Signal | Confidence |
| --- | --- | :---: |
| `AS001-dynamic-code-execution` | `eval(...)` or `exec(...)` | high |
| `AS002-shell-command-execution` | a `shell=True` keyword, `os.system(...)`, or `os.popen(...)` | high |
| `AS003-unsafe-deserialization` | `pickle.load`/`pickle.loads`, or a `yaml.load` with no explicit loader | high |
| `AS004-weak-hash-primitive` | `hashlib.md5(...)` or `hashlib.sha1(...)` | low |
| `AS005-insecure-temporary-file` | `tempfile.mktemp(...)` | high |
| `AS006-js-dynamic-code-execution` | native JavaScript/TypeScript `eval(...)` or `new Function(...)` | high |
| `AS007-go-command-execution` | native Go `exec.Command(...)` or `exec.CommandContext(...)` | high |
| `AS008-rust-unsafe-block` | native Rust `unsafe { … }` block | medium |

`AS001`–`AS005` are Python-AST rules. `AS006`–`AS008` are native analysis over a
tree-sitter AST for JavaScript/TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`), Go
(`.go`), and Rust (`.rs`); they require the optional `native` extra
(`pip install rigor-foundry[native]`) and a deployment without the extra simply
produces no `AS006`–`AS008` candidate. Being AST-based, they are precise: `AS006`
ignores a member access such as `obj.eval(x)`; `AS007` distinguishes
`exec.Command` from `other.Command` or `exec.LookPath`; and `AS008` flags a real
`unsafe` block, not the word `unsafe` in a string or comment. `AS008` is medium
confidence because an `unsafe` block is sometimes a reviewed, necessary
abstraction; the candidate asks a reviewer to confirm its invariants.

Each candidate carries a repository-tree anchor (path, line, content SHA-256), a
neutral rationale, and a concrete verification procedure — for example, prove the
argument to `eval` is a trusted literal, pass an argument vector instead of a
shell string, or switch `yaml.load` to `yaml.safe_load` for external input.

## Precision and applicability

The rules match on the Python AST, not on text, so a mention inside a string or
comment is not flagged, and hardened equivalents are deliberately ignored:
`subprocess.run([...], shell=False)`, `yaml.safe_load(...)`,
`yaml.load(stream, Loader=SafeLoader)`, `hashlib.sha256(...)`, and
`tempfile.mkstemp(...)` produce no candidate. `AS004` is low confidence because a
weak hash is only a defect in a security or integrity context; a reviewer
confirms whether the digest backs a security decision.

The category applies to every tracked Python file, because a security defect is
not test-only. It runs as a portable control for the `application-security`
audit domain: a repository that declares that domain required is now covered by a
portable rule as well as any wired native adapter (for example the Semgrep
profile), so the domain is no longer reported as uncontrolled on the portable
axis alone.

## Calibration

False-positive calibration against real repositories is deliberately separate
work: these rules ship with safe-and-vulnerable fixtures and precise AST matching,
but adjudicated false-positive and reviewer-effort evidence across adopter
repositories is the maturity-lifecycle step that promotes a rule from candidate
breadth to calibrated enforcement.
