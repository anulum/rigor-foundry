# Roadmap

Roadmap items are acceptance-gated; dates and versions are not release promises.

## 0.1 — Repository foundation

- Validate the completed local Apache-2.0 repository governance, reproducible
  dependencies, CI, security, documentation, packaging, and container surfaces
  through remote gates.
- Complete independent review of the internal-storage and work-lifecycle
  modules at an exact commit.
- Establish the first independently audited local commit.

## 0.2 — Desired-state profiles

- Integrate the implemented `StandardPack`, `ProjectProfile`,
  `EffectiveProfileLock`, `ControlAssessment`, `TargetGap`, and
  `RemediationPlan` records with stable CLI import/export commands.
- Publish adopter examples for typed project variables, secret-provider
  references, namespaced custom controls, bounded conditions, and
  contradiction reports.
- Independently verify exact pack source, licence, signature policy, adapter,
  and content-digest locking against adversarial fixtures.
- Add a policy-declared ignored-inventory evidence extension. Rules whose
  semantics depend on ignored or untracked reality must remain
  `needs-evidence` when that extension is absent; tracked-only absence must
  never become a failure verdict.
- Completed: replace prose-only candidate evidence with machine-verifiable
  tracked-blob or repository-tree anchors that bind repository path, inclusive
  line span, exact object identity, and content digest while retaining a
  bounded human-readable excerpt.
- Represent classified coverage residuals explicitly: structurally unreachable
  branches, retained fail-closed guards, and preregistered negative searches
  require different evidence and must not incentivise guard deletion.
- Generalise verified-at-source provenance beyond action pins for externally
  sourced CVEs, versions, standards, and content digests.

## 0.3 — Controlled remediation

- Connect the implemented declarative procedure DAG and conflict-safe batch
  model to an explicit-authority executor with enforced time/resource budgets,
  idempotency, rollback, and evidence capture.
- Add worktree/claim isolation for the model's non-conflicting write sets,
  semantic dependencies, and serialization keys.
- Prove stale-plan, cross-repository, symlink, cancellation, and partial-failure
  behaviour without granting implicit remediation authority.
- Extend campaign attestations with model/provider identity, collapse correlated
  same-model runs to one evidentiary witness, and require at least one
  independently operated model family for promotion campaigns.

## 1.0 — Promotion candidate

- Run independently reviewed audit campaigns against representative external
  and GOTM repositories.
- Publish measured precision/recall and reviewer-effort evidence with corpus and
  methodology limits.
- Introduce a per-rule maturity lifecycle. New rules remain in probation until
  enough adjudicated reviews establish bounded false-positive and reviewer-cost
  evidence; only calibrated active rules may enter ratchet or zero enforcement.
- Complete release quorum, documentation, package, container, SBOM, signing,
  provenance, and rollback evidence.
- Activate fleet authority only with explicit owner authorisation.
