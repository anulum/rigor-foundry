# Assisted-review drafting

RigorFoundry can draft review notes for audit candidates with an optional,
provider-neutral assisted-review adapter. A draft is a **suggestion, never a
verdict**: it always carries the `needs-evidence` decision, holds no signature,
and cannot promote a candidate to valid or invalid on its own.

## Guarantees

- **Needs-evidence only.** Every draft's decision is fixed to `needs-evidence`.
  There is no path for a draft to assert a `valid` or `invalid` verdict.
- **Deterministic and network-free.** The local core performs no network calls.
  The same report, candidate, identity, and text always produce the same
  content-addressed draft.
- **Digest-bound evidence.** A draft binds the exact report digest and the
  candidate's anchor evidence digests; it only drafts for a candidate that is
  actually present in the report.
- **Provider and model identity recorded.** Each draft records the producing
  provider, model, correlation family, and operator through the existing
  `InferenceIdentity`.
- **Secret redaction.** Draft title and rationale pass through a conservative,
  deterministic redactor before storage. Private-key blocks, cloud access-key
  identifiers, bearer tokens, secret assignments, and high-entropy values are
  replaced with `[redacted-secret]`, and the substitution count is recorded.
- **Promotion requires independent review.** A draft states, and structurally
  enforces, that promotion needs an independent human or signed reviewer
  attestation.

## Usage

```python
from rigor_foundry.assisted_review import draft_assisted_review
from rigor_foundry.campaign_identity import InferenceIdentity

identity = InferenceIdentity.build(
    provider="acme-inference",
    model="acme-review-1",
    model_family="acme-review",
    operator="platform-operator",
)
draft = draft_assisted_review(
    report,
    report.candidates[0],
    identity,
    title="Review the wildcard import boundary",
    rationale="The candidate needs an independent evidence review before any verdict.",
)
assert draft.decision == "needs-evidence"
print(draft.redaction_count, draft.promotion_requirement)
```

A draft serialises with `to_dict()` and re-binds to its report with
`ReviewDraft.from_dict(value, report)`, which re-validates the candidate, the
report digest, and the content digest and rejects any tampering — including any
attempt to change the decision away from `needs-evidence`.

The adapter is intentionally out of the deterministic audit core: it drafts
review text to accelerate human review, and it never substitutes for the signed,
independent reviewer attestations that RigorFoundry requires before promotion.
