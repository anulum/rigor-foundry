# Rule-chain candidate inspection

`rigor_foundry.rule_chain_candidate.inspect_rule_chain_candidate` is a
read-only Python API for checking whether one proposed semantic transition,
its signed review, retained StandardPack sources, and a signed ProjectProfile
refer to the same exact objects. It composes the host-selected discovery and
native-source readers, review verifier, pack verifiers, and profile selection.
It does not fetch a remote source or assign a numeric freshness lifetime.

The caller supplies the exact proposal artefact and source captures, typed v2
pack and profile objects, a host-composed semantic-review verifier, one
host-composed retained-source verifier per selected pack, the role-separated
trust policies, the expected project and scope, and an explicit UTC instant.
The host must protect selections and revocations throughout its leases. A
caller-controlled test provider can exercise the API but cannot enrol live
authority. A signed `clear` review is checked as a source dependency; the
reviewer must have a separate identity and trusted signing key from the author.

The result is `RuleChainCandidateReport`. Its digest binds the proposal,
review acceptance dependency, profile, packs, selected authority clauses and
reviewer policy. `guard_admissible` is always `False`. A report is neither a
signed EffectiveProfileLock nor an active dispatch permit. It cannot resolve
local constraints, current grants, adapter custody, revocation or mutable
evidence state, and it cannot authorise an effect. The v1 pack, profile,
audit-lock and dispatch formats remain unchanged; no automatic CLI or Guard
cutover occurs.

Applications that need an active gate must separately implement and select a
reviewed effective lock, verify current state and grant authority before each
effect, and obtain rollout authority. Reusing this inspection result as an
effect permission is a contract violation.
