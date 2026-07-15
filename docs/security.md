# Security

Treat repository names, paths, file content, configuration, native-tool output,
and archive members as adversarial input.

- Inventory fails closed when Git objects or tracked paths cannot be read.
- Native processes require explicit consent and use fixed-root executable
  resolution, argv-only invocation, a credential-free environment, a
  no-network read-only bubblewrap sandbox, mandatory timeouts, process-tree
  termination, and a streaming aggregate output hard cap.
- Reports retain only native execution digests and bounded counts; raw argv,
  environment values, source excerpts, and process output are excluded.
- Repository policies must be tracked, non-symlink UTF-8 files inside the
  audited root, and Git index modes and object ids bind every tracked entry.
- Writes require an explicit command and a validated ignored destination.
- Missing evidence never becomes pass.
- Pack and reviewer clearance requires real Ed25519 verification against an
  explicit integrity-bound public-key trust store. Key identifiers and raw
  public keys must both be unique, so aliases for one underlying key cannot
  satisfy independent-review quorum; labels and digest-shaped strings do not
  establish trust.
- CI actions, Python dependencies, and the base image are immutably pinned.
- Package publication uses a protected OIDC environment rather than a stored
  package credential.

Do not disclose a suspected vulnerability in a public issue. Follow the
[security policy](https://github.com/anulum/RIGOR-FOUNDRY/security/policy) and
use private vulnerability reporting.
