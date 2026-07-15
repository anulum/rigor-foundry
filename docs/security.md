# Security

Treat repository names, paths, file content, configuration, native-tool output,
and archive members as adversarial input.

- Inventory fails closed when Git objects or tracked paths cannot be read.
- Native processes use resolved executables, argv-only invocation, timeouts,
  and bounded output.
- Writes require an explicit command and a validated ignored destination.
- Missing evidence never becomes pass.
- CI actions, Python dependencies, and the base image are immutably pinned.
- Package publication uses a protected OIDC environment rather than a stored
  package credential.

Do not disclose a suspected vulnerability in a public issue. Follow the
[security policy](https://github.com/anulum/rigor-foundry/security/policy) and
use private vulnerability reporting.
