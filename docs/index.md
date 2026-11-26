# RigorFoundry

RigorFoundry is an evidence-bound repository audit and remediation-planning
tool. The current codebase is in migration and has not yet passed its promotion
gates.

The audit contract keeps static candidates, verified findings, accepted risk,
target gaps, and remediation plans as distinct records. Missing evidence never
becomes an implicit pass.

## Start here

- [First repository](getting-started.md) provides the explicit, non-overwriting
  adopter bootstrap and first read-only scan.
- [Architecture](architecture.md) defines the separation between observation,
  review, target state, and remediation.
- [CLI](cli.md) documents the installed command boundary.
- [Offline CRA preparation](cra-reporting.md) documents the prepare-only
  Article 14 evidence workflow and its non-submission boundary.
- [SARIF export](sarif.md) documents candidate-versus-verdict semantics and
  exact Git-anchor interchange.
- [Configuration](configuration.md) explains portable policy discovery and
  adopter-owned variables.
- [Validation](validation.md) distinguishes focused local evidence from the
  exhaustive remote gates.
- [Security](security.md) defines the adversarial repository boundary.
- [Public API stability](api-stability.md) inventories stable, provisional, and
  deprecated top-level imports.
- [1.0 stable compatibility contract](stable-contract-1.0.md) freezes the
  supported Python, CLI, and serialized-schema surfaces with one digest.
- [API and schema compatibility rules](api-compatibility-rules.md) define the
  tracked declared-surface manifest and its candidate-only review boundary.

## Support and reporting

- [Support routes](https://github.com/anulum/rigor-foundry/blob/main/SUPPORT.md)
  cover usage questions, defects, proposals and conduct concerns.
- [Private vulnerability reporting](https://github.com/anulum/rigor-foundry/security/policy)
  lists the reporting channels and supported versions.

For general correspondence, email [protoscience@anulum.li](mailto:protoscience@anulum.li).

---

<p align="center">
  <a href="https://www.anulum.li"><img src="assets/anulum_logo_company.jpg" height="70" alt="ANULUM"></a>
  &nbsp;&nbsp;&nbsp;
  <img src="assets/fortis_studio_logo.jpg" height="70" alt="Fortis Studio">
  <br>
  <em>Developed by <a href="https://www.anulum.li">ANULUM</a> / Fortis Studio</em>
</p>

[GitHub Actions security candidates](github-actions-security.md) document the
workflow/composite scopes, incomplete outcomes and verification boundaries.

[Lockfile integrity rules](lockfile-integrity-rules.md) classify every tracked
lockfile entry by its pin, refuse unreadable lockfiles by name, and keep new
rules in probation.
