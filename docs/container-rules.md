# Container rules

Rule-pack `rigor-foundry/1.10.0` adds a bounded container category (prefix `DK`)
of high-precision rules over tracked Docker and OCI build recipes. Like every
RigorFoundry rule, each `DK` finding is an anchored **needs-evidence candidate**,
never a verdict: it marks a real image-hardening surface for review, not a proven
compromise. The rules are deliberately narrow to keep false positives low;
breadth is not an acceptance metric.

## Rules

| Rule | Signal | Confidence |
| --- | --- | :---: |
| `DK001-unpinned-base-image` | a `FROM` base image referenced by a mutable tag with no `@sha256:` digest | high |
| `DK002-root-runtime-user` | the final image stage sets no non-root `USER`, so the container runs as root | high |

`DK001` flags a `FROM` whose image is not pinned to an immutable content digest:
such an image can change under the same recipe and is never verified. It is
precise by construction — a `FROM scratch` and a `FROM <previous-stage>` build
reference are not external images and are not flagged, and a `--platform` build
flag is ignored. `DK002` flags the final (runtime) stage when it never sets a
non-root `USER`, or sets `USER root` / `USER 0`: the container then runs with
full root authority. Only the last stage is evaluated, because intermediate
build stages running as root are expected.

Both rules parse Dockerfile instructions directly, joining backslash-continued
lines and skipping comments, and apply to any tracked file named `Dockerfile`,
`Containerfile`, `Dockerfile.<suffix>`, `*.dockerfile`, or `*.containerfile`.

Each candidate carries a repository-tree anchor (path, line, content SHA-256), a
neutral rationale, and a concrete verification procedure — for `DK001`, pin the
base image to an `@sha256:` digest; for `DK002`, add a `USER` directive selecting
an unprivileged account as the last identity in the runtime stage.

## Precision and applicability

The rules match on Dockerfile structure, not on arbitrary text, so an image
reference inside a comment or a non-recipe file is not flagged, and a
digest-pinned, non-root recipe produces no candidate. The category contributes a
portable control toward the `packaging-deployment-iac` audit domain over the
tracked container-recipe surface.

## Calibration

False-positive calibration against real repositories is deliberately separate
work: these rules ship with safe-and-vulnerable fixtures and precise instruction
parsing, but adjudicated false-positive and reviewer-effort evidence across
adopter repositories is the maturity-lifecycle step that promotes a rule from
candidate breadth to calibrated enforcement.
