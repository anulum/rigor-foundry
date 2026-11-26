<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Apache License 2.0; see LICENSE. -->
<!-- © Concepts 1996–2026 Miroslav Šotek. All rights reserved. -->
<!-- © Code 2020–2026 Miroslav Šotek. All rights reserved. -->
<!-- ORCID: 0009-0009-3560-0851 -->
<!-- Contact: www.anulum.li | protoscience@anulum.li -->
<!-- RigorFoundry — lockfile integrity rules -->

# Lockfile integrity rules

Rule-pack `rigor-foundry/1.20.0` classifies every entry of every tracked
lockfile by how its content is pinned, and raises supply-chain candidates
(prefix `SC`) for the entries whose pin fails. Like every RigorFoundry rule,
each finding is an anchored **needs-evidence candidate**, never a verdict. A
lockfile that cannot be read is refused by name and never looks clean. The
rules implement *lockfile integrity semantics v1*.

Rule pack `rigor-foundry/1.20.0` reads npm lockfiles (`package-lock.json` and
`npm-shrinkwrap.json`, `lockfileVersion` 1, 2 and 3), and `rigor-foundry/1.21.0`
adds Yarn 1 (`yarn.lock` with the `# yarn lockfile v1` header). Every other
lockfile the rules recognise is refused as `unsupported-file-kind` until its own
rules exist: a Yarn 2+ `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`,
`poetry.lock` and `Pipfile.lock`. All the rules are in maturity probation.

## One class per entry

Every locked entry gets exactly one class, plus zero or more findings.

| Class | Meaning |
|---|---|
| `artifact-pinned` | an exact version and an accepted, well-formed digest of the fetched artifact |
| `commit-pinned` | a VCS source with a full commit id (40 or 64 lower-case hex) |
| `local` | a path, link or workspace source inside the repository root |
| `unpinned` | a recognised artifact, VCS or path form that fails its pin; its `form` is recorded |
| `unclassified` | a form these rules do not know; it always carries `unknown-form` |
| `graph-only` | reserved for Go's graph-only `go.sum` lines, which are informational |

An `unpinned` entry always names its failure: `missing-digest`,
`weak-digest`, `malformed-digest`, `floating-ref` or `path-escape`. The other
findings are `origin-mismatch`, `origin-unknown`, `manifest-drift` (no npm
signal) and `unknown-form`.

## Digests

SHA-512, SHA-384 and SHA-256 are accepted; SHA-1 and MD5 are weak. An npm
`integrity` value may list several SRI tokens, separated by ASCII whitespace,
and every token is validated:

- a token decodes only when its algorithm is known, it has no `?option`
  suffix, its standard base64 is canonical (re-encoding reproduces it exactly)
  and the decoded length matches the algorithm;
- any token that does not decode gives `malformed-digest`, even beside a valid
  accepted token, and the entry is then `unpinned`;
- an entry whose valid tokens are all weak gives `weak-digest`;
- a weak token beside a valid accepted one is clean, and both algorithms are
  recorded;
- an `integrity` field that is present but empty is malformed; only an absent
  field is `missing-digest`.

## npm lockfiles

- **Where entries come from.** Versions 2 and 3 are read from `packages`.
  Version 1 is read from its nested `dependencies` tree, and each entry is keyed
  by its equivalent `node_modules` path. Each entry points at the line where
  its key is written.
- **The legacy tree.** A version 2 file also keeps the version 1 tree for
  npm 6. When that tree records an `integrity` or a `resolved` URL that differs
  from `packages` for the same path, the file is refused as
  `conflicting-entries`.
- **Registry artifacts.** A remote artifact is pinned by an exact version and
  an accepted, well-formed `integrity`. An entry with an exact version and no
  `resolved` URL comes from the declared registry.
- **VCS sources.** A `git+…`, `git://` or hosted (`github:`, `gitlab:`,
  `bitbucket:`, `gist:`) source is pinned by a full commit id; a branch, tag,
  `semver:` range or abbreviated commit gives `floating-ref`. The VCS host is
  recorded but not compared with the registry, because the commit is the pin.
- **Local sources.** `link` entries, `file:` sources and `packages` keys that
  are paths are `local` when they resolve inside the repository. An absolute
  path, a Windows drive, a backslash or a `..` that leaves the repository root
  gives `path-escape`. The rules read paths as written and do not follow
  symbolic links.
- **Bundled entries.** An `inBundle` (version 1: `bundled`) entry arrives inside
  the artifact of its nearest non-bundled ancestor. It takes that ancestor's
  class and findings, with `digest_scope` `parent-artifact` and the ancestor's
  key in `inherited_from`. It is listed in the report, but its findings are not
  raised again as candidates.

## Yarn 1 lockfiles

- **Syntax.** The reader accepts exactly what Yarn 1 writes: header comments that
  include `# yarn lockfile v1`; key lines at column 0 that list one or more
  specifiers separated by `, `; fields indented two spaces; and the members of a
  `dependencies:` block indented four. Quoted keys and values use JSON string
  escapes; a bare one holds no space, quote or colon. A file whose line endings
  are all CRLF reads as LF. Anything else is `unparseable`, including mixed line
  endings, a byte-order mark, a tab, another indentation or a comment after the
  first entry. A field repeated in one entry, or a specifier named by two entries
  (compared unquoted), is `conflicting-entries`; one version resolved under two
  specifiers is normal.
- **Keys.** An entry's key lists its specifiers, unquoted, separated by `, `.
- **Local sources.** A `file:` or `link:` specifier, or a `file:` URL, is `local`
  inside the repository and gives `path-escape` outside it.
- **Git clones.** A `resolved` `git+…` or `git://` URL with `#<commit>` is cloned
  through Git, so a full commit makes it `commit-pinned`; anything shorter gives
  `floating-ref`.
- **Hosted archives.** Yarn 1 writes a GitHub dependency as a
  `https://codeload.github.com/<owner>/<repo>/tar.gz/<ref>` archive. Neither Git
  nor Yarn checks those bytes, so a full commit in the path does not pin it.
  Without an `integrity` digest it is `unpinned` with `missing-digest`, and the
  commit is recorded as `archive_commit` with its `commit_hash_algorithm`. A
  reference that is not a full commit also gives `floating-ref`. The archive host
  is recorded, not compared, like every VCS host.
- **Registry artifacts.** Any other URL is a registry artifact with an exact
  `version`, pinned by an accepted `integrity` digest. The SHA-1 hex after the
  URL's `#` is a weak digest of its own: alone it gives `weak-digest`, and beside
  an accepted `integrity` it is clean.

## The declared registry

Origins are compared only with what the repository itself declares; user-level
and global npm configuration are not repository content.

- A tracked `.npmrc` beside the lockfile is read first, then the one at the
  repository root. `registry=` names the default registry and
  `@scope:registry=` the registry of one scope.
- With no `.npmrc` at either place, or no `registry` key, the declared registry
  is npm's documented default, `https://registry.npmjs.org/`.
- With the default `replace-registry-host`, a `resolved` URL on
  `registry.npmjs.org` is npm's placeholder for the configured registry, so it
  matches. Other hosts are compared literally, by host and explicit port; a
  registry's path is not compared.
- For Yarn 1, every tracked `.npmrc` and every tracked `.yarnrc` on the path
  from the repository root down to the lockfile's directory is read and merged
  per key, the nearer file winning, as Yarn 1 merges them; an untracked or
  unreadable file at any of those levels makes the origin unknown. Per package,
  Yarn's own order applies: the
  `.npmrc` registry of the package's scope, the `.yarnrc` one, then the unscoped
  `.npmrc` and `.yarnrc` registries. Yarn 1 fetches lockfile URLs as written, so
  there is no placeholder: with nothing declared, `registry.yarnpkg.com` and
  `registry.npmjs.org` are both the default; with a registry declared, any other
  host is `origin-mismatch`. `.yarnrc.yml` is Yarn 2+ configuration and is not
  read. A `.yarnrc` registry line with `${…}`, a `--registry` flag, a changed
  repeat, a non-HTTP(S) value or a line that does not tokenise is uncertain.
- Every artifact's origin is `origin-unknown`, never a pass, when the
  declaration cannot be read with certainty:
  - an `.npmrc` that is present but untracked, or tracked but not text;
  - a registry set through `${…}` interpolation;
  - a `replace-registry-host` other than `npmjs`;
  - a section header;
  - a repeated registry key with a different value;
  - a registry that is not an HTTP(S) URL.

## Refused files

A refused file names its reason and has no entry results.

| Reason | When |
|---|---|
| `unparseable` | not one strict JSON object, a non-finite number, an entry or level that is not an object, or nesting past the parser's recursion limit |
| `missing-version` | no `lockfileVersion` |
| `unsupported-version` | a `lockfileVersion` other than 1, 2 or 3 |
| `conflicting-entries` | a key repeated in one object, a version 2 legacy tree that disagrees with `packages`, or a Yarn 1 field or specifier repeated |
| `unreadable` | over the 8 MiB inventory limit, binary, or not UTF-8 |
| `ambiguous-yarn-lock` | a `yarn.lock` with neither, or both, the `# yarn lockfile v1` header and a top-level `__metadata:` block; a byte-order mark is `unparseable` |
| `unsupported-file-kind` | a recognised lockfile whose rules are not in this rule pack |
| `unsupported-lock-version` | reserved for Poetry lock formats below 2.0 |

## Rules

| Rule | Finding | Confidence |
| --- | --- | :---: |
| `SC003-lockfile-refused` | one candidate per refused file, with its kind and reason in the evidence | high |
| `SC004-lockfile-missing-digest` | `missing-digest` | high |
| `SC005-lockfile-weak-digest` | `weak-digest` | high |
| `SC006-lockfile-malformed-digest` | `malformed-digest` | high |
| `SC007-lockfile-floating-ref` | `floating-ref` | high |
| `SC008-lockfile-origin-mismatch` | `origin-mismatch` | high |
| `SC009-lockfile-origin-unknown` | `origin-unknown` | medium |
| `SC010-lockfile-path-escape` | `path-escape` | high |
| `SC012-lockfile-unknown-form` | `unknown-form` | medium |

`SC011-lockfile-manifest-drift` enters the rule pack with the first lockfile
kind that records a manifest hash. A finding candidate is anchored at its
entry's line and carries the file's SHA-256, the entry key's SHA-256, the class,
the finding and the entry's origin host, so a reviewer sees an unexpected host. A refused file without text is
anchored at the repository tree.

## The report

`rigor lockfile-integrity --root PATH [--json]` prints the classification of
every tracked lockfile; see the [command reference](cli.md#lockfile-integrity-provisional).
The `--json` form is the provisional `rigor.lockfile-integrity-report.v1`
record:

- `head`, `head_tree` and `tracked_content_digest` bind the repository state
  that was read; `rule_pack_version` and `rule_pack_digest` bind the rules;
- `summary` counts files, entries, every class, every finding and every
  refusal reason, zeros included; the entry counts include bundled entries;
- `files` lists one record per tracked lockfile in path order, with `path`,
  `file_sha256`, `kind`, `format_version`, `status` and `refusal_reason`;
- each file lists its entries in line, then key, order, with `key`, `line`,
  `class`, `form`, `findings`, `digest_algorithms`, `digest_scope`,
  `commit_hash_algorithm`, `origin`, `inherited_from` and `archive_commit`;
- `report_digest` is the SHA-256 of the canonical JSON of the report without
  that field. The report holds no floating-point number and only fixed ASCII
  member names, so the canonical JSON is the RFC 8785 serialisation.

## Boundaries

The rules read tracked lockfiles only. Which findings fail a build is the
consumer's policy, so the command exits zero whenever it produced a report.
Install commands and configuration that weaken verification (`npm install`
instead of `npm ci`, disabled checksums or registries) belong to a separate
companion rule. Calibration across adopter repositories is the maturity step
that can take a rule out of probation.

The clean test fixtures were generated by npm 6.14.18, 8.19.4 and 10.9.2 and by
Yarn 1.22.22, on Node.js 18.19.1 (`tests/fixtures/lockfiles/`), and every failing
case is a recorded edit of one of them.
