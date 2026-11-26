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
adds Yarn 1 (`yarn.lock` with the `# yarn lockfile v1` header), and
`rigor-foundry/1.22.0` adds Yarn 2+ (`yarn.lock` with a `__metadata` block),
`rigor-foundry/1.23.0` adds pnpm (`pnpm-lock.yaml`, `lockfileVersion` `6.0`
and `9.0`), `rigor-foundry/1.24.0` adds Cargo (`Cargo.lock` v1 to v4),
`rigor-foundry/1.25.0` adds Go (`go.sum`, read with the `go.mod` beside it),
`rigor-foundry/1.26.0` adds Poetry (`poetry.lock`, `lock-version` `2.0` and
`2.1`), `rigor-foundry/1.27.0` adds Pipenv (`Pipfile.lock`, `pipfile-spec`
6), and `rigor-foundry/1.28.0` compares Poetry's and Pipenv's manifest hashes
(`SC011`). Every lockfile kind the rules recognise is now classified. All the rules are in maturity probation.

## One class per entry

Every locked entry gets exactly one class, plus zero or more findings.

| Class | Meaning |
|---|---|
| `artifact-pinned` | an exact version and an accepted, well-formed digest of the fetched artifact |
| `commit-pinned` | a VCS source with a full commit id (40 or 64 lower-case hex) |
| `local` | a path, link or workspace source inside the repository root |
| `unpinned` | a recognised artifact, VCS or path form that fails its pin; its `form` is recorded |
| `unclassified` | a form these rules do not know; it always carries `unknown-form` |
| `graph-only` | in the graph but not fetched itself: a Cargo package that names a `replace`, or a Go module version that `go.sum` lists with only its `/go.mod` line and `go.mod` does not require |

An `unpinned` entry always names its failure: `missing-digest`,
`weak-digest`, `malformed-digest`, `floating-ref` or `path-escape`. The other
entry findings are `origin-mismatch`, `origin-unknown` and `unknown-form`.
`manifest-drift` belongs to a whole Poetry or Pipenv lockfile; see
[Manifest drift](#manifest-drift).

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
- **two exceptions:** in Poetry and Pipenv lockfiles every listed hash must be
  accepted, and a weak one anywhere gives `weak-digest`. Poetry checks the file
  an install picks, which depends on the platform, against that file's own
  hash; pip, which Pipenv drives, accepts a file when any listed hash of any
  algorithm matches (`check_against_chunks`). Either way a weak hash is a way
  in. See the two sections below;
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

## Yarn 2+ lockfiles

- **Syntax and versions.** The file is YAML read without anchors, aliases or
  tags, with a duplicate key refused as `unparseable`. Only `__metadata.version`
  values that a real Yarn release wrote into a fixture here are read: 6 (Yarn 3)
  and 10 (Yarn 4). Any other version is `unsupported-version`. `cacheKey` must
  match `^[0-9]+([a-z][0-9a-z]*)?$`. Each entry's key lists its descriptors and
  must be written as Yarn writes it: plain when it is a plain YAML string and
  JSON-quoted otherwise, on the line before its fields, or, when longer than
  1024 characters, after `? ` with the `:` alone on the next line. Any other
  layout is `unparseable`, and a descriptor named by two entries is
  `conflicting-entries`.
- **Checksums.** A `checksum` hashes Yarn's own cache archive, so its scope is
  `cache-archive`. Yarn 3 writes bare hex and Yarn 4 prefixes the cache key. A
  checksum whose cache key differs from `__metadata.cacheKey` is not verified by
  Yarn, so it is `malformed-digest`, and the entry's `notes` record
  `digest_problem: foreign-cache-key` with both keys.
- **Registry artifacts.** An `npm:` resolution has no URL: its origin is the
  registry declared for its scope. An `npm:` alias (`foo@npm:bar@1.0.0`) is the
  artifact `bar`, with `alias` recorded. A tarball URL is compared with the
  declared registry.
- **Git.** A clone (`git:`, `git+…`, `ssh:`) at a full `#commit=` is
  `commit-pinned`. A GitHub archive is an artifact pinned only by its checksum,
  with `archive_commit`. `#head=`, `#tag=`, `#semver=` and short commits give
  `floating-ref`.
- **Local and other protocols.** `file:` (its checksum recorded), `link:`,
  `portal:` and `workspace:` are `local`, and give `path-escape` outside the
  repository. `exec:` and any other protocol are `unclassified` with
  `unknown-form`.
- **Paths.** A path is read as Yarn 3.8.7 and 4.19.0 read it: the part after
  `#` (or the whole reference without one), URL-decoded. A relative path is
  resolved from the package its `locator` binding names: a workspace's
  directory, or a local package's own folder found the same way, at most 32
  levels deep. A path relative to a fetched package is inside that package,
  not the repository, so the entry is `unknown-form`, as is a path Yarn could
  not read (no single `locator`, or a bad `%` escape). An absolute path leaves
  the repository whoever declared it.
- **Patches.** A `patch:` entry is classified by its own checksum, and its base
  is a separate entry. `notes` records `patch_source`: `builtin<name>` for a
  patch that ships with Yarn, or the patch paths, joined by `&` as Yarn joins
  them. Every path must stay inside the repository. Flags are read as the Yarn
  that wrote the lockfile reads them: for version 6 (Yarn 3) a leading `~`
  means optional, so `~/x` is the absolute `/x`; for version 10 (Yarn 4) flags
  end at the last `!`, and `~/` is the project root.

## pnpm lockfiles

- **Versions and documents.** Only the versions a real pnpm release wrote into a
  fixture here are read: `6.0` (pnpm 8.15.9) and `9.0` (pnpm 9.15.9 to
  12.23.0). Any other is `unsupported-version`. pnpm 11 and later may write two
  YAML documents, an env document (configuration dependencies and the pinned
  package manager) and then the main lockfile. Both are read, and the env
  document's entries are keyed `env › <key>`. An env document with no main
  document has no fixture and is `unsupported-version`. A tracked git-branch
  lockfile, `pnpm-lock.<branch>.yaml`, is refused as `unsupported-version`,
  never skipped.
- **Entries.** Each `packages` key is an entry, classified by its `resolution`.
  In `9.0`, `snapshots` add peer and patch suffixes, and a snapshot whose package
  is missing makes the file `unparseable`. Each importer's `link:` dependency
  (`workspace:` included) is a `local` entry keyed `<importer> › <name>`, its
  path resolved from the importer's directory. A `6.0` lockfile of a single
  project writes its dependencies at the top level, as importer `.`; pnpm 8
  writes one form or the other, so a `6.0` file with both is `unparseable`. A
  key must
  be written as js-yaml writes it: plain or quoted on the line before its
  fields, or after `? ` with the `:` alone on the next line when longer than
  1024 characters.
- **Registry packages and tarballs.** A resolution with no `type` and no
  `tarball` comes from the registry declared for its scope and is pinned by its
  `integrity`. A relative `tarball` is resolved against that registry, as pnpm's
  `new URL(tarball, registry)` does. An absolute one is compared with the
  registry, giving `origin-mismatch` otherwise, and records
  `tarball_url_dependency`.
- **Git-hosted archives.** pnpm exempts codeload, GitLab and Bitbucket archives
  from integrity because their URL names a commit, but nothing verifies those
  bytes against the commit. So, as for Yarn 1, such an archive is an artifact
  pinned only by its `integrity`, with `archive_commit`, and another reference
  gives `floating-ref`. pnpm 8 and 9 never write that integrity; pnpm 10 and 11
  write it when they download the archive.
- **Git clones and local sources.** `type: git` at a full commit is
  `commit-pinned`, with the repository host and any `path` recorded.
  `type: directory` and `file:` tarballs are `local`, resolved from the
  lockfile's directory (a tarball's integrity is recorded), and give
  `path-escape` outside the repository. `binary`, `variations`, `custom:…` and
  any other `type` have no fixture yet and are `unknown-form`.
- **Patches.** A patched package is classified by its own `integrity`, and
  `notes` record `patch_hash` and `patch_source`. pnpm 8 to 10 write the patch's
  path into `patchedDependencies`; pnpm 11 writes only its hash, and the path
  comes from the tracked `pnpm-workspace.yaml`. Without a path the entry is
  `unknown-form`; a path outside the repository is `path-escape`.

## Cargo lockfiles

- **Formats.** Only the formats a real Cargo release wrote into a fixture here
  are read: v1 (Cargo 1.40.0), v2 (1.47.0), `version = 3` (1.75.0) and
  `version = 4` (1.83.0 and 1.100.0). The version is a TOML integer, as Cargo
  reads it; a float such as `3.0` is `unsupported-version`. v1 and v2 carry no
  `version`: v1 lists its
  checksums in `[metadata]` as `"checksum <name> <version> (<source>)"`, and v2
  lists them on each package. A v1 file with no registry package has no checksum
  keys, so it reads as v2; that is harmless, since nothing in it has a digest to
  read. `version = 5`, or any other value, is `unsupported-version`. A file whose
  `[metadata]` holds checksum keys but which is otherwise v2 or later is one
  Cargo treats as a bad merge, dropping every checksum, so it is refused as
  `conflicting-entries`.
- **Entries and lines.** Each `[[package]]` is an entry at its header's line, and
  Cargo writes `name` and `version` on the two lines after it; any other layout
  is `unparseable`. The key is `<name> <version>`, with ` (<source>)` added when
  two entries share a name and a version. `[[patch.unused]]` is not installed,
  so it is not classified, and the file records `unused_patches`.
- **Registry packages.** A `registry+` or `sparse+` package is pinned by the
  64-hex lowercase sha256 Cargo verifies on download; a missing checksum or
  `"<none>"` is `missing-digest`, and any other shape `malformed-digest`. The
  origin is the index the lockfile names, so it is not compared: crates.io's two
  source IDs report `crates.io`, and any other index is recorded by host with
  `alternate_registry`. Source replacement, which changes where the bytes come
  from but keeps the recorded checksums, is the companion rule's.
- **Git packages.** The full commit after `#` pins a Git package, whatever its
  query asks for. The query is recorded as `git_reference` (`default-branch`
  when there is none), and a 64-hex commit is a sha256 one. A missing, short or
  non-hex fragment is `floating-ref`.
- **Path packages and workspace members** have no source and are `local`, noted
  `path_unverified: manifest`. The lockfile cannot show whether such an entry is
  a real path dependency or a registry entry with its `source` and `checksum`
  stripped; `cargo --locked` refuses that mismatch against `Cargo.toml`, and a
  manifest rule is the place to check it.
- **`[replace]`.** A package that names a `replace` is `graph-only`, noted
  `replaced_by`, and its replacement is classified as its own entry in the same
  file, so a Cargo `graph-only` entry always carries `replaced_by`. A `replace`
  that names no package in the file, or names one that itself carries a
  `replace` (a package replacing itself, a cycle or a chain, which Cargo never
  writes and which would hide an unpinned package), is `unparseable`.

## Go lockfiles

- **The pair.** Each tracked `go.sum` is read with the tracked `go.mod` beside
  it. Go never writes a `go.sum` alone, so one without a `go.mod` is
  `unparseable`; a `go.mod` that is present but untracked, or not text, is
  `unreadable`. `go.sum` has no format version: Go 1.16.15, 1.17.13, 1.22.2 and
  1.27.4 wrote byte-identical files for the fixtures, so `format_version` is
  `go.sum`.
- **Reading `go.sum`** follows Go's `readGoSum` (go1.27.4): lines end only at a
  line feed, fields are separated by the characters `unicode.IsSpace` accepts
  (so CRLF reads the same), blank lines are skipped, and any other line without
  exactly three fields is `unparseable`. Lines carrying the empty-`go.mod` hash
  (`h1:G7mAYYxgmS0lVkHyy2hEOLQCFB0DlQFTMLWggykrydY=`), which an old Go wrote
  for non-modules, are skipped as Go skips them, and the file records how many
  as `dropped_lines`. Two different hashes of one line kind for one module
  version are `conflicting-entries`, since Go accepts whichever matches;
  identical repeats are accepted.
- **Reading `go.mod`** follows Go's own grammar (`golang.org/x/mod/modfile`):
  `require`, `exclude` and `replace` are read, as lines or blocks; `module`,
  `go`, `toolchain`, `godebug`, `retract`, `tool` and `ignore` are accepted and
  not read, and `module`, `godebug`, `retract`, `tool` and `ignore` may be
  blocks, as in Go. Versions are kept as written. A `go.mod` is `unparseable`
  when it holds any of these:
  - a directive Go does not know;
  - a `/*` comment, or a character Go's lexer refuses (a byte-order mark
    included);
  - a quote inside a word, or a back-quoted string;
  - a double-quoted string with a backslash escape (Go accepts some; this
    reader does not decode them);
  - a line ending in `(` other than a block directive followed by `(` alone
    (Go's "unknown block type"), or a block that is never closed;
  - `require`, `exclude` or `replace` arguments Go refuses.

  Two different replacements of one module version are `conflicting-entries`,
  as Go refuses them.
- **Entries and lines.** Each module version is one entry, keyed
  `<module> <version>` exactly as written (pseudo-versions and `+incompatible`
  included), at its `h1:` line, else at its `/go.mod` line.
  - With both lines it is `artifact-pinned`, with `digest_scope` `module-tree`:
    `h1:` is Go's `dirhash.Hash1`, a SHA-256 over the module's files, not over an
    archive. Only a lower-case `h1:` followed by standard base64 of exactly 32
    bytes pins; any other prefix or shape is `malformed-digest`.
  - With only its `/go.mod` line it is `graph-only`, noted
    `go_mod_digest: present`: that hash covers only the module's `go.mod`, a
    graph digest, and Go needs the module's files only when it builds a package
    from it.
  - A version that `go.mod` requires needs both lines; without either it is
    `missing-digest`. A required version with no line at all stands at line 1,
    which stands for the file, noted `required_at: go.mod:<line>`, and its
    candidate's evidence ends with `; required_at=go.mod:<line>`.
- **`replace`.** A replacement Go reads as a directory (`modfile.IsDirectoryPath`)
  makes the required version `local`, noted `replaced_by` with the directory;
  the directory is read from the directory of `go.mod`, and one outside the
  repository is `path-escape`. A module replacement makes the required version
  take its target's class from the target's `go.sum` lines, noted `replaced_by:
  <module> <version>`. A replacement with no version on its left applies to
  every version, and one naming the exact version wins, as in Go.
- **`exclude`.** Lines for an excluded version are classified as written, noted
  `excluded_at: go.mod:<line>`, with no finding; Go leaves that version out of
  the build list.
- **Origin.** The origin is the module path's first element: the import path's
  host, not the server. `golang.org/x`, `gopkg.in` and `go.uber.org` are vanity
  paths, and `GOPROXY`, from the environment, chooses the server; `h1:` and the
  checksum database bind the bytes whoever serves them. The proxy configuration
  is the companion rule's. A local replacement's origin is `local`.
- **Known limits.** Build-list completeness, which pruned module graphs leave to
  `go.mod`, is the companion rule's. With `vendor/` and `-mod=vendor`, Go builds
  from the vendored tree without checking `go.sum`, so a pinned `go.sum` proves
  nothing about vendored code. `go.work.sum`, written for Go workspaces, is not
  read yet.

## Poetry lockfiles

- **Versions.** Poetry 1.3 to 1.8 write `lock-version = "2.0"` and Poetry 2
  writes `"2.1"`; these two are read, and `format_version` is the string.
  Poetry 1.2 and older write `1.x`, with every hash in `[metadata.files]` keyed
  by name alone, so a `lock-version` below 2.0 is `unsupported-lock-version`;
  regenerate it with Poetry 1.3 or later. A missing `lock-version` is
  `missing-version`. Any other value, `2.2` or a non-string included, is
  `unsupported-version`, and a 2.x file that also has `[metadata.files]` mixes
  the two encodings as `conflicting-entries`.
- **Entries and lines.** Each `[[package]]` is an entry at its header's line,
  with `name` and `version` on the two lines after it, as for Cargo. The key is
  `<name> <version>`, plus ` (<source url>)` when two entries share both. A
  package without `files`, which Poetry cannot read, is `unparseable`.
- **Digests.** Poetry verifies an archive at install by its file name against
  `files`, and verifies nothing when `files` is empty, which is
  `missing-digest`. Each hash is `<algorithm>:<hex>` at the algorithm's length.
  **Every file must carry an accepted hash:** a sha1 or md5 hash on any file
  gives `weak-digest`, even beside accepted ones, because the file an install
  picks depends on the platform. This is one of the two exceptions to the rule
  that one accepted digest suffices. An algorithm outside the accepted and weak ones
  (Poetry also knows `sha224` and the `sha3`, `shake` and `blake2` families) is
  `malformed-digest`, noted `unrecognised_algorithm`.
- **Sources.**
  - no `[package.source]`: PyPI, `artifact-pinned` through `files`, with origin
    `pypi.org`;
  - `legacy`: an index, `artifact-pinned` through `files`, with its URL's host
    as origin, compared with the declared sources (below);
  - `url`: a direct archive, `artifact-pinned` through `files`, with its URL's
    host as origin; the URL is the dependency itself, so nothing is compared;
  - `file` and `directory`: `local`, read from the lockfile's directory, and
    `path-escape` outside the repository; a file's hash is recorded as the
    note `file_hash`, and a developed directory as `develop`;
  - `git`: `commit-pinned` by a full `resolved_reference`, with
    `commit_hash_algorithm`, `git_reference` and any `subdirectory`; a missing
    or short one is `floating-ref`;
  - any other type, or a known one without its URL, is `unclassified` with
    `unknown-form`.
- **Declared sources.** They are the `[[tool.poetry.source]]` entries of the
  tracked `pyproject.toml` beside `poetry.lock`.
  - An index package must name a declared source by `reference`, compared
    without case, at that source's URL, ignoring the trailing slash Poetry
    strips; otherwise it is `origin-mismatch`.
  - A PyPI package is `origin-mismatch` when the declaration deactivates PyPI
    for the Poetry generation that wrote the lockfile, and no source is named
    `pypi`:
    - for `lock-version` 2.0 (Poetry 1.3 to 1.8), a source with
      `default = true` (1.3.2), or with `priority = "default"` or `"primary"`
      (1.8.5); `secondary = true` and the other priorities keep PyPI;
    - for `lock-version` 2.1 (Poetry 2), a source whose `priority` is
      `"primary"` or absent.
  - A `pyproject.toml` that is absent, untracked, not text, not TOML or not
    the shape Poetry writes gives `origin-unknown` on every PyPI and index
    entry.
  - A declaration that cannot be judged for the generation that wrote the
    lockfile gives `origin-unknown` on every PyPI entry: a priority that
    generation does not know; a `default` or `secondary` key beside a Poetry 2 lockfile
    (Poetry 2's schema refuses them); or, beside a 2.0 lockfile, a source with
    none of `default = true`, `secondary = true` or a priority, which 1.8.5
    counts as primary and so deactivates PyPI, while 1.3.2 keeps PyPI, and the
    lockfile cannot tell which wrote it.
  - Neither is ever a refusal.
- **Not read:** `groups`, `category`, `markers`, `extras`, `dependencies`,
  `optional`, `python-versions` and `description`, even when malformed; they
  play no part in the pin.
- **`content-hash`** is Poetry's hash of the manifest the lockfile was made
  from. It is recorded as the file's `manifest_hash`, a drift signal and never
  an artifact digest, and is compared with `pyproject.toml`; see
  [Manifest drift](#manifest-drift).

## Pipenv lockfiles

- **Version.** Pipenv 2020.11.15 to 2026.12.1 all write `pipfile-spec` 6, which
  is read; `format_version` is `6`. Only the integer 6 is accepted: another
  number, a string, the float `6.0` or a boolean is `unsupported-version`, and
  a missing `_meta` or `pipfile-spec` is `missing-version`. The JSON is read as
  npm's is: a repeated key is `conflicting-entries`, and anything that is not
  one strict JSON object of objects where Pipenv writes them is `unparseable`.
- **Categories, keys and lines.** Every top-level key except `_meta` is a
  category: `default`, `develop`, and from Pipenv 2022.10 the categories a
  Pipfile names. Each entry is keyed `<category>/<name>`, since one package can
  sit in several categories, and stands at its own key's line.
- **Digests.** An entry's `hashes` is a list of `<algorithm>:<hex>`; a missing
  or empty list is `missing-digest`. **Every listed hash must be accepted:** pip
  accepts a file when any listed hash matches, so an md5 or sha1 hash anywhere
  gives `weak-digest`, even beside accepted ones. An algorithm outside the table
  is `malformed-digest`, noted `unrecognised_algorithm`; pip refuses an unknown
  one.
- **Forms.**
  - an exact `version`, one `==<version>` with no `*`, `,`, `;` or space:
    `artifact-pinned` through its hashes, from the source its `index` names
    (below); `===`, prefix matches such as `==1.*`, ranges, several specifiers
    and `*` pin no artifact and are `unclassified` with `unknown-form`;
  - a `file` with an `http` or `https` URL: `artifact-pinned` through its
    hashes, with the URL's host as origin; Pipenv 2026.12.1 writes no hash for
    such an entry, which is `missing-digest`;
  - a `file` with a local path, and a `path`: `local`, read from the lockfile's
    directory, and `path-escape` outside the repository; a local file's hashes
    are recorded as the note `file_hash`, and `editable: true` as `editable`;
  - `git`: `commit-pinned` by a 40- or 64-hex `ref`, with
    `commit_hash_algorithm` and any `subdirectory`; any other `ref` is
    `floating-ref`, with the URL's host as origin;
  - `hg`, `svn`, `bzr`, a `file` with another scheme, or an entry with none of
    these keys: `unclassified` with `unknown-form`.
- **Origins.** An exact-version entry's `index` must name a source in
  `_meta.sources`, compared exactly as written, and its origin is that source's
  host; any other name is `origin-mismatch`. Two sources with one name leave
  the index ambiguous, so the file is refused as `conflicting-entries`. Without an `index`, pip may take
  the entry from any declared source, so its origin is the one source when
  there is exactly one, and otherwise `origin-unknown`. A source with
  `verify_ssl: false` is noted on the entries that name it; weakened transport
  is the companion rule's. The Pipfile's own `[[source]]` is not compared with
  `_meta.sources` here.
- **Not read:** `markers`, `extras` and `_meta.requires`.
- **`_meta.hash.sha256`** is the hash of the Pipfile the lockfile was made from.
  It is recorded as the file's `manifest_hash`, a drift signal, and is compared
  with the `Pipfile`; see [Manifest drift](#manifest-drift).

## Manifest drift

`rigor-foundry/1.28.0` compares the manifest hash that a Poetry or Pipenv
lockfile records with the tracked manifest beside it. It raises
`SC011-lockfile-manifest-drift` when the hash matches no form that the tool
which wrote the lockfile, or the current release, computes from that manifest.
The rule follows one principle: a false drift is worse than a missing one.

- **The manifest.** It is `pyproject.toml` beside `poetry.lock` and `Pipfile`
  beside `Pipfile.lock`, as both tools read them.
- **The states.** Each file's `manifest_check` records one:
  - `fresh` or `drift`;
  - `manifest-missing`, when no manifest sits beside the lockfile;
  - `manifest-uncertain`, when the manifest is present but untracked, or
    tracked but not text (reason `manifest-untracked-or-not-text`). It is also
    the state when a Poetry writer newer than the newest release mirrored here,
    2.5.2, matches no F1 (reason `writer-newer-than-mirrored`);
  - `manifest-unparseable`, when the TOML does not parse, a hashed table has
    another type, or a hashed value has no JSON form, such as a TOML date.
    Poetry 1.8.5 and 2.5.2 refuse such a manifest as invalid, and Pipenv
    2025.0.4 and 2026.12.1 fail with `TypeError`.

  Only `drift` gives SC011.
- **Poetry's forms,** read in `packages/locker.py` at each release's tag:
  - **F1, from 2.3.0,** hashes `[project]`'s `requires-python`, `dependencies`
    and `optional-dependencies`, a non-empty `[dependency-groups]`, and
    `[tool.poetry]`'s `dependencies`, `source`, `extras`, `dev-dependencies` and
    `group`;
  - **F2, 2.0 to 2.2,** is F1 without the groups;
  - **F3, 1.x,** is the `[tool.poetry]` part alone.
- **The writer** is the version that line 1 names (`@generated by Poetry
  <version>`), ordered as PEP 440 orders versions, so `2.3.0b1` comes before
  `2.3.0`. The accepted forms are the union of the writer's own verdict and that
  of Poetry 2.5.2, which recomputes without the groups for a writer before 2.3.0:
  - from 2.3.0 to 2.5.2: F1;
  - from 2.0 to before 2.3.0: F1 or F2;
  - before 2.0, or a line 1 without a parseable version: F1, F2 or F3;
  - after 2.5.2: F1, and a mismatch is `manifest-uncertain`, because a later
    Poetry may hash differently.

  Two consequences, both as Poetry itself reports them:
  - a `[dependency-groups]` table added after a 2.5.2 lock is drift, although
    the hash without the groups still matches;
  - a group changed after a pre-2.3.0 lock is not detected.
- **Pipenv's forms:**
  - **plette's,** used from 2022.12.19 to 2025.x, and by 2020.11.15 over
    `default` and `develop`;
  - **the PEP 503 canonical form** of 2026.12.1.

  `Pipfile.lock` names no writer, and each current release calls the other's
  fresh lock of a Pipfile with a non-canonical package name stale, so either
  form is accepted.
  - PyPI is inserted as the source when `[[source]]` is absent, as every
    release does.
  - A `${VAR}` in a source URL is hashed as written, never expanded, by both
    current releases.
  - A changed source is drift through the hash.
- **A lockfile without its hash,** with no `content-hash` or no `_meta.hash`,
  is drift with `recorded=none`. Both tools call such a lock stale.
- **Not read:** environment variables, the manifest's other keys, its layout and
  its key order.
- **The fixtures.** There are 34 real cases (`manifest-*`), generated by
  `tests/fixtures/lockfiles/generate-manifest-drift.sh` with Poetry 1.8.5, 2.2.1
  and 2.5.2 and Pipenv 2020.11.15, 2025.0.4 and 2026.12.1.
  - Each case keeps the tool's own freshness check in `verdict.txt`: its
    command, its exit status and its final message.
  - Two complete runs wrote identical bytes.

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
- For Yarn 2+, only `.yarnrc.yml` is read: every tracked one from the root down
  to the lockfile's directory, merged per key with the nearer winning and
  `npmScopes` merged per scope. `npmRegistryServer` is the default registry
  (`https://registry.yarnpkg.com` when unset) and
  `npmScopes.<scope>.npmRegistryServer` a scope's. A file that is not one YAML
  mapping, `${…}` in a read value, or a registry that is not an HTTP(S) URL is
  uncertain. A `checksumBehavior` of `ignore` or `update` is recorded on the
  lockfile's result as `checksum_behavior`, because Yarn then accepts a checksum
  mismatch.
- For pnpm, only the tracked `.npmrc` beside the lockfile (pnpm's workspace
  root) is read for `6.0`, because pnpm 8 ignores `pnpm-workspace.yaml`
  registries. A `9.0` lockfile does not say whether pnpm 10 or 11 installs it,
  and they read differently: pnpm 10 builds its registries from its defaults
  and `.npmrc` alone, while pnpm 11 lets the tracked `pnpm-workspace.yaml`
  `registry` and `registries` win (within the YAML, `registry` beats a
  `registries` default). Both views are built, and every scope whose host
  differs between them is `origin-unknown`, a YAML-only scope or default
  included; a YAML entry that names the same host as the pnpm 10 view stays
  clean. With nothing declared the default is
  `registry.npmjs.org`, and for `9.0` the `@jsr` scope is `npm.jsr.io`. A
  `registries` setting that mixes its two shapes, names an unknown field, routes
  a scope twice, or holds `${…}` is uncertain.
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
| `unparseable` | not one strict JSON object, a non-finite number, an entry or level that is not an object, or nesting past the parser's recursion limit; a `go.sum` with no `go.mod` beside it, a `go.sum` line without three fields, or a `go.mod` outside the grammar subset |
| `missing-version` | no `lockfileVersion`, or no Poetry `lock-version` |
| `unsupported-version` | a version the kind's rules do not read, such as an npm `lockfileVersion` other than 1, 2 or 3, or a pnpm branch lockfile |
| `conflicting-entries` | a key repeated in one object, a version 2 legacy tree that disagrees with `packages`, a Yarn 1 field or specifier repeated, two different `go.sum` hashes of one line kind for one module version, two different `replace` targets for one module version, `[metadata.files]` in a Poetry 2.x lockfile, or a repeated source name in a `Pipfile.lock` |
| `unreadable` | over the 8 MiB inventory limit, binary, or not UTF-8; for `go.sum`, a `go.mod` beside it that is untracked or not text |
| `ambiguous-yarn-lock` | a `yarn.lock` with neither, or both, the `# yarn lockfile v1` header and a top-level `__metadata:` block; a byte-order mark is `unparseable` |
| `unsupported-file-kind` | reserved for a recognised lockfile whose rules are not in this rule pack; since `rigor-foundry/1.27.0` every recognised kind has its rules |
| `unsupported-lock-version` | a Poetry `lock-version` below 2.0 |

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
| `SC011-lockfile-manifest-drift` | one candidate per Poetry or Pipenv lockfile whose manifest hash has drifted, from `rigor-foundry/1.28.0` | high |
| `SC012-lockfile-unknown-form` | `unknown-form` | medium |

A finding candidate is anchored at its
entry's line and carries the file's SHA-256, the entry key's SHA-256, the class,
the finding and the entry's origin host, so a reviewer sees an unexpected host. A Go version that `go.mod`
requires and `go.sum` does not list stands at `go.sum` line 1, and its evidence
ends with `; required_at=go.mod:<line>`, so a reviewer finds the requirement.
A refused file without text is anchored at the repository tree.

An SC011 candidate stands at the lockfile line that records the hash, or at
line 1 when there is none. Its evidence is
`file_sha256=…; manifest=<path>; manifest_sha256=…; recorded=<hash|none>; writer=…; accepted=<forms>`.
`writer` is the text after `Poetry` on line 1, `unknown` when line 1 names
none, and `none` for Pipenv.

## The report

`rigor lockfile-integrity --root PATH [--json]` prints the classification of
every tracked lockfile; see the [command reference](cli.md#lockfile-integrity-provisional).
The `--json` form is the provisional `rigor.lockfile-integrity-report.v1`
record:

- `head`, `head_tree` and `tracked_content_digest` bind the repository state
  that was read; `rule_pack_version` and `rule_pack_digest` bind the rules;
- `summary` counts files, entries, every class, every finding, every refusal
  reason and, in `manifest_states`, every manifest state, zeros included. The
  entry counts include bundled entries, and `manifest-drift` counts drifted
  files;
- `scope_note` says that installer configuration that weakens verification is
  evaluated by a separate configuration rule;
- `files` lists one record per tracked lockfile in path order, with `path`,
  `file_sha256`, `kind`, `format_version`, `status`, `refusal_reason`,
  `checksum_behavior`, `unused_patches`, `dropped_lines`, `manifest_hash` and
  `manifest_check`. `manifest_check` is `null` except for Poetry and Pipenv
  lockfiles that were classified, where it holds `manifest_path`,
  `manifest_sha256`, `state`, `reason`, `recorded`, `hash_line`, `writer` and
  `accepted`;
- each file lists its entries in line, then key, order, with `key`, `line`,
  `class`, `form`, `findings`, `digest_algorithms`, `digest_scope`,
  `commit_hash_algorithm`, `origin`, `inherited_from`, `archive_commit` and
  `notes` (named evidence: `alias`, `alternate_registry`, `develop`,
  `digest_problem` with the cache keys, `excluded_at`, `file_hash`, `git_path`,
  `git_reference`, `go_mod_digest`, `patch_hash`, `patch_source`,
  `path_unverified`, `replaced_by`, `required_at`, `subdirectory`,
  `tarball_url_dependency` or `unrecognised_algorithm`); `digest_scope` is `artifact`, `cache-archive`,
  `uncompressed-tar`, `parent-artifact` or `module-tree`;
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

The clean test fixtures (`tests/fixtures/lockfiles/`) were generated by npm
6.14.18, 8.19.4 and 10.9.2, by Yarn 1.22.22, 3.8.7 and 4.19.0, and by pnpm 8.15.9,
9.15.9 and 10.34.9, all on Node.js 18.19.1, and by pnpm 11.29.0 and 12.23.0 on
Node.js 26.13.0. Each pnpm release ran with a fresh store, so a repeated run
writes the same bytes. The Cargo fixtures were generated by Cargo 1.40.0,
1.47.0, 1.75.0, 1.83.0 and 1.100.0, against crates.io sources vendored once and
read through source replacement, a loopback Git daemon and a loopback sparse
registry serving crates.io's own crate and index line. The Go fixtures were
generated by Go 1.16.15, 1.17.13, 1.22.2 and 1.27.4, each with fresh module and
build caches, against `proxy.golang.org` and `sum.golang.org`; every release
wrote the same `go.sum`, and two complete runs wrote the same bytes. Go 1.27.4
also wrote `tool`, `godebug` and `ignore` blocks into one `go.mod` through
`go mod edit`. The Poetry fixtures were generated by Poetry 1.2.2, 1.3.2, 1.8.5,
2.0.1 and 2.5.2, each wheel checked against the sha256 PyPI publishes and its
dependencies resolved as of its release, with fresh caches, for one project
holding a PyPI package, a declared loopback index serving PyPI's own wheel, a
loopback Git daemon, a directory, a local wheel and a URL; two complete runs
wrote the same bytes. The Pipenv fixtures were generated in the same way by
Pipenv 2020.11.15, 2022.12.19, 2023.12.1, 2024.4.1, 2025.0.4 and 2026.12.1, for
one Pipfile adding an editable path, a development package and, from 2022, a
custom category; 2023.12.1 and 2024.4.1 wrote the same lockfile. Pipenv records
PyPI's sdist hash beside a local wheel's own, and 2020.11.15 records it for the
loopback-index package too; both are accepted hashes. Every failing case is a
recorded edit of one of them.
