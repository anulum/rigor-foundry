#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — regenerate the clean pnpm lockfile fixtures with pinned pnpm releases
# Usage: generate-pnpm.sh EMPTY_OUTPUT_DIRECTORY [NODE22_BIN_DIR] (needs node, npx, git and network access to the npm
# registry and GitHub; pnpm 11 and 12 run on the Node 22.13 or later found in NODE22_BIN_DIR). The repository stores
# pnpm-lock.yaml, the manifests and the patch gzip-compressed (Python gzip, level 9, mtime 0); GENERATED_BY.txt records
# the SHA-256 of the uncompressed lockfile.
set -euo pipefail
R="${1:?usage: generate-pnpm.sh EMPTY_OUTPUT_DIRECTORY [NODE22_BIN_DIR]}"
N22="${2:-}"
mkdir -p "$R"
if [ -n "$(ls -A "$R")" ]; then echo "refusing: $R is not empty" >&2; exit 2; fi
cd "$R"
export npm_config_cache="$R/npm-cache" npm_config_update_notifier=false
V=/tmp/rigor-pnpm-fixture
rm -rf "${V:?}"; mkdir -p "$V/work"
git -C "$V/work" init -q -b main
printf '{\n  "name": "vcs-lib",\n  "version": "1.0.0"\n}\n' > "$V/work/package.json"
git -C "$V/work" add package.json
GIT_AUTHOR_DATE=2026-11-25T00:00:00Z GIT_COMMITTER_DATE=2026-11-25T00:00:00Z git -C "$V/work" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m fixture
git clone -q --bare "$V/work" "$V/vcs-lib.git"
SHA=$(git -C "$V/vcs-lib.git" rev-parse HEAD)
# Serve the bare repository on loopback so pnpm clones it through Git (git://), the form B7 pins by commit.
git daemon --base-path="$V" --export-all --reuseaddr --listen=127.0.0.1 --port=19419 "$V" > "$R/git-daemon.log" 2>&1 &
DAEMON=$!
trap 'kill "$DAEMON" 2>/dev/null || true' EXIT
sleep 1
for ver in 8.15.9 9.15.9 10.34.9 11.29.0 12.23.0; do
  d="$R/pnpm-$ver"; mkdir -p "$d/local-lib" "$d/linked-lib" "$d/local-tgz" "$d/packages/ws-a" "$d/patches"
  # pnpm 11 and later read settings only from pnpm-workspace.yaml; earlier releases read patchedDependencies from package.json.
  case "$ver" in
    8.*|9.*|10.*) manifest_patch=',
  "pnpm": {
    "patchedDependencies": {
      "ms@2.1.2": "patches/ms@2.1.2.patch"
    }
  }'; workspace_patch="" ;;
    *) manifest_patch=""; workspace_patch='patchedDependencies:
  ms@2.1.2: patches/ms@2.1.2.patch
' ;;
  esac
  cat > "$d/package.json" <<PKG
{
  "name": "rigor-lockfile-fixture-pnpm",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "debug": "4.3.4",
    "left-pad": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
    "ms-tarball": "https://registry.yarnpkg.com/ms/-/ms-2.0.0.tgz",
    "local-tgz": "file:./local-tgz/local-tgz-1.0.0.tgz",
    "ms-alias": "npm:ms@2.1.3",
    "is-number": "github:jonschlinkert/is-number#98e8ff1da1a89f93d1397a24d7413ed15421c139",
    "vcs-lib": "git://127.0.0.1:19419/vcs-lib.git#$SHA",
    "local-lib": "file:./local-lib",
    "linked-lib": "link:./linked-lib",
    "ws-a": "workspace:*"
  }$manifest_patch
}
PKG
  printf 'packages:\n  - "packages/*"\n%b' "$workspace_patch" > "$d/pnpm-workspace.yaml"
  # A local tarball, packed by npm from a one-file package (npm pack sets fixed entry times).
  mkdir -p "$R/tgz-src-$ver"; printf '{\n  "name": "local-tgz",\n  "version": "1.0.0"\n}\n' > "$R/tgz-src-$ver/package.json"
  (cd "$R/tgz-src-$ver" && npm pack --silent --pack-destination "$d/local-tgz" > /dev/null)
  for lib in local-lib linked-lib; do printf '{\n  "name": "%s",\n  "version": "1.0.0"\n}\n' "$lib" > "$d/$lib/package.json"; done
  printf '{\n  "name": "ws-a",\n  "version": "1.0.0",\n  "dependencies": {\n    "linked-lib": "link:../../linked-lib",\n    "local-lib": "file:../../local-lib"\n  }\n}\n' > "$d/packages/ws-a/package.json"
  cat > "$d/patches/ms@2.1.2.patch" <<'PATCH'
diff --git a/index.js b/index.js
index 7229750..b8dbf2b 100644
--- a/index.js
+++ b/index.js
@@ -1,3 +1,4 @@
+// patched by the RigorFoundry pnpm fixture
 /**
  * Helpers.
  */
PATCH
  node_dir=""
  case "$ver" in 11.*|12.*) node_dir="$N22" ;; esac
  if [ -n "$node_dir" ]; then P="$node_dir:$PATH"; else P="$PATH"; fi
  # A fresh store and cache per release: pnpm writes some integrity fields only for tarballs it downloads.
  (cd "$d" && PATH="$P" npx -y "pnpm@$ver" install --no-frozen-lockfile --ignore-scripts \
    --store-dir "$R/store-$ver" --cache-dir "$R/cache-$ver" > "$R/pnpm-$ver.log" 2>&1) || { tail -30 "$R/pnpm-$ver.log"; exit 1; }
  (cd "$d" && printf 'pnpm %s\nnode %s\nsha256 %s\n' "$(PATH="$P" npx -y "pnpm@$ver" --version)" "$(PATH="$P" node --version)" "$(sha256sum pnpm-lock.yaml | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $ver"; cat "$d/GENERATED_BY.txt"
done
# The two-document form: pnpm 11 and later write an env lockfile document first when the project pins its package
# manager or declares configDependencies (pnpm-workspace.yaml), then the main lockfile document.
for ver in 11.29.0 12.23.0; do
  d="$R/pnpm-$ver-env"; mkdir -p "$d"
  cat > "$d/package.json" <<PKG
{
  "name": "rigor-lockfile-fixture-pnpm-env",
  "version": "1.0.0",
  "private": true,
  "packageManager": "pnpm@$ver",
  "dependencies": {
    "debug": "4.3.4"
  }
}
PKG
  printf 'configDependencies:\n  ms: 2.1.3\n' > "$d/pnpm-workspace.yaml"
  (cd "$d" && PATH="$N22:$PATH" npx -y "pnpm@$ver" install --no-frozen-lockfile --ignore-scripts \
    --store-dir "$R/store-$ver-env" --cache-dir "$R/cache-$ver-env" > "$R/pnpm-$ver-env.log" 2>&1) || { tail -30 "$R/pnpm-$ver-env.log"; exit 1; }
  (cd "$d" && printf 'pnpm %s\nnode %s\nsha256 %s\n' "$(PATH="$N22:$PATH" npx -y "pnpm@$ver" --version)" "$(PATH="$N22:$PATH" node --version)" "$(sha256sum pnpm-lock.yaml | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $ver env"; cat "$d/GENERATED_BY.txt"
done
# A single project with no workspace: pnpm 8 writes its dependencies at the top level of a 6.0 lockfile.
for ver in 8.15.9 9.15.9; do
  d="$R/pnpm-$ver-single"; mkdir -p "$d/linked-lib"
  printf '{\n  "name": "rigor-lockfile-fixture-pnpm-single",\n  "version": "1.0.0",\n  "private": true,\n  "dependencies": {\n    "debug": "4.3.4",\n    "linked-lib": "link:./linked-lib"\n  }\n}\n' > "$d/package.json"
  printf '{\n  "name": "linked-lib",\n  "version": "1.0.0"\n}\n' > "$d/linked-lib/package.json"
  (cd "$d" && npx -y "pnpm@$ver" install --no-frozen-lockfile --ignore-scripts \
    --store-dir "$R/store-$ver-single" --cache-dir "$R/cache-$ver-single" > "$R/pnpm-$ver-single.log" 2>&1) || { tail -30 "$R/pnpm-$ver-single.log"; exit 1; }
  (cd "$d" && printf 'pnpm %s\nnode %s\nsha256 %s\n' "$(npx -y "pnpm@$ver" --version)" "$(node --version)" "$(sha256sum pnpm-lock.yaml | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $ver single"; cat "$d/GENERATED_BY.txt"
done
