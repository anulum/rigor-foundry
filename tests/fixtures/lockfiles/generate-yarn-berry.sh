#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — regenerate the clean Yarn 2+ lockfile fixtures with pinned Yarn releases
# Usage: generate-yarn-berry.sh EMPTY_OUTPUT_DIRECTORY (needs node, npx, git and network access to the npm registry
# and GitHub). The repository stores yarn.lock, package.json and .yarnrc.yml gzip-compressed (Python gzip, level 9,
# mtime 0); GENERATED_BY.txt records the SHA-256 of the uncompressed lockfile.
set -euo pipefail
R="${1:?usage: gen-yarn-berry.sh EMPTY_OUTPUT_DIRECTORY}"
mkdir -p "$R"
if [ -n "$(ls -A "$R")" ]; then echo "refusing: $R is not empty" >&2; exit 2; fi
cd "$R"
export npm_config_cache="$R/npm-cache" npm_config_update_notifier=false YARN_ENABLE_TELEMETRY=0 YARN_ENABLE_GLOBAL_CACHE=0
V=/tmp/rigor-yarn-berry-fixture
rm -rf "${V:?}"; mkdir -p "$V/work"
git -C "$V/work" init -q -b main
printf '{\n  "name": "vcs-lib",\n  "version": "1.0.0"\n}\n' > "$V/work/package.json"
git -C "$V/work" add package.json
GIT_AUTHOR_DATE=2026-11-25T00:00:00Z GIT_COMMITTER_DATE=2026-11-25T00:00:00Z git -C "$V/work" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m fixture
git clone -q --bare "$V/work" "$V/vcs-lib.git"
SHA=$(git -C "$V/vcs-lib.git" rev-parse HEAD)
# Serve the bare repository on loopback so Yarn clones it through Git (git://), the form B7 pins by commit.
git daemon --base-path="$V" --export-all --reuseaddr --listen=127.0.0.1 --port=19418 "$V" > "$R/git-daemon.log" 2>&1 &
DAEMON=$!
trap 'kill "$DAEMON" 2>/dev/null || true' EXIT
sleep 1
for ver in 3.8.7 4.19.0; do
  d="$R/yarn-$ver"; mkdir -p "$d/local-lib" "$d/linked-lib" "$d/portal-lib" "$d/packages/ws-a"
  cat > "$d/package.json" <<PKG
{
  "name": "rigor-lockfile-fixture-yarn-berry",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "debug": "4.3.4",
    "resolve": "1.22.8",
    "is-number": "github:jonschlinkert/is-number#98e8ff1da1a89f93d1397a24d7413ed15421c139",
    "vcs-lib": "git://127.0.0.1:19418/vcs-lib.git#$SHA",
    "local-lib": "file:./local-lib",
    "linked-lib": "link:./linked-lib",
    "portal-lib": "portal:./portal-lib",
    "ws-a": "workspace:*"
  }
}
PKG
  for lib in local-lib linked-lib portal-lib; do printf '{\n  "name": "%s",\n  "version": "1.0.0"\n}\n' "$lib" > "$d/$lib/package.json"; done
  printf '{\n  "name": "ws-a",\n  "version": "1.0.0"\n}\n' > "$d/packages/ws-a/package.json"
  printf 'enableTelemetry: false\nenableGlobalCache: false\nnodeLinker: node-modules\n' > "$d/.yarnrc.yml"
  # Yarn 4.x only fetches Git repositories that approvedGitRepositories names; Yarn 3 rejects the unknown key.
  case "$ver" in
    4.*) printf 'approvedGitRepositories:\n  - "https://github.com/jonschlinkert/is-number.git"\n  - "git://127.0.0.1:19418/vcs-lib.git"\n' >> "$d/.yarnrc.yml" ;;
  esac
  (cd "$d" && touch yarn.lock && npx -y -p "@yarnpkg/cli-dist@$ver" yarn install > "$R/yarn-$ver.log" 2>&1) || { tail -20 "$R/yarn-$ver.log"; exit 1; }
  (cd "$d" && printf 'yarn %s\nnode %s\nsha256 %s\n' "$(npx -y -p "@yarnpkg/cli-dist@$ver" yarn --version)" "$(node --version)" "$(sha256sum yarn.lock | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $ver"; cat "$d/GENERATED_BY.txt"
done
