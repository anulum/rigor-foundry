#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — regenerate the clean Yarn 1 lockfile fixture with a pinned Yarn release
# Usage: generate-yarn1.sh EMPTY_OUTPUT_DIRECTORY (needs node, npx, git and network access to the npm registry).
# The repository stores yarn.lock and package.json gzip-compressed (Python gzip, level 9, mtime 0);
# GENERATED_BY.txt records the SHA-256 of the uncompressed lockfile.
set -euo pipefail
R="${1:?usage: gen-yarn1.sh EMPTY_OUTPUT_DIRECTORY}"
mkdir -p "$R"
if [ -n "$(ls -A "$R")" ]; then echo "refusing: $R is not empty" >&2; exit 2; fi
cd "$R"
export npm_config_cache="$R/npm-cache" YARN_CACHE_FOLDER="$R/yarn-cache" npm_config_update_notifier=false
mkdir -p project/local-lib project/linked-lib
# A Git dependency that Yarn 1 clones through Git, so it is written "git+file:///…#<sha>". The bare repository sits at
# a fixed neutral path, so the generated lockfile names no host-specific directory.
V=/tmp/rigor-yarn1-fixture
rm -rf "${V:?}"; mkdir -p "$V/work"
git -C "$V/work" init -q -b main
printf '{\n  "name": "vcs-lib",\n  "version": "1.0.0"\n}\n' > "$V/work/package.json"
git -C "$V/work" add package.json
GIT_AUTHOR_DATE=2026-11-25T00:00:00Z GIT_COMMITTER_DATE=2026-11-25T00:00:00Z git -C "$V/work" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m fixture
git clone -q --bare "$V/work" "$V/vcs-lib.git"
SHA=$(git -C "$V/vcs-lib.git" rev-parse HEAD)
cat > project/package.json <<'PKG'
{
  "name": "rigor-lockfile-fixture-yarn1",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "bundle-dependencies": "1.0.2",
    "debug": "4.3.4",
    "is-number": "github:jonschlinkert/is-number#98e8ff1da1a89f93d1397a24d7413ed15421c139",
    "local-lib": "file:./local-lib",
    "linked-lib": "link:./linked-lib",
    "vcs-lib": "git+file:///tmp/rigor-yarn1-fixture/vcs-lib.git#VCS_SHA"
  }
}
PKG
sed -i "s/VCS_SHA/$SHA/" project/package.json
printf '{\n  "name": "local-lib",\n  "version": "1.0.0"\n}\n' > project/local-lib/package.json
printf '{\n  "name": "linked-lib",\n  "version": "1.0.0"\n}\n' > project/linked-lib/package.json
(cd project && npx -y yarn@1.22.22 install --ignore-scripts --non-interactive --no-progress > "$R/yarn.log" 2>&1)
(cd project && printf 'yarn %s\nnode %s\nsha256 %s\n' "$(npx -y yarn@1.22.22 --version)" "$(node --version)" "$(sha256sum yarn.lock | cut -c1-64)" > GENERATED_BY.txt)
cat project/GENERATED_BY.txt
