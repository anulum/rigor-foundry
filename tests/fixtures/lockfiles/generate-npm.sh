#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — regenerate the clean npm lockfile fixtures with pinned npm versions
# Usage: generate-npm.sh EMPTY_OUTPUT_DIRECTORY (needs node, npx and network access to the npm registry).
# The repository stores each package-lock.json and package.json gzip-compressed (Python gzip,
# level 9, mtime 0); GENERATED_BY.txt records the SHA-256 of the uncompressed lockfile.
set -euo pipefail
R="${1:?usage: generate-npm.sh EMPTY_OUTPUT_DIRECTORY}"
mkdir -p "$R"
if [ -n "$(ls -A "$R")" ]; then echo "refusing: $R is not empty" >&2; exit 2; fi
cd "$R"
export npm_config_cache="$R/cache" npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false
for spec in 6.14.18:v1 8.19.4:v2 10.9.2:v3; do
  ver=${spec%%:*}; tag=${spec##*:}
  d="$R/$tag"; mkdir -p "$d/local-lib"
  cat > "$d/package.json" <<'PKG'
{
  "name": "rigor-lockfile-fixture-npm",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "bundle-dependencies": "1.0.2",
    "debug": "4.3.4",
    "is-number": "github:jonschlinkert/is-number#98e8ff1da1a89f93d1397a24d7413ed15421c139",
    "local-lib": "file:./local-lib"
  }
}
PKG
  printf '{\n  "name": "local-lib",\n  "version": "1.0.0"\n}\n' > "$d/local-lib/package.json"
  (cd "$d" && npx -y "npm@$ver" install --package-lock-only --ignore-scripts --no-audit --no-fund > "$R/$tag.log" 2>&1)
  (cd "$d" && printf 'npm %s\nnode %s\nlockfileVersion %s\nsha256 %s\n' "$(npx -y "npm@$ver" --version)" "$(node --version)" \
     "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["lockfileVersion"])' package-lock.json)" \
     "$(sha256sum package-lock.json | cut -c1-64)" > GENERATED_BY.txt)
  echo "$tag: $(tr '\n' ' ' < "$d/GENERATED_BY.txt")"
done
