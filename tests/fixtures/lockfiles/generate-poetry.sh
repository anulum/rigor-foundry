#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — regenerate the clean poetry.lock fixtures with pinned Poetry releases
# Usage: generate-poetry.sh EMPTY_OUTPUT_DIRECTORY POETRY_TOOLS_DIRECTORY (that directory holds poetry-<version>/venv
# for each pinned release, whose Poetry wheel matched the sha256 PyPI publishes; needs git, network access to pypi.org
# and files.pythonhosted.org, and the loopback ports 19431 and 19432). One project holds every source form the rules
# read: a PyPI package, a package from a declared loopback index that serves PyPI's own wheel, a Git package from a
# loopback Git daemon, a directory, a local wheel and a URL. Each release locks it with its own cache, configuration
# and data directories. The repository stores each release's poetry.lock and pyproject.toml as
# poetry-<release>-lock-<lock-version>, gzip-compressed (Python gzip, level 9, mtime 0); GENERATED_BY.txt records the
# SHA-256 of the uncompressed lockfile.
set -euo pipefail
R="${1:?usage: generate-poetry.sh EMPTY_OUTPUT_DIRECTORY POETRY_TOOLS_DIRECTORY}"
T="${2:?usage: generate-poetry.sh EMPTY_OUTPUT_DIRECTORY POETRY_TOOLS_DIRECTORY}"
mkdir -p "$R"
if [ -n "$(ls -A "$R")" ]; then echo "refusing: $R is not empty" >&2; exit 2; fi
cd "$R"
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid GIT_COMMITTER_NAME=fixture
export GIT_COMMITTER_EMAIL=fixture@example.invalid GIT_AUTHOR_DATE=2026-11-25T00:00:00Z
export GIT_COMMITTER_DATE=2026-11-25T00:00:00Z

# PyPI's own wheels, each checked against the sha256 PyPI publishes for it.
fetch() {
  local name=$1 version=$2 filename=$3 out=$4 meta url digest
  meta=$(curl -sS "https://pypi.org/pypi/$name/$version/json")
  read -r url digest < <(python3 -I -c "
import json, sys
[f] = [f for f in json.loads(sys.argv[1])['urls'] if f['filename'] == sys.argv[2]]
print(f['url'], f['digests']['sha256'])" "$meta" "$filename")
  curl -sS -L -o "$out/$filename" "$url"
  printf '%s  %s\n' "$digest" "$out/$filename" | sha256sum --check --strict >&2
  echo "$url"
}
mkdir -p index/files index/simple/idna wheels
fetch idna 3.4 idna-3.4-py3-none-any.whl index/files > /dev/null
IDNA_SHA=$(sha256sum index/files/idna-3.4-py3-none-any.whl | cut -c1-64)
printf '<!DOCTYPE html>\n<html><body>\n<a href="../../files/idna-3.4-py3-none-any.whl#sha256=%s">idna-3.4-py3-none-any.whl</a>\n</body></html>\n' "$IDNA_SHA" > index/simple/idna/index.html
printf '<!DOCTYPE html>\n<html><body>\n<a href="idna/">idna</a>\n</body></html>\n' > index/simple/index.html
fetch toml 0.10.2 toml-0.10.2-py2.py3-none-any.whl wheels > /dev/null
ATTRS_URL=$(fetch attrs 22.1.0 attrs-22.1.0-py2.py3-none-any.whl wheels)

# A Git package served by a loopback daemon.
mkdir -p git-src/gitlib/gitlib
cat > git-src/gitlib/pyproject.toml <<'TOML'
[tool.poetry]
name = "gitlib"
version = "0.1.0"
description = "Git fixture package"
authors = ["fixture <fixture@example.invalid>"]

[tool.poetry.dependencies]
python = ">=3.8"

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
TOML
printf '' > git-src/gitlib/gitlib/__init__.py
git -C git-src/gitlib init -q -b main && git -C git-src/gitlib add -A && git -C git-src/gitlib commit -q -m fixture
git clone -q --bare git-src/gitlib git/gitlib.git
touch git/gitlib.git/git-daemon-export-ok
git daemon --reuseaddr --base-path="$R/git" --listen=127.0.0.1 --port=19432 --export-all "$R/git" &
DAEMON=$!
python3 -I -m http.server 19431 --bind 127.0.0.1 --directory "$R/index" > "$R/index.log" 2>&1 &
SERVER=$!
trap 'kill "$DAEMON" "$SERVER" 2>/dev/null || true' EXIT
sleep 2

for release in 1.2.2 1.3.2 1.8.5 2.0.1 2.5.2; do
  d="$R/poetry-$release"; mkdir -p "$d/localpkg/localpkg" "$d/vendor"
  cp wheels/toml-0.10.2-py2.py3-none-any.whl "$d/vendor/"
  cat > "$d/localpkg/pyproject.toml" <<'TOML'
[tool.poetry]
name = "localpkg"
version = "0.1.0"
description = "Directory fixture package"
authors = ["fixture <fixture@example.invalid>"]

[tool.poetry.dependencies]
python = ">=3.8"

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
TOML
  printf '' > "$d/localpkg/localpkg/__init__.py"
  case "$release" in
    1.2.2|1.3.2) priority='secondary = true' ;;
    *) priority='priority = "explicit"' ;;
  esac
  cat > "$d/pyproject.toml" <<TOML
[tool.poetry]
name = "rigor-lockfile-fixture-poetry"
version = "1.0.0"
description = "Lockfile fixture"
authors = ["fixture <fixture@example.invalid>"]

[tool.poetry.dependencies]
python = ">=3.10,<4.0"
six = "1.16.0"
idna = {version = "3.4", source = "loop"}
gitlib = {git = "git://127.0.0.1:19432/gitlib.git", branch = "main"}
localpkg = {path = "localpkg", develop = true}
toml = {path = "vendor/toml-0.10.2-py2.py3-none-any.whl"}
attrs = {url = "$ATTRS_URL"}

[[tool.poetry.source]]
name = "loop"
url = "http://127.0.0.1:19431/simple/"
$priority

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
TOML
  # A fresh cache, configuration and data directory per release, so no release reads another's state.
  (cd "$d" && POETRY_CACHE_DIR="$R/state-$release/cache" POETRY_CONFIG_DIR="$R/state-$release/config" \
    POETRY_DATA_DIR="$R/state-$release/data" POETRY_VIRTUALENVS_PATH="$R/state-$release/venvs" \
    POETRY_NO_INTERACTION=1 "$T/poetry-$release/venv/bin/poetry" lock > "$R/poetry-$release.log" 2>&1) \
    || { tail -20 "$R/poetry-$release.log"; exit 1; }
  (cd "$d" && printf '%s\nsha256 %s\n' "$("$T/poetry-$release/venv/bin/poetry" --version)" \
    "$(sha256sum poetry.lock | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $release"; cat "$d/GENERATED_BY.txt"
done
