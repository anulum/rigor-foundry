#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — regenerate the clean Pipfile.lock fixtures with pinned Pipenv releases
# Usage: generate-pipenv.sh EMPTY_OUTPUT_DIRECTORY PIPENV_TOOLS_DIRECTORY (that directory holds pipenv-<version>/venv
# for each pinned release, whose Pipenv wheel matched the sha256 PyPI publishes; needs git, uv, network access to
# pypi.org and files.pythonhosted.org, and the loopback ports 19441 and 19442). One Pipfile holds every source form the
# rules read: a PyPI package, a package from a declared loopback index that serves PyPI's own wheel, a Git package from
# a loopback Git daemon, an editable directory, a local wheel and a URL, plus a development package and, from Pipenv
# 2022 on, a package in a custom category. Each release locks it with its own cache and
# virtualenv directories. The repository stores each distinct Pipfile.lock with its Pipfile as pipenv-<release>
# (2023.12.1 writes the same bytes as 2024.4.1, which is stored),
# gzip-compressed (Python gzip, level 9, mtime 0); GENERATED_BY.txt records the SHA-256 of the uncompressed lockfile.
set -euo pipefail
R="${1:?usage: generate-pipenv.sh EMPTY_OUTPUT_DIRECTORY PIPENV_TOOLS_DIRECTORY}"
T="${2:?usage: generate-pipenv.sh EMPTY_OUTPUT_DIRECTORY PIPENV_TOOLS_DIRECTORY}"
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
printf '<!DOCTYPE html>\n<html><body>\n<a href="../../files/idna-3.4-py3-none-any.whl#sha256=%s">%s</a>\n</body></html>\n' \
  "$IDNA_SHA" idna-3.4-py3-none-any.whl > index/simple/idna/index.html
printf '<!DOCTYPE html>\n<html><body>\n<a href="idna/">idna</a>\n</body></html>\n' > index/simple/index.html
fetch toml 0.10.2 toml-0.10.2-py2.py3-none-any.whl wheels > /dev/null
ATTRS_URL=$(fetch attrs 22.1.0 attrs-22.1.0-py2.py3-none-any.whl wheels)

# A Git package served by a loopback daemon, built by its setup.py as every pip release can.
mkdir -p git-src/gitlib/gitlib
printf 'from setuptools import setup\n\nsetup(name="gitlib", version="0.1.0", packages=["gitlib"])\n' \
  > git-src/gitlib/setup.py
printf '' > git-src/gitlib/gitlib/__init__.py
git -C git-src/gitlib init -q -b main
git -C git-src/gitlib add -A
git -C git-src/gitlib commit -q -m fixture
git clone -q --bare git-src/gitlib git/gitlib.git
touch git/gitlib.git/git-daemon-export-ok
git daemon --reuseaddr --base-path="$R/git" --listen=127.0.0.1 --port=19442 --export-all "$R/git" &
DAEMON=$!
python3 -I -m http.server 19441 --bind 127.0.0.1 --directory "$R/index" > "$R/index.log" 2>&1 &
SERVER=$!
trap 'kill "$DAEMON" "$SERVER" 2>/dev/null || true' EXIT
sleep 2

while read -r release python; do
  d="$R/pipenv-$release"; mkdir -p "$d/localpkg/localpkg" "$d/vendor"
  cp wheels/toml-0.10.2-py2.py3-none-any.whl "$d/vendor/"
  printf 'from setuptools import setup\n\nsetup(name="localpkg", version="0.1.0", packages=["localpkg"])\n' \
    > "$d/localpkg/setup.py"
  printf '' > "$d/localpkg/localpkg/__init__.py"
  cat > "$d/Pipfile" <<TOML
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[[source]]
url = "http://127.0.0.1:19441/simple"
verify_ssl = false
name = "loop"

[packages]
six = "==1.16.0"
idna = {version = "==3.4", index = "loop"}
gitlib = {git = "git://127.0.0.1:19442/gitlib.git", ref = "main"}
localpkg = {path = "./localpkg", editable = true}
toml = {file = "vendor/toml-0.10.2-py2.py3-none-any.whl"}
attrs = {file = "$ATTRS_URL"}

[dev-packages]
six = "==1.16.0"

[requires]
python_version = "$python"
TOML
  # Package categories beyond default and develop arrived in Pipenv 2022.10; the older release has none.
  if [ "$release" != 2020.11.15 ]; then
    printf '\n[docs]\nidna = {version = "==3.4", index = "loop"}\n' >> "$d/Pipfile"
  fi
  interpreter=$(uv python find "$python" < /dev/null)
  s="$R/state-$release"
  # A fresh cache and virtualenv directory per release, so no release reads another's state.
  (cd "$d" && PIPENV_CACHE_DIR="$s/cache" PIP_CACHE_DIR="$s/pip-cache" WORKON_HOME="$s/venvs" \
    XDG_CACHE_HOME="$s/xdg" PIPENV_VENV_IN_PROJECT=0 PIPENV_IGNORE_VIRTUALENVS=1 PIPENV_YES=1 \
    PIPENV_NOSPIN=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    "$T/pipenv-$release/venv/bin/pipenv" lock --python "$interpreter" < /dev/null > "$R/pipenv-$release.log" 2>&1) \
    || { tail -30 "$R/pipenv-$release.log"; exit 1; }
  (cd "$d" && printf '%s\nsha256 %s\n' "$("$T/pipenv-$release/venv/bin/pipenv" --version < /dev/null)" \
    "$(sha256sum Pipfile.lock | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $release"; cat "$d/GENERATED_BY.txt"
done <<'LIST'
2020.11.15 3.9
2022.12.19 3.11
2023.12.1 3.12
2024.4.1 3.12
2025.0.4 3.13
2026.12.1 3.13
LIST
