#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — regenerate the manifest-drift fixtures with pinned Poetry and Pipenv releases
# Usage: generate-manifest-drift.sh EMPTY_OUTPUT_DIRECTORY POETRY_TOOLS_DIRECTORY PIPENV_TOOLS_DIRECTORY (each tools
# directory holds <tool>-<version>/venv for its pinned releases; needs uv and network access to pypi.org). Each case is a
# manifest locked by a pinned release and, for a drift case, a copy edited without relocking; the tool's own freshness
# check (`poetry check --lock`, `pipenv verify`) is recorded beside each as verdict.txt with its exit status.
set -euo pipefail
R="${1:?usage: generate-manifest-drift.sh EMPTY_OUTPUT_DIRECTORY POETRY_TOOLS PIPENV_TOOLS}"
PT="${2:?usage: generate-manifest-drift.sh EMPTY_OUTPUT_DIRECTORY POETRY_TOOLS PIPENV_TOOLS}"
VT="${3:?usage: generate-manifest-drift.sh EMPTY_OUTPUT_DIRECTORY POETRY_TOOLS PIPENV_TOOLS}"
mkdir -p "$R"
if [ -n "$(ls -A "$R")" ]; then echo "refusing: $R is not empty" >&2; exit 2; fi
cd "$R"
PYTHON=$(uv python find 3.13 < /dev/null)

# One pinned Poetry release in one directory, with its own cache, configuration and data.
poetry_run() {
  local release=$1 dir=$2
  shift 2
  (cd "$dir" && POETRY_CACHE_DIR="$R/state-poetry-$release/cache" POETRY_CONFIG_DIR="$R/state-poetry-$release/config" \
    POETRY_DATA_DIR="$R/state-poetry-$release/data" POETRY_VIRTUALENVS_PATH="$R/state-poetry-$release/venvs" \
    POETRY_NO_INTERACTION=1 "$PT/poetry-$release/venv/bin/poetry" "$@" < /dev/null)
}

# One pinned Pipenv release in one directory, with its own caches and virtualenv directory. PIPENV_VENV_IN_PROJECT is
# left unset: 2020.11.15 reads any value, "0" included, as true and would put the virtualenv in the case directory.
pipenv_run() {
  local release=$1 dir=$2
  shift 2
  local s="$R/state-pipenv-$release"
  (cd "$dir" && env -u PIPENV_VENV_IN_PROJECT PIPENV_CACHE_DIR="$s/cache" PIP_CACHE_DIR="$s/pip-cache" \
    WORKON_HOME="$s/venvs" XDG_CACHE_HOME="$s/xdg" PIPENV_IGNORE_VIRTUALENVS=1 PIPENV_YES=1 PIPENV_NOSPIN=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 "$VT/pipenv-$release/venv/bin/pipenv" "$@" < /dev/null)
}

# The tool's own verdict on one directory: which release ran which check, its exit status, and its output.
verdict() {
  local dir=$1 tool=$2 release=$3
  shift 3
  local status=0 output
  output=$("${tool}_run" "$release" "$dir" "$@" 2>&1) || status=$?
  printf '%s %s %s\nexit status: %s\n%s\n' "$tool" "$release" "$*" "$status" "$output" > "$dir/verdict.txt"
}

# Poetry, tool.poetry form: a fresh lock, and a copy whose pyproject gains a dependency without relocking.
for release in 1.8.5 2.5.2; do
  d="$R/poetry-$release-legacy-fresh"; e="$R/poetry-$release-legacy-drift"; mkdir -p "$d"
  cat > "$d/pyproject.toml" <<'TOML'
[tool.poetry]
name = "rigor-drift-fixture"
version = "1.0.0"
description = "Drift fixture"
authors = ["fixture <fixture@example.invalid>"]
package-mode = false

[tool.poetry.dependencies]
python = ">=3.10,<4.0"
six = "1.16.0"
TOML
  poetry_run "$release" "$d" lock > "$R/poetry-$release-legacy.log" 2>&1
  cp -R "$d" "$e"
  sed -i 's/^six = "1.16.0"$/six = "1.16.0"\nidna = "3.4"/' "$e/pyproject.toml"
  verdict "$d" poetry "$release" check --lock
  verdict "$e" poetry "$release" check --lock
done

# Poetry 2, project form with dependency groups: 2.3.0 added the groups to the content hash.
for release in 2.2.1 2.5.2; do
  d="$R/poetry-$release-project-fresh"; mkdir -p "$d"
  cat > "$d/pyproject.toml" <<'TOML'
[project]
name = "rigor-drift-fixture"
version = "1.0.0"
requires-python = ">=3.10,<4.0"
dependencies = ["six==1.16.0"]

[dependency-groups]
test = ["idna==3.4"]

[tool.poetry]
package-mode = false
TOML
  poetry_run "$release" "$d" lock > "$R/poetry-$release-project.log" 2>&1
done
# 2.5.2's verdict on 2.2.1's lock, which it recomputes in the pre-2.3.0 form for an older writer.
cp -R "$R/poetry-2.2.1-project-fresh" "$R/poetry-2.2.1-project-fresh-checked-by-2.5.2"
# A group changed after a 2.2.1 lock: neither 2.2.1 nor 2.5.2 hashes the groups of a pre-2.3.0 lock.
cp -R "$R/poetry-2.2.1-project-fresh" "$R/poetry-2.2.1-project-group-changed"
sed -i 's/^test = \["idna==3.4"\]$/test = ["idna==3.4", "six==1.16.0"]/' "$R/poetry-2.2.1-project-group-changed/pyproject.toml"
cp -R "$R/poetry-2.2.1-project-group-changed" "$R/poetry-2.2.1-project-group-changed-checked-by-2.5.2"
verdict "$R/poetry-2.2.1-project-fresh" poetry 2.2.1 check --lock
verdict "$R/poetry-2.5.2-project-fresh" poetry 2.5.2 check --lock
verdict "$R/poetry-2.2.1-project-fresh-checked-by-2.5.2" poetry 2.5.2 check --lock
verdict "$R/poetry-2.2.1-project-group-changed" poetry 2.2.1 check --lock
verdict "$R/poetry-2.2.1-project-group-changed-checked-by-2.5.2" poetry 2.5.2 check --lock

# Poetry 2.5.2, project form without groups, then a [dependency-groups] table added without relocking: the hash
# without groups still matches, and 2.5.2 reports drift because the lock names a writer from 2.3.0 on.
d="$R/poetry-2.5.2-project-nogroups-fresh"; e="$R/poetry-2.5.2-project-groups-added"; mkdir -p "$d"
cat > "$d/pyproject.toml" <<'TOML'
[project]
name = "rigor-drift-fixture"
version = "1.0.0"
requires-python = ">=3.10,<4.0"
dependencies = ["six==1.16.0"]

[tool.poetry]
package-mode = false
TOML
poetry_run 2.5.2 "$d" lock > "$R/poetry-2.5.2-project-nogroups.log" 2>&1
cp -R "$d" "$e"
printf '\n[dependency-groups]\ntest = ["idna==3.4"]\n' >> "$e/pyproject.toml"
verdict "$d" poetry 2.5.2 check --lock
verdict "$e" poetry 2.5.2 check --lock

# Poetry 1.8.5 locks a manifest with a [project] table, which it does not read; 2.5.2 hashes that table.
d="$R/poetry-1.8.5-with-project-table"; mkdir -p "$d"
cat > "$d/pyproject.toml" <<'TOML'
[project]
name = "rigor-drift-fixture"
version = "1.0.0"
requires-python = ">=3.10,<4.0"
dependencies = ["idna==3.4"]

[tool.poetry]
name = "rigor-drift-fixture"
version = "1.0.0"
description = "Drift fixture"
authors = ["fixture <fixture@example.invalid>"]
package-mode = false

[tool.poetry.dependencies]
python = ">=3.10,<4.0"
six = "1.16.0"
TOML
poetry_run 1.8.5 "$d" lock > "$R/poetry-1.8.5-with-project-table.log" 2>&1
cp -R "$d" "$R/poetry-1.8.5-with-project-table-checked-by-2.5.2"
verdict "$d" poetry 1.8.5 check --lock
verdict "$R/poetry-1.8.5-with-project-table-checked-by-2.5.2" poetry 2.5.2 check --lock

# Pipenv: a non-canonical package name, which 2026.12.1 canonicalises before hashing and 2025.0.4 does not.
for release in 2025.0.4 2026.12.1; do
  d="$R/pipenv-$release-fresh"; e="$R/pipenv-$release-drift"; mkdir -p "$d"
  cat > "$d/Pipfile" <<'TOML'
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
Six = "==1.16.0"

[requires]
python_version = "3.13"
TOML
  pipenv_run "$release" "$d" lock --python "$PYTHON" > "$R/pipenv-$release.log" 2>&1
  cp -R "$d" "$e"
  sed -i 's/^Six = "==1.16.0"$/Six = "==1.16.0"\nidna = "==3.4"/' "$e/Pipfile"
done
# Each release's verdict on its own locks, and on the other's fresh lock.
cp -R "$R/pipenv-2025.0.4-fresh" "$R/pipenv-2025.0.4-fresh-checked-by-2026.12.1"
cp -R "$R/pipenv-2026.12.1-fresh" "$R/pipenv-2026.12.1-fresh-checked-by-2025.0.4"
for release in 2025.0.4 2026.12.1; do
  verdict "$R/pipenv-$release-fresh" pipenv "$release" verify
  verdict "$R/pipenv-$release-drift" pipenv "$release" verify
done
verdict "$R/pipenv-2025.0.4-fresh-checked-by-2026.12.1" pipenv 2026.12.1 verify
verdict "$R/pipenv-2026.12.1-fresh-checked-by-2025.0.4" pipenv 2025.0.4 verify

# A Pipfile without [[source]]: each release hashes the default PyPI source it inserts. 2020.11.15 has no
# `verify`; its fresh lock is its own output.
for release in 2020.11.15 2025.0.4 2026.12.1; do
  d="$R/pipenv-$release-no-source"; mkdir -p "$d"
  cat > "$d/Pipfile" <<'TOML'
[packages]
six = "==1.16.0"
TOML
  case "$release" in
    2020.11.15) interpreter=$(uv python find 3.9 < /dev/null) ;;
    *) interpreter="$PYTHON" ;;
  esac
  pipenv_run "$release" "$d" lock --python "$interpreter" > "$R/pipenv-$release-no-source.log" 2>&1
done
verdict "$R/pipenv-2025.0.4-no-source" pipenv 2025.0.4 verify
verdict "$R/pipenv-2026.12.1-no-source" pipenv 2026.12.1 verify
for f in "$R"/*/verdict.txt; do echo "== ${f#"$R"/}"; head -2 "$f"; done
# A TOML date in a hashed key: each tool's own verdict on its own fresh lock, with the date added afterwards.
d="$R/poetry-2.5.2-toml-date"; cp -R "$R/poetry-2.5.2-legacy-fresh" "$d"; rm -f -- "$d/verdict.txt"
printf '\n[[tool.poetry.source]]\nname = "dated"\nurl = "https://example.invalid/simple"\npriority = "explicit"\nadded = 2024-01-01\n' \
  >> "$d/pyproject.toml"
verdict "$d" poetry 2.5.2 check --lock
d="$R/poetry-1.8.5-toml-date"; cp -R "$R/poetry-1.8.5-legacy-fresh" "$d"; rm -f -- "$d/verdict.txt"
printf '\n[[tool.poetry.source]]\nname = "dated"\nurl = "https://example.invalid/simple"\npriority = "explicit"\nadded = 2024-01-01\n' \
  >> "$d/pyproject.toml"
verdict "$d" poetry 1.8.5 check --lock
for release in 2025.0.4 2026.12.1; do
  d="$R/pipenv-$release-toml-date"; cp -R "$R/pipenv-$release-fresh" "$d"; rm -f -- "$d/verdict.txt"
  sed -i 's/^python_version = "3.13"$/python_version = "3.13"\nchecked = 2024-01-01/' "$d/Pipfile"
  verdict "$d" pipenv "$release" verify
done

# Poetry writer headers edited on 2.2.1's real project lock: a pre-release before 2.3.0, and a release newer than any
# mirrored here. Poetry 2.5.2's own verdict on each is recorded.
for header in 2.3.0b1 9.0.0; do
  d="$R/poetry-2.2.1-project-header-$header"; cp -R "$R/poetry-2.2.1-project-fresh" "$d"; rm -f -- "$d/verdict.txt"
  sed -i "1s/Poetry 2.2.1 and/Poetry $header and/" "$d/poetry.lock"
  verdict "$d" poetry 2.5.2 check --lock
done

# A Pipfile source URL through an environment variable, locked and verified with the variable set.
for release in 2025.0.4 2026.12.1; do
  d="$R/pipenv-$release-env-source"; mkdir -p "$d"
  cat > "$d/Pipfile" <<'TOML'
[[source]]
url = "https://${RIGOR_INDEX_HOST}/simple"
verify_ssl = true
name = "pypi"

[packages]
six = "==1.16.0"

[requires]
python_version = "3.13"
TOML
  RIGOR_INDEX_HOST=pypi.org pipenv_run "$release" "$d" lock --python "$PYTHON" > "$R/pipenv-$release-env-source.log" 2>&1
  RIGOR_INDEX_HOST=pypi.org verdict "$d" pipenv "$release" verify
done

# Package names that differ from their PEP 503 form only by separators, locked by each current Pipenv release.
for release in 2025.0.4 2026.12.1; do
  d="$R/pipenv-$release-separator-names"; mkdir -p "$d"
  cat > "$d/Pipfile" <<'TOML'
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
typing_extensions = "==4.12.2"
"backports.tarfile" = "==1.2.0"

[requires]
python_version = "3.13"
TOML
  pipenv_run "$release" "$d" lock --python "$PYTHON" > "$R/pipenv-$release-separator-names.log" 2>&1
  verdict "$d" pipenv "$release" verify
done

# Poetry 2.5.2 with an empty [project] dependencies list, and with an empty optional-dependencies table.
d="$R/poetry-2.5.2-project-empty-dependencies"; mkdir -p "$d"
cat > "$d/pyproject.toml" <<'TOML'
[project]
name = "rigor-drift-fixture"
version = "1.0.0"
requires-python = ">=3.10,<4.0"
dependencies = []

[tool.poetry]
package-mode = false
TOML
poetry_run 2.5.2 "$d" lock > "$R/poetry-2.5.2-project-empty-dependencies.log" 2>&1
verdict "$d" poetry 2.5.2 check --lock
d="$R/poetry-2.5.2-project-empty-optional"; mkdir -p "$d"
cat > "$d/pyproject.toml" <<'TOML'
[project]
name = "rigor-drift-fixture"
version = "1.0.0"
requires-python = ">=3.10,<4.0"
dependencies = ["six==1.16.0"]

[project.optional-dependencies]

[tool.poetry]
package-mode = false
TOML
poetry_run 2.5.2 "$d" lock > "$R/poetry-2.5.2-project-empty-optional.log" 2>&1
verdict "$d" poetry 2.5.2 check --lock

# Every case directory holds only its manifest, its lockfile and its verdict.
stray=$(find "$R" -mindepth 2 -maxdepth 2 ! -path "$R/state-*" ! -name pyproject.toml ! -name poetry.lock ! -name Pipfile \
  ! -name Pipfile.lock ! -name verdict.txt)
if [ -n "$stray" ]; then echo "stray files in case directories:" >&2; echo "$stray" >&2; exit 3; fi
