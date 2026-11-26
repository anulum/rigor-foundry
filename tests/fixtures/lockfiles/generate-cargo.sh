#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — regenerate the clean Cargo.lock fixtures with pinned Cargo releases
# Usage: generate-cargo.sh EMPTY_OUTPUT_DIRECTORY RUSTUP_HOME (the rustup home holds the pinned toolchains, installed
# with `rustup toolchain install <version> --profile minimal`; needs git and network access to crates.io). The newest
# Cargo vendors the crates.io sources once, and every release resolves against them through source replacement, which
# keeps crates.io as the source a lockfile records, so the oldest releases need no git index of crates.io. The
# repository stores Cargo.lock and the manifests gzip-compressed (Python gzip, level 9, mtime 0); GENERATED_BY.txt
# records the SHA-256 of the uncompressed lockfile.
set -euo pipefail
R="${1:?usage: generate-cargo.sh EMPTY_OUTPUT_DIRECTORY RUSTUP_HOME}"
RH="${2:?usage: generate-cargo.sh EMPTY_OUTPUT_DIRECTORY RUSTUP_HOME}"
RELEASES="1.40.0 1.47.0 1.75.0 1.83.0 1.100.0"
NEWEST=1.100.0
mkdir -p "$R"
if [ -n "$(ls -A "$R")" ]; then echo "refusing: $R is not empty" >&2; exit 2; fi
cd "$R"
export CARGO_HOME="$R/cargo-home" CARGO_TERM_COLOR=never
bin() { echo "$RH/toolchains/$1-x86_64-unknown-linux-gnu/bin"; }
V=/tmp/rigor-cargo-fixture
rm -rf "${V:?}"; mkdir -p "$V"
SHA=""
for lib in vcs-lib vcs-branch-lib itoa-fork; do
  mkdir -p "$V/$lib/src"
  case "$lib" in
    itoa-fork) printf '[package]\nname = "itoa"\nversion = "0.4.8"\nauthors = ["fixture"]\nedition = "2015"\n' > "$V/$lib/Cargo.toml" ;;
    *) printf '[package]\nname = "%s"\nversion = "1.0.0"\nauthors = ["fixture"]\nedition = "2015"\n' "$lib" > "$V/$lib/Cargo.toml" ;;
  esac
  : > "$V/$lib/src/lib.rs"
  git -C "$V/$lib" init -q -b main
  git -C "$V/$lib" add Cargo.toml src/lib.rs
  GIT_AUTHOR_DATE=2026-11-25T00:00:00Z GIT_COMMITTER_DATE=2026-11-25T00:00:00Z git -C "$V/$lib" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m fixture
  git clone -q --bare "$V/$lib" "$V/$lib.git"
done
SHA=$(git -C "$V/vcs-lib.git" rev-parse HEAD)
FORK=$(git -C "$V/itoa-fork.git" rev-parse HEAD)
# Serve the bare repositories on loopback so Cargo fetches them through Git (git://), the form B7 pins by commit.
git daemon --base-path="$V" --export-all --reuseaddr --listen=127.0.0.1 --port=19420 "$V" > "$R/git-daemon.log" 2>&1 &
DAEMON=$!
HTTP=""
trap 'kill "$DAEMON" $HTTP 2>/dev/null || true' EXIT
sleep 1
REGISTRY_DEPENDENCIES='cfg-if = "=0.1.10"
itoa = "=0.4.8"
either = "=1.5.3"'
# Vendor the crates.io sources once, with the newest Cargo; every release then reads crates.io from that directory,
# and only the loopback Git repositories are fetched.
mkdir -p "$R/vendor-project/src"
printf '[package]\nname = "vendor-project"\nversion = "0.0.0"\nedition = "2018"\n\n[dependencies]\n%s\n' "$REGISTRY_DEPENDENCIES" > "$R/vendor-project/Cargo.toml"
: > "$R/vendor-project/src/lib.rs"
(cd "$R/vendor-project" && PATH="$(bin $NEWEST):$PATH" cargo vendor --versioned-dirs "$R/vendored" > "$R/vendor.log" 2>&1) || { tail -20 "$R/vendor.log"; exit 1; }
for ver in $RELEASES; do
  d="$R/cargo-$ver"; mkdir -p "$d/src" "$d/local-lib/src" "$d/crates/ws-a/src" "$d/.cargo"
  cat > "$d/Cargo.toml" <<TOML
[package]
name = "rigor-lockfile-fixture-cargo"
version = "1.0.0"
authors = ["fixture"]
edition = "2018"

[workspace]
members = ["crates/ws-a"]

[dependencies]
$REGISTRY_DEPENDENCIES
local-lib = { path = "local-lib" }
vcs-lib = { git = "git://127.0.0.1:19420/vcs-lib.git", rev = "$SHA" }
vcs-branch-lib = { git = "git://127.0.0.1:19420/vcs-branch-lib.git", branch = "main" }
ws-a = { path = "crates/ws-a" }
TOML
  printf '[package]\nname = "local-lib"\nversion = "1.0.0"\nauthors = ["fixture"]\nedition = "2018"\n' > "$d/local-lib/Cargo.toml"
  printf '[package]\nname = "ws-a"\nversion = "1.0.0"\nauthors = ["fixture"]\nedition = "2018"\n\n[dependencies]\nitoa = "=0.4.8"\n' > "$d/crates/ws-a/Cargo.toml"
  : > "$d/src/lib.rs"; : > "$d/local-lib/src/lib.rs"; : > "$d/crates/ws-a/src/lib.rs"
  # The oldest releases read .cargo/config; the newer ones read it too.
  printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "%s"\n' "$R/vendored" > "$d/.cargo/config"
  (cd "$d" && PATH="$(bin "$ver"):$PATH" cargo generate-lockfile > "$R/cargo-$ver.log" 2>&1) || { tail -20 "$R/cargo-$ver.log"; exit 1; }
  (cd "$d" && printf '%s\nsha256 %s\n' "$(PATH="$(bin "$ver"):$PATH" cargo --version)" "$(sha256sum Cargo.lock | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $ver"; cat "$d/GENERATED_BY.txt"
done
# A real sparse alternate registry on loopback, for the releases that read sparse indexes: the crate and its index line
# are crates.io's own, checked against each other before they are served. The project also patches a crate that
# nothing uses, which Cargo lists under [[patch.unused]] (Cargo refuses [patch] beside [replace]).
S="$R/sparse-registry"; mkdir -p "$S/index/it/oa" "$S/crates/itoa/0.4.8"
curl -sSf --max-time 120 -o "$S/crates/itoa/0.4.8/download" https://static.crates.io/crates/itoa/itoa-0.4.8.crate
LINE=$(curl -sSf --max-time 120 https://index.crates.io/it/oa/itoa | grep '"vers":"0.4.8"')
CKSUM=$(printf '%s' "$LINE" | python3 -c 'import json, sys; print(json.load(sys.stdin)["cksum"])')
test "$(sha256sum "$S/crates/itoa/0.4.8/download" | cut -c1-64)" = "$CKSUM"
printf '%s\n' "$LINE" > "$S/index/it/oa/itoa"
printf '{\n  "dl": "http://127.0.0.1:19421/crates"\n}\n' > "$S/index/config.json"
python3 -m http.server 19421 --bind 127.0.0.1 --directory "$S" > "$R/sparse-http.log" 2>&1 &
HTTP=$!
sleep 1
for ver in 1.83.0 1.100.0; do
  d="$R/cargo-$ver-sparse"; mkdir -p "$d/src" "$d/either-patch/src" "$d/.cargo"
  printf '[package]\nname = "rigor-lockfile-fixture-cargo-sparse"\nversion = "1.0.0"\nedition = "2018"\n\n[dependencies]\nitoa = "=0.4.8"\nitoa-alt = { package = "itoa", version = "=0.4.8", registry = "local-sparse" }\n\n[patch.crates-io]\neither = { path = "either-patch" }\n' > "$d/Cargo.toml"
  printf '[package]\nname = "either"\nversion = "9.9.9"\nedition = "2015"\n' > "$d/either-patch/Cargo.toml"
  : > "$d/src/lib.rs"; : > "$d/either-patch/src/lib.rs"
  printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "%s"\n\n[registries.local-sparse]\nindex = "sparse+http://127.0.0.1:19421/index/"\n' "$R/vendored" > "$d/.cargo/config.toml"
  (cd "$d" && PATH="$(bin "$ver"):$PATH" cargo generate-lockfile > "$R/cargo-$ver-sparse.log" 2>&1) || { tail -20 "$R/cargo-$ver-sparse.log"; exit 1; }
  (cd "$d" && printf '%s\nsha256 %s\n' "$(PATH="$(bin "$ver"):$PATH" cargo --version)" "$(sha256sum Cargo.lock | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $ver sparse"; cat "$d/GENERATED_BY.txt"
done
# The old [replace] table: the registry package names its Git replacement.
for ver in 1.40.0 1.100.0; do
  d="$R/cargo-$ver-replace"; mkdir -p "$d/src" "$d/.cargo"
  cat > "$d/Cargo.toml" <<TOML
[package]
name = "rigor-lockfile-fixture-cargo-replace"
version = "1.0.0"
authors = ["fixture"]
edition = "2018"

[dependencies]
itoa = "=0.4.8"

[replace]
"itoa:0.4.8" = { git = "git://127.0.0.1:19420/itoa-fork.git", rev = "$FORK" }
TOML
  : > "$d/src/lib.rs"
  printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "%s"\n' "$R/vendored" > "$d/.cargo/config"
  (cd "$d" && PATH="$(bin "$ver"):$PATH" cargo generate-lockfile > "$R/cargo-$ver-replace.log" 2>&1) || { tail -20 "$R/cargo-$ver-replace.log"; exit 1; }
  (cd "$d" && printf '%s\nsha256 %s\n' "$(PATH="$(bin "$ver"):$PATH" cargo --version)" "$(sha256sum Cargo.lock | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $ver replace"; cat "$d/GENERATED_BY.txt"
done
