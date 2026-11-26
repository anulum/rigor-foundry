#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — regenerate the clean go.sum fixtures with pinned Go releases
# Usage: generate-go.sh EMPTY_OUTPUT_DIRECTORY GO_RELEASES_DIRECTORY (that directory holds go<version>/go/bin/go for
# each pinned release, unpacked from go.dev archives whose sha256 matched; needs network access to proxy.golang.org and
# sum.golang.org). Each release tidies the same module with its own `go` directive, so Go 1.17's pruned module graph
# shows, and then a second module whose pkg/errors v0.9.1 is replaced by v0.8.1. Every release writes the same go.sum
# for each module, so the repository stores the newest release's go.sum and go.mod (go-1.27.4, go-1.27.4-replace),
# go1.27.4's go.mod after `go mod edit` added tool, godebug and ignore blocks (go-1.27.4-blocks),
# go1.16.15's go.mod beside the same go.sum (go-1.16.15-gomod), and a copy with CRLF line endings (go-1.27.4-crlf),
# all gzip-compressed (Python gzip, level 9, mtime 0); GENERATED_BY.txt records the SHA-256 of the go.sum Go wrote.
set -euo pipefail
R="${1:?usage: generate-go.sh EMPTY_OUTPUT_DIRECTORY GO_RELEASES_DIRECTORY}"
G="${2:?usage: generate-go.sh EMPTY_OUTPUT_DIRECTORY GO_RELEASES_DIRECTORY}"
mkdir -p "$R"
if [ -n "$(ls -A "$R")" ]; then echo "refusing: $R is not empty" >&2; exit 2; fi
cd "$R"
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOFLAGS=-mod=mod GOTOOLCHAIN=local GO111MODULE=on
export GONOSUMDB="" GOPRIVATE="" GOINSECURE="" CGO_ENABLED=0
for release in 1.16.15 1.17.13 1.22.2 1.27.4; do
  d="$R/go-$release"; mkdir -p "$d/local"
  directive="${release%.*}"
  cat > "$d/go.mod" <<MOD
module example.com/rigor-lockfile-fixture-go

go $directive

require (
	example.com/local v0.0.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/text v0.3.6
)

replace example.com/local => ./local
MOD
  printf 'module example.com/local\n\ngo 1.16\n' > "$d/local/go.mod"
  printf 'package local\n' > "$d/local/local.go"
  cat > "$d/fixture.go" <<'GO'
package fixture

import (
	_ "example.com/local"
	_ "github.com/pkg/errors"
	_ "github.com/stretchr/testify/assert"
	_ "golang.org/x/text/language"
)
GO
  # A fresh module cache and build cache per release, so no release reads another's downloads.
  (cd "$d" && GOPATH="$R/gopath-$release" GOMODCACHE="$R/gopath-$release/pkg/mod" GOCACHE="$R/gocache-$release" \
    "$G/go$release/go/bin/go" mod tidy > "$R/go-$release.log" 2>&1) || { tail -20 "$R/go-$release.log"; exit 1; }
  (cd "$d" && printf '%s\nsha256 %s\n' "$("$G/go$release/go/bin/go" version)" "$(sha256sum go.sum | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $release"; cat "$d/GENERATED_BY.txt"
done
# The same module with a module replacement: pkg/errors v0.9.1 replaced by v0.8.1 of the same module.
for release in 1.16.15 1.17.13 1.22.2 1.27.4; do
  d="$R/go-$release-replace"; mkdir -p "$d"
  directive="${release%.*}"
  cat > "$d/go.mod" <<MOD
module example.com/rigor-lockfile-fixture-go-replace

go $directive

require github.com/pkg/errors v0.9.1

replace github.com/pkg/errors v0.9.1 => github.com/pkg/errors v0.8.1
MOD
  printf 'package fixture\n\nimport _ "github.com/pkg/errors"\n' > "$d/fixture.go"
  (cd "$d" && GOPATH="$R/gopath-$release-replace" GOMODCACHE="$R/gopath-$release-replace/pkg/mod" GOCACHE="$R/gocache-$release-replace" \
    "$G/go$release/go/bin/go" mod tidy > "$R/go-$release-replace.log" 2>&1) || { tail -20 "$R/go-$release-replace.log"; exit 1; }
  (cd "$d" && printf '%s\nsha256 %s\n' "$("$G/go$release/go/bin/go" version)" "$(sha256sum go.sum | cut -c1-64)" > GENERATED_BY.txt)
  echo "== $release replace"; cat "$d/GENERATED_BY.txt"
done
# The first module again, with Go's block directives written by go1.27.4 itself: two tools from the local module
# (`tool` blocks are Go 1.24's), two godebug settings (Go 1.21's) and two ignored directories (Go 1.25's).
release=1.27.4
d="$R/go-$release-blocks"; mkdir -p "$d"
cp -R "$R/go-$release/." "$d/"
mkdir -p "$d/local/cmd/first" "$d/local/cmd/second"
printf 'package main\n\nfunc main() {}\n' > "$d/local/cmd/first/main.go"
printf 'package main\n\nfunc main() {}\n' > "$d/local/cmd/second/main.go"
(cd "$d" && GOPATH="$R/gopath-$release" GOMODCACHE="$R/gopath-$release/pkg/mod" GOCACHE="$R/gocache-$release" \
  "$G/go$release/go/bin/go" mod edit -tool=example.com/local/cmd/first -tool=example.com/local/cmd/second \
  -godebug=panicnil=1 -godebug=winsymlink=0 -ignore=./build -ignore=./node_modules \
  && GOPATH="$R/gopath-$release" GOMODCACHE="$R/gopath-$release/pkg/mod" GOCACHE="$R/gocache-$release" \
  "$G/go$release/go/bin/go" mod tidy > "$R/go-$release-blocks.log" 2>&1) || { tail -20 "$R/go-$release-blocks.log"; exit 1; }
(cd "$d" && printf '%s\nsha256 %s\n' "$("$G/go$release/go/bin/go" version)" "$(sha256sum go.sum | cut -c1-64)" > GENERATED_BY.txt)
echo "== $release blocks"; cat "$d/GENERATED_BY.txt"
