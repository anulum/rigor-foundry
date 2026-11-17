#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Semgrep child-process stack profile
set -euo pipefail

# Semgrep's native children require a finite hard stack on Python 3.15.
stack_soft=$(ulimit -S -s)
if [[ "$stack_soft" == unlimited ]]; then
    printf '%s\n' 'Semgrep requires a finite host soft stack limit.' >&2
    exit 2
fi
if ! command -v semgrep >/dev/null; then
    printf '%s\n' 'The locked Semgrep console entry point is not on PATH.' >&2
    exit 127
fi
ulimit -H -s "$stack_soft"
export SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
exec semgrep "$@"
