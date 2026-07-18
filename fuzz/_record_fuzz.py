# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared Atheris consume helpers for record parsers
"""Feed fuzzer bytes through the JSON boundary into fail-closed record parsers.

Every RigorFoundry record parser is contractually fail-closed: hostile or
malformed input must raise ``ValueError``, never crash with an unexpected
exception or hang. These helpers cross the JSON boundary and tolerate only the
contractual failure modes, so any other exception propagates and the fuzzer
records it as a genuine robustness finding.
"""

from __future__ import annotations

import json
from collections.abc import Callable

# A hardened parser may reject adversarial input with ValueError (its fail-closed
# contract; UnicodeDecodeError and json.JSONDecodeError are ValueError subclasses)
# or RecursionError (CPython's bounded response to deeply nested input, not a
# parser defect). Any other exception is a finding.
_TOLERATED = (ValueError, RecursionError)


def fuzz_mapping_parser(data: bytes, parser: Callable[[object], object]) -> None:
    """Decode JSON and drive a mapping parser, tolerating only fail-closed errors."""
    try:
        payload = json.loads(data.decode("utf-8", "surrogatepass"))
    except _TOLERATED:
        return
    try:
        parser(payload)
    except _TOLERATED:
        return


def fuzz_text_parser(data: bytes, parser: Callable[[str], object]) -> None:
    """Drive a raw-text parser, tolerating only fail-closed errors."""
    try:
        text = data.decode("utf-8", "surrogatepass")
    except _TOLERATED:
        return
    try:
        parser(text)
    except _TOLERATED:
        return
