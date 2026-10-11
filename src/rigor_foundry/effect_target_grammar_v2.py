# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared target component grammar
"""Share the exact v2 identifier grammar across journal and clause targets."""

from __future__ import annotations

import re
from ipaddress import IPv6Address
from typing import Final
from unicodedata import normalize

TARGET_VARIANT_V2: Final = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_URI_SCHEME: Final = re.compile(r"[a-z][a-z0-9+.-]*\Z")


def require_remote_target_v2(name: str) -> None:
    """Validate a remote target using only local string and address operations.

    Parameters
    ----------
    name
        Exact URI identity; validation neither normalises it nor retrieves it.

    Raises
    ------
    ValueError
        If the scheme, authority or bracketed address is malformed, or the URI
        contains credentials, fragments, control characters or ambiguous delimiters.
    """
    scheme, separator, remainder = name.partition("://")
    authority = re.split(r"[/?#]", remainder, maxsplit=1)[0]
    if (
        separator != "://"
        or _URI_SCHEME.fullmatch(scheme) is None
        or not authority
        or "@" in authority
        or "%40" in authority.lower()
        or "#" in name
        or any(ord(char) <= 0x20 for char in name)
        or any(char in normalize("NFKC", authority.replace(":", "")) for char in "/?#@:")
    ):
        raise ValueError("target_ref remote URL is malformed")
    if "[" in authority or "]" in authority:
        host, closing, port = authority[1:].partition("]")
        if (
            not authority.startswith("[")
            or not closing
            or "]" in port
            or (port and not port.startswith(":"))
        ):
            raise ValueError("target_ref remote URL is malformed")
        if host.startswith("v"):
            if re.fullmatch(r"v[0-9A-Fa-f]+\..+", host) is None:
                raise ValueError("target_ref remote URL is malformed")
        else:
            try:
                IPv6Address(host)
            except ValueError as exc:
                raise ValueError("target_ref remote URL is malformed") from exc
