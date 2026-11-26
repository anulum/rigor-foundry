# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — lockfile digest decoding
"""Decode the artifact digests that lockfiles record, and judge their strength.

This implements lockfile integrity semantics v1, B7 §2, and its ruling on several SRI hashes.
SHA-512, SHA-384 and SHA-256 are accepted; SHA-1 and MD5 are weak. A digest decodes only when
its algorithm is known, its text is exactly canonical and its decoded length matches the
algorithm. A digest that does not decode is reported, never ignored, even beside a valid
one. An entry is accepted when at least one valid digest is accepted, and
it pins its artifact only when, in addition, no listed digest is malformed.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Literal

DigestAlgorithm = Literal["sha512", "sha384", "sha256", "sha1", "md5"]
DigestFinding = Literal["missing-digest", "weak-digest", "malformed-digest"]

DIGEST_BYTES: Final[dict[DigestAlgorithm, int]] = {
    "sha512": 64,
    "sha384": 48,
    "sha256": 32,
    "sha1": 20,
    "md5": 16,
}
ACCEPTED_ALGORITHMS: Final[frozenset[DigestAlgorithm]] = frozenset({"sha512", "sha384", "sha256"})

# ASCII whitespace as the SRI metadata grammar splits it: tab, line feed, form feed,
# carriage return and space.
_ASCII_WHITESPACE: Final = re.compile(r"[\t\n\f\r ]+")
_ASCII_WHITESPACE_CHARACTERS: Final = "\t\n\f\r "
_SRI_TOKEN: Final = re.compile(r"(sha512|sha384|sha256|sha1|md5)-([A-Za-z0-9+/]+={0,2})")
_PREFIXED_HEX: Final = re.compile(r"(sha512|sha384|sha256|sha1|md5):([0-9a-f]+)")
_LOWER_HEX: Final = re.compile(r"[0-9a-f]+")


@dataclass(frozen=True)
class DigestReading:
    """The digests decoded for one locked entry.

    Parameters
    ----------
    algorithms : tuple[DigestAlgorithm, ...]
        The algorithm of each digest that decoded, in the order the lockfile lists them.
    malformed_tokens : int
        How many listed digests did not decode.
    """

    algorithms: tuple[DigestAlgorithm, ...]
    malformed_tokens: int

    @property
    def accepted(self) -> bool:
        """Return whether at least one decoded digest uses an accepted algorithm."""
        return any(algorithm in ACCEPTED_ALGORITHMS for algorithm in self.algorithms)

    @property
    def pins_artifact(self) -> bool:
        """Return whether the digests pin an artifact: one is accepted and none is malformed."""
        return self.accepted and not self.malformed_tokens

    @property
    def findings(self) -> tuple[DigestFinding, ...]:
        """Return the digest findings, in a fixed order.

        Returns
        -------
        tuple[DigestFinding, ...]
            ``missing-digest`` when no digest is listed at all; otherwise ``weak-digest`` when
            digests decoded but none is accepted, then ``malformed-digest`` when any did not
            decode.
        """
        if not self.algorithms and not self.malformed_tokens:
            return ("missing-digest",)
        found: list[DigestFinding] = []
        if self.algorithms and not self.accepted:
            found.append("weak-digest")
        if self.malformed_tokens:
            found.append("malformed-digest")
        return tuple(found)


_MALFORMED: Final = DigestReading(algorithms=(), malformed_tokens=1)


def missing_digest() -> DigestReading:
    """Return the reading of an entry whose lockfile records no digest field at all.

    Returns
    -------
    DigestReading
        A reading whose only finding is ``missing-digest``.
    """
    return DigestReading(algorithms=(), malformed_tokens=0)


def _require_algorithm(algorithm: str) -> DigestAlgorithm:
    """Return a supported algorithm name, refusing a format that names any other."""
    for known in DIGEST_BYTES:
        if algorithm == known:
            return known
    raise ValueError(f"unsupported digest algorithm: {algorithm!r}")


def _canonical_base64(algorithm: DigestAlgorithm, text: str) -> bool:
    """Return whether text is the exact standard base64 encoding of one digest."""
    try:
        raw = base64.b64decode(text, validate=True)
    except binascii.Error:
        return False
    return len(raw) == DIGEST_BYTES[algorithm] and base64.b64encode(raw).decode("ascii") == text


def _canonical_hex(algorithm: DigestAlgorithm, text: str) -> bool:
    """Return whether text is the exact lowercase hex encoding of one digest."""
    return _LOWER_HEX.fullmatch(text) is not None and len(text) == 2 * DIGEST_BYTES[algorithm]


def _sri_token(token: str) -> DigestReading:
    """Decode one SRI ``<algorithm>-<base64>`` token, with no option suffix."""
    match = _SRI_TOKEN.fullmatch(token)
    if match is None:
        return _MALFORMED
    algorithm = _require_algorithm(match.group(1))
    if not _canonical_base64(algorithm, match.group(2)):
        return _MALFORMED
    return DigestReading(algorithms=(algorithm,), malformed_tokens=0)


def combine_readings(readings: Iterable[DigestReading]) -> DigestReading:
    """Combine the readings of several digests listed for one entry.

    Parameters
    ----------
    readings : Iterable[DigestReading]
        One reading per listed digest, in lockfile order.

    Returns
    -------
    DigestReading
        Accepted when any listed digest is accepted; malformed when any did not decode; missing
        when nothing was listed.
    """
    algorithms: list[DigestAlgorithm] = []
    malformed = 0
    for reading in readings:
        algorithms.extend(reading.algorithms)
        malformed += reading.malformed_tokens
    return DigestReading(algorithms=tuple(algorithms), malformed_tokens=malformed)


def read_sri(value: str) -> DigestReading:
    """Decode a present SRI integrity value, which may list several tokens.

    Parameters
    ----------
    value : str
        The integrity text, as npm, Yarn and pnpm record it.

    Returns
    -------
    DigestReading
        Every ASCII-whitespace-separated token decoded. A present value with no token is
        malformed, not missing.
    """
    tokens = [token for token in _ASCII_WHITESPACE.split(value) if token]
    if not tokens:
        return _MALFORMED
    return combine_readings(_sri_token(token) for token in tokens)


def read_hex_digest(algorithm: str, value: str) -> DigestReading:
    """Decode a lowercase hex digest whose algorithm the lockfile format implies.

    Parameters
    ----------
    algorithm : str
        The algorithm the format names, such as ``sha256`` for a Cargo checksum.
    value : str
        The hex text.

    Returns
    -------
    DigestReading
        One decoded digest, or one malformed digest.

    Raises
    ------
    ValueError
        If the format names an algorithm outside the supported table.
    """
    known = _require_algorithm(algorithm)
    if not _canonical_hex(known, value):
        return _MALFORMED
    return DigestReading(algorithms=(known,), malformed_tokens=0)


def read_prefixed_hex_digest(value: str) -> DigestReading:
    """Decode an ``<algorithm>:<hex>`` digest, as Poetry and Pipenv record it.

    Parameters
    ----------
    value : str
        The prefixed digest text.

    Returns
    -------
    DigestReading
        One decoded digest, or one malformed digest.
    """
    match = _PREFIXED_HEX.fullmatch(value)
    if match is None:
        return _MALFORMED
    return read_hex_digest(match.group(1), match.group(2))


def read_base64_digest(algorithm: str, value: str) -> DigestReading:
    """Decode a standard base64 digest whose algorithm the lockfile format implies.

    Parameters
    ----------
    algorithm : str
        The algorithm the format names, such as ``sha256`` for Go's ``h1:`` hash.
    value : str
        The base64 text, without any prefix.

    Returns
    -------
    DigestReading
        One decoded digest, or one malformed digest.

    Raises
    ------
    ValueError
        If the format names an algorithm outside the supported table.
    """
    known = _require_algorithm(algorithm)
    if value.strip(_ASCII_WHITESPACE_CHARACTERS) != value or not _canonical_base64(known, value):
        return _MALFORMED
    return DigestReading(algorithms=(known,), malformed_tokens=0)
