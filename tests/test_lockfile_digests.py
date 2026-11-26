# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — lockfile digest decoding witnesses
"""Witness the lockfile digest decoder against lockfile integrity semantics v1.

The semantics are B7 §2 and its ruling on several SRI hashes: every whitespace token is
validated, any malformed token is reported, and an entry is accepted when one valid token is
SHA-256 or stronger.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from rigor_foundry.lockfile_digests import (
    DigestReading,
    combine_readings,
    missing_digest,
    read_base64_digest,
    read_hex_digest,
    read_prefixed_hex_digest,
    read_sri,
)

PAYLOAD = b"lockfile integrity witness"


def _sri(algorithm: str) -> str:
    """Return a canonical SRI token for the witness payload under one algorithm."""
    return f"{algorithm}-" + base64.b64encode(hashlib.new(algorithm, PAYLOAD).digest()).decode()


def _hex(algorithm: str) -> str:
    """Return the lowercase hex digest of the witness payload under one algorithm."""
    return hashlib.new(algorithm, PAYLOAD).hexdigest()


@pytest.mark.parametrize("algorithm", ["sha512", "sha384", "sha256"])
def test_a_strong_sri_token_is_strong_and_clean(algorithm: str) -> None:
    """One valid SHA-256, SHA-384 or SHA-512 token gives an accepted entry with no finding.

    Parameters
    ----------
    algorithm : str
        The accepted algorithm of the single token.
    """
    reading = read_sri(_sri(algorithm))
    assert reading.algorithms == (algorithm,)
    assert reading.malformed_tokens == 0
    assert reading.accepted
    assert reading.pins_artifact
    assert reading.findings == ()


@pytest.mark.parametrize("algorithm", ["sha1", "md5"])
def test_a_weak_only_sri_token_gives_weak_digest(algorithm: str) -> None:
    """A valid SHA-1 or MD5 token alone gives ``weak-digest`` and is not accepted.

    Parameters
    ----------
    algorithm : str
        The weak algorithm of the single token.
    """
    reading = read_sri(_sri(algorithm))
    assert not reading.accepted
    assert not reading.pins_artifact
    assert reading.findings == ("weak-digest",)


def test_a_weak_token_beside_a_strong_one_is_clean() -> None:
    """The ruling's clean fixture: ``sha1-… sha512-…`` is accepted with no finding."""
    reading = read_sri(f"{_sri('sha1')} {_sri('sha512')}")
    assert reading.algorithms == ("sha1", "sha512")
    assert reading.pins_artifact
    assert reading.findings == ()


def test_a_malformed_secondary_token_is_never_ignored() -> None:
    """The ruling's failing fixture: ``sha512-… sha512-!!!`` is malformed, so it pins nothing."""
    reading = read_sri(f"{_sri('sha512')} sha512-!!!")
    assert reading.algorithms == ("sha512",)
    assert reading.malformed_tokens == 1
    assert reading.accepted
    assert not reading.pins_artifact
    assert reading.findings == ("malformed-digest",)


def test_a_weak_token_beside_a_malformed_one_reports_both() -> None:
    """A valid SHA-1 token beside a malformed token reports both findings."""
    reading = read_sri(f"{_sri('sha1')}\tsha256-AAAA")
    assert reading.findings == ("weak-digest", "malformed-digest")


@pytest.mark.parametrize(
    "value",
    [
        "\t" + _sri("sha512") + "\n\r\f " + _sri("sha384") + " ",
        _sri("sha512") + "  " + _sri("sha256"),
    ],
)
def test_tokens_split_on_ascii_whitespace(value: str) -> None:
    """Tokens split on any run of ASCII whitespace, with leading and trailing runs ignored.

    Parameters
    ----------
    value : str
        Two accepted tokens separated and surrounded by ASCII whitespace.
    """
    reading = read_sri(value)
    assert len(reading.algorithms) == 2
    assert reading.findings == ()


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("", "an integrity field that is present but empty"),
        ("   \t", "whitespace only"),
        (_sri("sha512") + "?opt", "an SRI option suffix"),
        ("sha3-" + base64.b64encode(b"x" * 32).decode(), "an unknown algorithm"),
        ("SHA512-" + _sri("sha512").removeprefix("sha512-"), "an upper-case algorithm name"),
        ("sha512-" + base64.b64encode(b"x" * 63).decode(), "a decoded length that does not match"),
        (_sri("sha256").rstrip("="), "missing base64 padding"),
        ("sha256-" + base64.urlsafe_b64encode(b"\xfb" * 32).decode(), "the URL-safe alphabet"),
        (_sri("sha512") + "\u00a0" + _sri("sha256"), "a non-ASCII space inside one token"),
        ("sha512", "no separator"),
        ("sha512-", "no digest"),
    ],
)
def test_each_malformed_sri_form_gives_malformed_digest(value: str, reason: str) -> None:
    """Every form the decoder cannot decode exactly gives ``malformed-digest``.

    Parameters
    ----------
    value : str
        The present integrity value.
    reason : str
        Why the value does not decode, for the failure message.
    """
    reading = read_sri(value)
    assert "malformed-digest" in reading.findings, reason
    assert not reading.accepted, reason


def test_non_canonical_base64_padding_bits_are_malformed() -> None:
    """A token whose unused padding bits are set decodes to the right length but is malformed."""
    canonical = _sri("sha256")
    assert canonical.endswith("=")
    last = canonical[-2]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    altered = canonical[:-2] + alphabet[alphabet.index(last) ^ 1] + "="
    assert altered != canonical
    assert base64.b64decode(altered.removeprefix("sha256-")) == base64.b64decode(
        canonical.removeprefix("sha256-")
    )
    assert read_sri(altered).findings == ("malformed-digest",)


def test_an_absent_digest_is_missing_not_malformed() -> None:
    """Only an absent digest field gives ``missing-digest``."""
    reading = missing_digest()
    assert reading == DigestReading(algorithms=(), malformed_tokens=0)
    assert not reading.accepted
    assert reading.findings == ("missing-digest",)


@pytest.mark.parametrize(
    ("algorithm", "accepted"), [("sha512", True), ("sha256", True), ("sha1", False)]
)
def test_a_lowercase_hex_digest_decodes_under_its_named_algorithm(
    algorithm: str, accepted: bool
) -> None:
    """A lowercase hex digest of the right length decodes under the algorithm the format names.

    Parameters
    ----------
    algorithm : str
        The algorithm the lockfile format implies.
    accepted : bool
        Whether that algorithm is accepted.
    """
    reading = read_hex_digest(algorithm, _hex(algorithm))
    assert reading.algorithms == (algorithm,)
    assert reading.accepted is accepted


@pytest.mark.parametrize(
    "value",
    [
        _hex("sha256").upper(),
        _hex("sha256")[:-2],
        _hex("sha256") + "0",
        "g" * 64,
        "",
        " " + _hex("sha256"),
    ],
)
def test_a_hex_digest_that_does_not_decode_exactly_is_malformed(value: str) -> None:
    """Upper case, a wrong length, a non-hex digit, empty text or padding give ``malformed-digest``.

    Parameters
    ----------
    value : str
        The hex text that must not decode.
    """
    assert read_hex_digest("sha256", value).findings == ("malformed-digest",)


def test_an_unknown_named_algorithm_is_refused_by_the_caller_contract() -> None:
    """A format that names an algorithm outside the table is a programming error."""
    with pytest.raises(ValueError, match="unsupported digest algorithm"):
        read_hex_digest("sha3_256", _hex("sha256"))
    with pytest.raises(ValueError, match="unsupported digest algorithm"):
        read_base64_digest("crc32", "AAAA")


@pytest.mark.parametrize(
    ("value", "algorithms", "findings"),
    [
        (f"sha256:{_hex('sha256')}", ("sha256",), ()),
        (f"sha512:{_hex('sha512')}", ("sha512",), ()),
        (f"md5:{_hex('md5')}", ("md5",), ("weak-digest",)),
        (f"sha256:{_hex('sha512')}", (), ("malformed-digest",)),
        (f"blake2b:{_hex('sha512')}", (), ("malformed-digest",)),
        (_hex("sha256"), (), ("malformed-digest",)),
        (f"SHA256:{_hex('sha256')}", (), ("malformed-digest",)),
    ],
)
def test_a_prefixed_hex_digest_names_its_algorithm(
    value: str, algorithms: tuple[str, ...], findings: tuple[str, ...]
) -> None:
    """``<algorithm>:<hex>`` decodes under the named algorithm, or is malformed.

    Parameters
    ----------
    value : str
        The prefixed digest, as Poetry and Pipenv write it.
    algorithms : tuple[str, ...]
        The algorithms that decode.
    findings : tuple[str, ...]
        The expected findings.
    """
    reading = read_prefixed_hex_digest(value)
    assert reading.algorithms == algorithms
    assert reading.findings == findings


def test_a_base64_digest_decodes_under_its_named_algorithm() -> None:
    """A canonical base64 digest of the right length decodes, as Go's ``h1:`` hash is written."""
    value = base64.b64encode(hashlib.sha256(PAYLOAD).digest()).decode()
    assert read_base64_digest("sha256", value).findings == ()
    assert read_base64_digest("sha256", value[:-1]).findings == ("malformed-digest",)
    assert read_base64_digest("sha256", value + "AAAA").findings == ("malformed-digest",)


def test_combined_readings_are_strong_when_any_digest_is_strong() -> None:
    """Several listed digests are accepted when one is accepted, and every one must be well formed."""
    accepted = read_prefixed_hex_digest(f"sha256:{_hex('sha256')}")
    weak = read_prefixed_hex_digest(f"md5:{_hex('md5')}")
    broken = read_prefixed_hex_digest("sha256:zz")
    assert combine_readings((weak, accepted)).findings == ()
    assert combine_readings((weak, accepted)).algorithms == ("md5", "sha256")
    assert combine_readings((weak,)).findings == ("weak-digest",)
    assert combine_readings((accepted, broken)).findings == ("malformed-digest",)
    assert combine_readings(()).findings == ("missing-digest",)
