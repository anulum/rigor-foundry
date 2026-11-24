# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — reviewed rule-to-CWE mapping
"""Load the reviewed rule-to-CWE mapping that the SARIF export and the rule catalogue publish.

A mapping says that a rule marks a surface *relevant* to one CWE weakness. It never says that
a candidate is that weakness, so ``relevant`` is the only admitted relationship kind. Only
reviewed entries are admitted. An entry is refused when it has no evidence review record, was
reviewed by its own author, names an unregistered or already-mapped rule, or has a
justification that does not cite its CWE. The data names CWE entries only by id; it holds no
CWE names or descriptions.
"""

from __future__ import annotations

import datetime
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from importlib import resources
from types import MappingProxyType
from typing import Final

from .rules import RULES

CWE_TAXONOMY_NAME: Final = "CWE"
CWE_ORGANIZATION: Final = "MITRE"
CWE_INFORMATION_URI: Final = "https://cwe.mitre.org/"
CWE_MAPPING_RESOURCE: Final = "cwe_mapping.json"
CWE_RELATIONSHIP_KIND: Final = "relevant"
CWE_REVIEW_SCOPE: Final = "evidence"
CWE_MAPPING_SCHEMA_VERSION: Final = "1.0"
_DOCUMENT_KEYS: Final = frozenset(
    {
        "schema_version",
        "cwe_version",
        "cwe_release_date",
        "cwe_download_uri",
        "cwe_member_sha256",
        "mappings",
    }
)
_MAPPING_KEYS: Final = frozenset(
    {"rule_id", "cwe_id", "kind", "justification", "author", "review"}
)
_REVIEW_KEYS: Final = frozenset({"reviewer", "date", "scope"})
_CWE_VERSION: Final = re.compile(r"[1-9][0-9]*\.[0-9]+")
_SEAT: Final = re.compile(r"[0-9a-z][0-9a-z-]*")
_SHA256: Final = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class CweReview:
    """The evidence review that admitted one mapping."""

    reviewer: str
    date: str
    scope: str


@dataclass(frozen=True)
class CweMapping:
    """One reviewed statement that a rule's candidates are relevant to one CWE entry."""

    rule_id: str
    cwe_id: int
    kind: str
    justification: str
    author: str
    review: CweReview


@dataclass(frozen=True)
class CweCatalogue:
    """The pinned CWE List version and every reviewed mapping, in rule-registry order."""

    version: str
    release_date: str
    download_uri: str
    member_sha256: str
    mappings: Mapping[str, CweMapping]

    def taxa(self) -> tuple[int, ...]:
        """Return each mapped CWE id once, in ascending numeric order.

        Returns
        -------
        tuple[int, ...]
            The CWE taxonomy's taxa ids.
        """
        return tuple(sorted({mapping.cwe_id for mapping in self.mappings.values()}))


def cwe_definition_uri(cwe_id: int) -> str:
    """Return the public definition page of one CWE entry.

    Parameters
    ----------
    cwe_id : int
        A CWE id such as ``95``.

    Returns
    -------
    str
        The ``cwe.mitre.org`` definition URL of the entry.
    """
    return f"{CWE_INFORMATION_URI}data/definitions/{cwe_id}.html"


def cwe_download_uri(version: str) -> str:
    """Return the version-specific download archive of one CWE List version.

    Parameters
    ----------
    version : str
        A CWE List version such as ``"5.0"``.

    Returns
    -------
    str
        The ``cwe.mitre.org`` XML archive URL of exactly that version, never the moving
        ``cwec_latest`` alias.
    """
    return f"{CWE_INFORMATION_URI}data/xml/cwec_v{version}.xml.zip"


def _object(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    """Return ``value`` as a JSON object holding exactly ``keys``, or refuse it."""
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} must be an object with exactly the keys {sorted(keys)}")
    return value


def _text(value: object, label: str) -> str:
    """Return ``value`` as a non-empty string without surrounding whitespace, or refuse it."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty string without surrounding whitespace")
    return value


def _seat(value: object, label: str) -> str:
    """Return ``value`` as a lower-case seat identifier, or refuse it."""
    seat = _text(value, label)
    if _SEAT.fullmatch(seat) is None:
        raise ValueError(f"{label} must be a lower-case seat identifier")
    return seat


def _date(value: object, label: str) -> str:
    """Return ``value`` as an ISO 8601 calendar date string, or refuse it."""
    text = _text(value, label)
    try:
        parsed = datetime.date.fromisoformat(text)
    except ValueError:
        parsed = None
    if parsed is None or parsed.isoformat() != text:
        raise ValueError(f"{label} must be an ISO 8601 calendar date (YYYY-MM-DD)")
    return text


def _review(value: object, rule_id: str, author: str) -> CweReview:
    """Return one mapping's evidence review, refusing an unreviewed or self-reviewed mapping."""
    if value is None or value == {}:
        raise ValueError(f"unreviewed CWE mapping refused: {rule_id}")
    record = _object(value, _REVIEW_KEYS, f"the review of {rule_id}")
    reviewer = _seat(record["reviewer"], f"the reviewer of {rule_id}")
    if reviewer == author:
        raise ValueError(f"CWE mapping of {rule_id} was reviewed by its own author: {author}")
    if record["scope"] != CWE_REVIEW_SCOPE:
        raise ValueError(f"the review of {rule_id} must have scope {CWE_REVIEW_SCOPE!r}")
    date = _date(record["date"], f"the review date of {rule_id}")
    return CweReview(reviewer, date, CWE_REVIEW_SCOPE)


def _mapping(value: object, registered: frozenset[str]) -> CweMapping:
    """Return one validated, reviewed mapping entry."""
    if not isinstance(value, dict):
        raise ValueError("each CWE mapping must be an object")
    rule_id = _text(value.get("rule_id"), "a CWE mapping rule_id")
    if rule_id not in registered:
        raise ValueError(f"CWE mapping names an unregistered rule: {rule_id}")
    author = _seat(value.get("author"), f"the author of {rule_id}")
    review = _review(value.get("review"), rule_id, author)
    entry = _object(value, _MAPPING_KEYS, f"the CWE mapping of {rule_id}")
    if entry["kind"] != CWE_RELATIONSHIP_KIND:
        raise ValueError(
            f"the CWE mapping of {rule_id} must have kind {CWE_RELATIONSHIP_KIND!r}, "
            f"not {entry['kind']!r}"
        )
    cwe_id = entry["cwe_id"]
    if type(cwe_id) is not int or cwe_id < 1:
        raise ValueError(f"the CWE id of {rule_id} must be a positive integer, not {cwe_id!r}")
    justification = _text(entry["justification"], f"the justification of {rule_id}")
    if (
        "\n" in justification
        or not justification.endswith(".")
        or ". " in justification
        or re.search(rf"\bCWE-{cwe_id}\b", justification) is None
    ):
        raise ValueError(
            f"the justification of {rule_id} must be one sentence that cites CWE-{cwe_id}"
        )
    return CweMapping(rule_id, cwe_id, CWE_RELATIONSHIP_KIND, justification, author, review)


def parse_cwe_catalogue(text: str) -> CweCatalogue:
    """Parse and strictly validate one rule-to-CWE mapping document.

    Parameters
    ----------
    text : str
        The JSON text of a mapping document.

    Returns
    -------
    CweCatalogue
        The pinned CWE List version and its reviewed mappings, in rule-registry order.

    Raises
    ------
    ValueError
        If the document is not exactly the expected shape, does not pin one CWE List version
        by its version-specific archive and member digest, or holds an unreviewed,
        self-reviewed, duplicated, unregistered, non-``relevant`` or uncited mapping.
    """
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"the CWE mapping is not valid JSON: {error.msg}") from error
    document = _object(value, _DOCUMENT_KEYS, "the CWE mapping document")
    if document["schema_version"] != CWE_MAPPING_SCHEMA_VERSION:
        raise ValueError(f"the CWE mapping schema_version must be {CWE_MAPPING_SCHEMA_VERSION!r}")
    version = _text(document["cwe_version"], "cwe_version")
    if _CWE_VERSION.fullmatch(version) is None:
        raise ValueError("cwe_version must be a CWE List version such as 5.0")
    release_date = _date(document["cwe_release_date"], "cwe_release_date")
    download_uri = document["cwe_download_uri"]
    if download_uri != cwe_download_uri(version):
        raise ValueError(
            f"cwe_download_uri must be the version-specific archive {cwe_download_uri(version)}"
        )
    member_sha256 = _text(document["cwe_member_sha256"], "cwe_member_sha256")
    if _SHA256.fullmatch(member_sha256) is None:
        raise ValueError("cwe_member_sha256 must be a lower-case hexadecimal SHA-256")
    entries = document["mappings"]
    if not isinstance(entries, list):
        raise ValueError("the CWE mappings must be a list")
    registered = frozenset(rule.rule_id for rule in RULES)
    mappings: dict[str, CweMapping] = {}
    for entry in entries:
        mapping = _mapping(entry, registered)
        if mapping.rule_id in mappings:
            raise ValueError(f"CWE mapping lists a rule twice: {mapping.rule_id}")
        mappings[mapping.rule_id] = mapping
    ordered = {rule.rule_id: mappings[rule.rule_id] for rule in RULES if rule.rule_id in mappings}
    return CweCatalogue(
        version, release_date, cwe_download_uri(version), member_sha256, MappingProxyType(ordered)
    )


@cache
def cwe_catalogue() -> CweCatalogue:
    """Return the packaged reviewed rule-to-CWE mapping.

    Returns
    -------
    CweCatalogue
        The validated catalogue read from the packaged ``cwe_mapping.json``.

    Raises
    ------
    ValueError
        If the packaged data fails validation.
    """
    resource = resources.files("rigor_foundry").joinpath(CWE_MAPPING_RESOURCE)
    return parse_cwe_catalogue(resource.read_text(encoding="utf-8"))
