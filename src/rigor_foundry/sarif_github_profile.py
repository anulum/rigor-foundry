# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — GitHub code-scanning SARIF consumer profile
"""Derive the GitHub code-scanning profile from the complete canonical SARIF export.

The canonical export keeps every audit candidate. GitHub code scanning would present any
uploaded result as an alert, so this profile keeps only results whose validated review
decision is ``valid``, declares what it omitted, binds the canonical document by digest, and
refuses GitHub's documented upload limits before anything is written.
"""

from __future__ import annotations

import copy
import gzip
import hashlib
from typing import Any, Final

GITHUB_CODE_SCANNING_PROFILE: Final = "github-code-scanning"
GITHUB_RESULT_LIMIT: Final = 5_000
GITHUB_GZIP_LIMIT_BYTES: Final = 10 * 1024 * 1024
_OMITTED_STATES: Final = ("unreviewed", "needs-evidence", "invalid", "accepted-boundary")


def github_code_scanning_document(
    canonical: dict[str, Any], canonical_text: str
) -> dict[str, Any]:
    """Return the GitHub profile of one canonical SARIF document.

    Parameters
    ----------
    canonical : dict[str, Any]
        The complete canonical SARIF document; it is not modified.
    canonical_text : str
        The exact rendered canonical document whose digest the profile declares.

    Returns
    -------
    dict[str, Any]
        A copy that keeps only reviewed ``valid`` results and declares the profile, the
        omitted count per state and the canonical document's SHA-256 in its run properties.
    """
    document = copy.deepcopy(canonical)
    for run in document["runs"]:
        omitted = dict.fromkeys(_OMITTED_STATES, 0)
        kept = []
        for result in run["results"]:
            state = result["properties"]["rigorFoundry/verdictState"]
            if state == "valid":
                kept.append(result)
            else:
                omitted[state] += 1
        run["results"] = kept
        run["properties"]["rigorFoundry/consumerProfile"] = GITHUB_CODE_SCANNING_PROFILE
        run["properties"]["rigorFoundry/omittedResults"] = omitted
        run["properties"]["rigorFoundry/canonicalDocumentDigest"] = hashlib.sha256(
            canonical_text.encode("utf-8")
        ).hexdigest()
    return document


def require_github_limits(document: dict[str, Any], rendered: str) -> None:
    """Refuse a profile document that GitHub code scanning would reject or truncate.

    Parameters
    ----------
    document : dict[str, Any]
        The GitHub profile document.
    rendered : str
        Its exact rendered text, whose gzip size is bounded.

    Raises
    ------
    ValueError
        Naming the first count that exceeds a documented GitHub limit. Results above
        5,000 are refused because GitHub would show only the top 5,000.
    """
    runs = document["runs"]
    counts: list[tuple[str, int, int]] = [("runs per file", len(runs), 20)]
    for run in runs:
        rules = run["tool"]["driver"]["rules"]
        results = run["results"]
        counts.append(("rules per run", len(rules), 25_000))
        counts.append(("results per run", len(results), GITHUB_RESULT_LIMIT))
        counts += [("tags per rule", len(rule["properties"]["tags"]), 20) for rule in rules]
        counts += [("locations per result", len(result["locations"]), 1_000) for result in results]
    compressed = len(gzip.compress(rendered.encode("utf-8"), mtime=0))
    counts.append(("gzip bytes per file", compressed, GITHUB_GZIP_LIMIT_BYTES))
    for label, count, limit in counts:
        if count > limit:
            raise ValueError(
                f"GitHub code-scanning profile refuses {count} {label}; the limit is {limit}"
            )
