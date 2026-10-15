# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Public identity and technical-format conformance
"""Separate supported technical names from public agent attribution."""

from __future__ import annotations

import re

_IDENTITIES = (
    "co" + "dex",
    "open" + "ai",
    "chat" + "gpt",
    "clau" + "de",
    "anthro" + "pic",
    "gr" + "ok",
    "x" + "ai",
)
_TECHNICAL_FORMAT = re.compile(r"(?<![\w/@-])" + "clau" + r"de[ \t\r\n]+jsonl\b(?![/@-])")
_FORMAT_CONTEXT = re.compile(r"\b(?:format|source|transcript|message|subset)\b")
_ATTRIBUTION_CONTEXT = re.compile(
    r"\b(?:agent|seat|author(?:ed|s|ship|ing)?|coauthor(?:ed)?|generated|generator|"
    r"written|writer|reviewer|contributor|branding|powered|created|built|developed|"
    r"maintainer|courtesy|copyright|by)\b|©"
)
_ATTRIBUTION_LEAD = re.compile(r"\b(?:by|author|authors|seat|reviewer|agent)\s*[:=]?\s*[\"']?\s*$")


def public_identity_errors(text: str) -> list[str]:
    """Find disallowed public identities while retaining supported format names.

    Parameters
    ----------
    text : str
        Public text, including source, fixtures and documentation.

    Returns
    -------
    list[str]
        One diagnostic per distinct disallowed identity, in policy order.

    Notes
    -----
    Only the registered JSONL format name is admitted, with an explicit
    technical-context word in the same paragraph. Attribution, actor, branding
    or authorship cues take precedence over that exception. Other names or
    ambiguous uses require review and an explicit policy extension. This
    conservative lexical check does not infer authorship or authenticate actors.
    No path or file type is exempt.
    """
    paragraphs = re.split(r"\n\s*\n", text.casefold())
    errors: list[str] = []
    for identity in _IDENTITIES:
        pattern = re.compile(rf"\b{re.escape(identity)}\b")
        for index, paragraph in enumerate(paragraphs):
            matches = tuple(pattern.finditer(paragraph))
            if not matches:
                continue
            technical = {
                match.start()
                for match in _TECHNICAL_FORMAT.finditer(paragraph)
                if _FORMAT_CONTEXT.search(paragraph)
                and not _ATTRIBUTION_CONTEXT.search(paragraph)
                and not (index and _ATTRIBUTION_LEAD.search(paragraphs[index - 1]))
            }
            if any(match.start() not in technical for match in matches):
                errors.append("vendor identity is public")
                break
    return errors
