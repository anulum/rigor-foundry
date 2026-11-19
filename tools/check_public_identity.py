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
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, ScalarNode

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
_BOOT_FILENAMES = frozenset(
    {"AGENTS.md", "CLAU" + "DE.md", "CO" + "DEX.md", "GEMINI.md", "GR" + "OK.md", "KIMI.md"}
)
_VSIX_IGNORE = Path("editors/vscode/.vscodeignore")
_DOCKER_IGNORE = Path(".dockerignore")
_POTENTIAL_INCLUDE = re.compile(r"[\s\ufeff]*!")
# Docker cleans path components before its matcher interprets a leading bang.
_POTENTIAL_DOCKER_INCLUDE = re.compile(r"(?!#).*!")
_IGNORE_PREFIXES = {
    Path(".gitignore"): "",
    _DOCKER_IGNORE: "**/",
    _VSIX_IGNORE: "**/",
}


def _docs_exclusion_lines(text: str) -> range:
    """Find the source lines of one literal MkDocs exclusion block."""
    try:
        config = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return range(0)
    if not isinstance(config, MappingNode):
        return range(0)
    selected = [
        (key, value)
        for key, value in config.value
        if isinstance(key, ScalarNode) and key.value == "exclude_docs"
    ]
    if len(selected) != 1:
        return range(0)
    key, block = selected[0]
    header = text.splitlines()[key.start_mark.line].rstrip()
    if not isinstance(block, ScalarNode) or header != "exclude_docs: |":
        return range(0)
    return range(block.start_mark.line + 1, block.end_mark.line + bool(block.end_mark.column))


def _exclusions_after_includes(
    lines: list[str], include: re.Pattern[str] = _POTENTIAL_INCLUDE
) -> int:
    """Return the first index after all potential ordered re-inclusions."""
    return max(
        (index + 1 for index, line in enumerate(lines) if include.match(line)),
        default=0,
    )


def _remove_private_boot_exclusions(text: str, path: Path | None) -> str:
    """Retain public text after classifying effective, exact boot-file exclusions."""
    if path is not None and path in _IGNORE_PREFIXES:
        prefix = _IGNORE_PREFIXES[path]
        patterns = {prefix + filename for filename in _BOOT_FILENAMES}
        if path == _VSIX_IGNORE:
            # vsce applies every re-inclusion regardless of ordering. The project's
            # compiled JavaScript glob cannot match a Markdown boot file.
            lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            if any(
                _POTENTIAL_INCLUDE.match(line) and line.strip() != "!out/src/*.js"
                for line in lines
            ):
                return text
            first = 0
        else:
            # Ordered projections may re-include any earlier exclusion. Only
            # classify the final exclusions, without guessing glob intersections.
            lines = text.split("\n")
            include = _POTENTIAL_DOCKER_INCLUDE if path == _DOCKER_IGNORE else _POTENTIAL_INCLUDE
            first = _exclusions_after_includes(lines, include)
        return "\n".join(
            "." if index >= first and line.removesuffix("\r") in patterns else line
            for index, line in enumerate(lines)
        )
    if path == Path("mkdocs.yml"):
        active = _docs_exclusion_lines(text)
        lines = text.splitlines()
        first = active.start + _exclusions_after_includes(lines[active.start : active.stop])
        return "\n".join(
            "." if first <= index < active.stop and line.lstrip(" ") in _BOOT_FILENAMES else line
            for index, line in enumerate(lines)
        )
    return text


def public_identity_errors(text: str, *, path: Path | None = None) -> list[str]:
    """Find disallowed public identities while retaining technical references.

    Parameters
    ----------
    text : str
        Public text, including source, fixtures and documentation.
    path : pathlib.Path or None
        Repository-relative path of the scanned text, for syntax checks on
        public projection configuration.

    Returns
    -------
    list[str]
        One diagnostic per distinct disallowed identity, in policy order.

    Notes
    -----
    The registered JSONL format name requires an explicit
    technical-context word in the same paragraph. Attribution, actor, branding
    or authorship cues take precedence. Exact private boot filenames are also
    admitted as active exclusions in the maintained projection configuration.
    Every other occurrence remains subject to the lexical identity rule.
    """
    paragraphs = re.split(r"\n\s*\n", _remove_private_boot_exclusions(text, path).casefold())
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
