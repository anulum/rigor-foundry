# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — GitHub Actions expression context analysis
"""Identify bounded inline expressions without interpreting their values."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .workflow_yaml import WorkflowFormatError

_SAFE_EVENT_PATHS = frozenset(
    {
        ("github", "event", "pull_request", "head", "sha"),
        ("github", "event", "pull_request", "base", "sha"),
        ("github", "event", "pull_request", "merge_commit_sha"),
        ("github", "event", "pull_request", "number"),
        ("github", "event", "issue", "number"),
        ("github", "event", "number"),
    }
)
_CONTEXTS = frozenset(
    {
        "github",
        "inputs",
        "env",
        "vars",
        "matrix",
        "steps",
        "needs",
        "strategy",
        "runner",
        "job",
        "secrets",
    }
)
_TRUSTED_CHECKOUT_PATHS = frozenset(
    {
        ("github", "sha"),
        ("github", "ref"),
        ("github", "ref_name"),
        ("github", "repository"),
        ("github", "event", "repository", "full_name"),
        ("github", "event", "pull_request", "base", "ref"),
        ("github", "event", "pull_request", "base", "sha"),
        ("github", "event", "pull_request", "base", "repo", "full_name"),
    }
)
# ECMAScript WhiteSpace and LineTerminator used by the action input reader.
_CHECKOUT_INPUT_PADDING = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)


@dataclass(frozen=True)
class _Token:
    """One expression token with quoted literals distinct from identifiers."""

    kind: Literal["identifier", "string", "punctuation"]
    value: str


def _tokens(expression: str) -> tuple[_Token, ...]:
    """Lex property access and strings, preserving escaped single quotes."""
    result: list[_Token] = []
    index = 0
    while index < len(expression):
        character = expression[index]
        if character.isspace():
            index += 1
        elif character == "'":
            index += 1
            value = ""
            while index < len(expression):
                if expression[index] != "'":
                    value += expression[index]
                    index += 1
                elif expression[index : index + 2] == "''":
                    value += "'"
                    index += 2
                else:
                    index += 1
                    break
            else:
                raise WorkflowFormatError("invalid-actions-expression")
            result.append(_Token("string", value.casefold()))
        elif character.isalpha() or character == "_":
            end = index + 1
            while end < len(expression) and (expression[end].isalnum() or expression[end] in "_-"):
                end += 1
            result.append(_Token("identifier", expression[index:end].casefold()))
            index = end
        else:
            result.append(_Token("punctuation", character))
            index += 1
    return tuple(result)


def _expressions(text: str) -> tuple[str, ...]:
    """Extract expression bodies using quote-aware closing delimiters."""
    expressions: list[str] = []
    offset = 0
    while True:
        start = text.find("${{", offset)
        if start < 0:
            return tuple(expressions)
        index = start + 3
        quoted = False
        while index < len(text):
            if text[index] == "'":
                if quoted and text[index : index + 2] == "''":
                    index += 2
                    continue
                quoted = not quoted
            elif not quoted and text.startswith("}}", index):
                expressions.append(text[start + 3 : index])
                offset = index + 2
                break
            index += 1
        else:
            raise WorkflowFormatError("invalid-actions-expression")


def _context_path(tokens: tuple[_Token, ...], index: int) -> tuple[tuple[str, ...], int]:
    """Read one constant property path and return its first unconsumed token."""
    path = [tokens[index].value]
    cursor = index + 1
    while cursor < len(tokens):
        if (
            tokens[cursor].kind == "punctuation"
            and tokens[cursor].value == "."
            and cursor + 1 < len(tokens)
            and tokens[cursor + 1].kind == "identifier"
        ):
            path.append(tokens[cursor + 1].value)
            cursor += 2
        elif (
            tokens[cursor].kind == "punctuation"
            and tokens[cursor].value == "["
            and cursor + 2 < len(tokens)
            and tokens[cursor + 1].kind == "string"
            and tokens[cursor + 2].kind == "punctuation"
            and tokens[cursor + 2].value == "]"
        ):
            path.append(tokens[cursor + 1].value)
            cursor += 3
        else:
            break
    return tuple(path), cursor


def expression_context_paths(text: str) -> tuple[tuple[str, ...], ...]:
    """Return context paths from inline expressions, excluding literal strings.

    Dot and constant bracket property access are equivalent. Dynamic access
    retains the known prefix so an unknown event selector cannot appear safe.
    This is bounded lexical analysis, not a GitHub expression evaluator.
    """
    paths: list[tuple[str, ...]] = []
    for expression in _expressions(text):
        tokens = _tokens(expression)
        for index, token in enumerate(tokens):
            if token.kind != "identifier" or token.value not in _CONTEXTS:
                continue
            if index and tokens[index - 1].value == ".":
                continue
            path, _cursor = _context_path(tokens, index)
            paths.append(path)
    return tuple(paths)


def has_untrusted_run_interpolation(text: str) -> bool:
    """Identify direct event, branch-name or input interpolation into a script.

    Known numeric PR/issue identifiers and exact GitHub-provided commit SHA
    paths are excluded. Other event data needs review; no shell data-flow or
    exploitability proof is inferred. Shell quotes and comments do not prevent
    GitHub's earlier expression substitution.
    """
    for path in expression_context_paths(text):
        if path[0] == "inputs":
            return True
        if path == ("github",):
            return True
        if len(path) > 1 and path[0] == "github" and path[1] in {"head_ref", "ref_name"}:
            return True
        if path[:2] == ("github", "event") and path not in _SAFE_EVENT_PATHS:
            return True
    return False


def selects_pull_request_code(text: str) -> bool:
    """Flag PR selectors and dynamic checkout values whose trust is unresolved.

    Parameters
    ----------
    text
        Complete checkout ref or repository input, including literal text.

    Returns
    -------
    bool
        Whether the selector names PR code or needs review because its complete
        value is neither a literal nor one exact trusted context property.

    Notes
    -----
    Functions, operators and composed substitutions remain unresolved even
    when all referenced context properties are trusted. This lexical check
    neither evaluates expressions nor authenticates a hardcoded revision.
    Literal input padding follows the action input reader's ECMAScript trim
    semantics, including no-break spaces and the byte-order mark.

    """
    text = text.strip(_CHECKOUT_INPUT_PADDING)
    expressions = _expressions(text)
    if not expressions:
        return text.casefold().startswith("refs/pull/")
    if len(expressions) != 1 or text != "${{" + expressions[0] + "}}":
        return True
    tokens = _tokens(expressions[0])
    if len(tokens) == 1 and tokens[0].kind == "string":
        return tokens[0].value.strip(_CHECKOUT_INPUT_PADDING).startswith("refs/pull/")
    if not tokens or tokens[0].kind != "identifier":
        return True
    path, cursor = _context_path(tokens, 0)
    return cursor != len(tokens) or path not in _TRUSTED_CHECKOUT_PATHS
