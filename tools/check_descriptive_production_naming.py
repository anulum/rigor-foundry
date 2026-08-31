# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — descriptive production naming guard
"""Reject internal planning identifiers from Git-visible production surfaces."""

from __future__ import annotations

import argparse
import ast
import io
import re
import tokenize
from collections.abc import Sequence
from pathlib import Path

from tools._repository import ROOT, read_text, redacted_guard_exit_code, visible_files

_PRIVATE_ROOTS = (Path(".coordination"), Path("docs/internal"))
_GENERATED_TEXT = {Path("editors/vscode/package-lock.json")}
_PROSE_SUFFIXES = {".md", ".rst", ".txt"}
_SEVERITY_REFERENCE_PATHS = {Path("docs/sarif.md")}
_SEVERITY_CODE = re.compile(r"(?<![A-Za-z0-9_.-])P[0-9](?![A-Za-z0-9_.-])")
_SVG_PATH_DATA = re.compile(r"\s+d=(?P<quote>[\"']).*?(?P=quote)", re.DOTALL)
_TASK_HEADING = re.compile(r"\*\*(?P<code>[^*\n]+?)\s+—")
_TASK_CODE = re.compile(r"[A-Z0-9][A-Z0-9 /_-]{0,63}")

_PLANNING_PATTERNS = (
    (
        "short campaign identifier",
        re.compile(
            r"(?<![A-Za-z0-9_.-])"
            r"(?:A(?:[0-9]|1[0-6])|G[1-8]|M[1-7]|E[1-5]|C[12]|D[12]|R[12])"
            r"(?![A-Za-z0-9_.-])"
        ),
    ),
    (
        "queue or workstream identifier",
        re.compile(
            r"(?<![A-Za-z0-9_.-])"
            r"(?:BL-[0-9]+|WS-[0-9]+|QWC-[0-9]+|CO[0-9]+(?:-[A-Z0-9]+)+|"
            r"K[0-9]+-D[0-9]+)"
            r"(?![A-Za-z0-9_.-])"
        ),
    ),
    (
        "campaign hierarchy identifier",
        re.compile(r"(?<![A-Za-z0-9_.-])MOAT(?:-[A-Z0-9]+)+(?![A-Za-z0-9_.-])"),
    ),
    (
        "CRA campaign stage",
        re.compile(r"(?<![A-Za-z0-9_.-])CRA[ _-]+P[0-9]+(?![A-Za-z0-9_.-])", re.I),
    ),
    (
        "coded CRA identifier",
        re.compile(r"(?<![A-Za-z0-9])cra[_-]?p[0-9]+[A-Za-z0-9_]*", re.I),
    ),
    (
        "coded identifier segment",
        re.compile(
            r"(?<![A-Za-z0-9])(?:[A-Za-z][A-Za-z0-9]*_)*"
            r"[AGEMCDRagemcdr][0-9]{1,2}_[A-Za-z0-9_]+"
        ),
    ),
    (
        "coded camel-case identifier",
        re.compile(r"(?<![A-Za-z0-9])[A-Za-z]+[AGEMCDRP][0-9]{1,2}[A-Z][A-Za-z0-9]*"),
    ),
)


def _is_private(path: Path) -> bool:
    """Return whether a path belongs to an allowed private coordination root."""
    return any(path == root or root in path.parents for root in _PRIVATE_ROOTS)


def _private_task_codes(root: Path) -> tuple[str, ...]:
    """Return task identifiers declared by the optional private TODO registry."""
    registry = root / "docs/internal/TODO.md"
    if not registry.exists():
        return ()
    text = registry.read_text(encoding="utf-8")
    codes = {
        match.group("code").strip()
        for match in _TASK_HEADING.finditer(text)
        if any(character.isdigit() for character in match.group("code"))
        and _TASK_CODE.fullmatch(match.group("code").strip())
    }
    return tuple(sorted(codes, key=lambda code: (-len(code), code)))


def _registry_pattern(
    codes: tuple[str, ...],
    *,
    path_boundary: bool = False,
) -> re.Pattern[str] | None:
    """Compile exact private task codes without exposing them in diagnostics."""
    if not codes:
        return None
    alternatives = "|".join(re.escape(code) for code in codes)
    boundary = "A-Za-z0-9" if path_boundary else "A-Za-z0-9_.-"
    return re.compile(
        rf"(?<![{boundary}])(?:{alternatives})(?![{boundary}])",
        re.I,
    )


def _path_errors(path: Path, registry_pattern: re.Pattern[str] | None) -> list[str]:
    """Return descriptive-naming failures encoded in one visible path."""
    rendered = path.as_posix()
    errors = [
        f"{rendered}: internal planning identifier appears in a production path"
        for _label, pattern in _PLANNING_PATTERNS
        if pattern.search(rendered)
    ]
    if registry_pattern is not None and registry_pattern.search(rendered):
        errors.append(f"{rendered}: private task registry identifier appears in a path")
    return errors


def _python_prose_errors(path: Path, text: str) -> list[str]:
    """Reject campaign-stage severity tokens in Python prose, not exact values."""
    errors: list[str] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            if token.type == tokenize.COMMENT:
                if _SEVERITY_CODE.search(token.string):
                    errors.append(
                        f"{path.as_posix()}:{token.start[0]}: priority code appears in prose"
                    )
                continue
            if token.type != tokenize.STRING:
                continue
            try:
                value = ast.literal_eval(token.string)
            except (SyntaxError, ValueError):
                value = token.string
            if not isinstance(value, str) or not _SEVERITY_CODE.search(value):
                continue
            if re.fullmatch(r"P[0-9]", value):
                continue
            errors.append(f"{path.as_posix()}:{token.start[0]}: priority code appears in prose")
    except (IndentationError, tokenize.TokenError) as exc:
        line = getattr(exc, "lineno", None) or 1
        errors.append(f"{path.as_posix()}:{line}: Python text could not be inspected")
    return errors


def _content_errors(
    path: Path,
    text: str,
    registry_pattern: re.Pattern[str] | None,
) -> list[str]:
    """Return deterministic content failures for one project-authored text file."""
    errors: list[str] = []
    if path.suffix == ".svg":
        text = _SVG_PATH_DATA.sub(' d=""', text)
    for line_number, line in enumerate(text.splitlines(), start=1):
        for label, pattern in _PLANNING_PATTERNS:
            if pattern.search(line):
                errors.append(f"{path.as_posix()}:{line_number}: {label} is public")
        if registry_pattern is not None and registry_pattern.search(line):
            errors.append(
                f"{path.as_posix()}:{line_number}: private task registry identifier is public"
            )
        if (
            path.suffix in _PROSE_SUFFIXES
            and path not in _SEVERITY_REFERENCE_PATHS
            and _SEVERITY_CODE.search(line)
        ):
            errors.append(
                f"{path.as_posix()}:{line_number}: priority code appears in public prose"
            )
    if path.suffix == ".py":
        errors.extend(_python_prose_errors(path, text))
    return errors


def descriptive_naming_errors(root: Path = ROOT) -> list[str]:
    """Return internal planning identifiers exposed by Git-visible surfaces.

    Parameters
    ----------
    root:
        Git worktree whose cached and non-ignored untracked files are inspected.

    Returns
    -------
    list[str]
        Sorted path- and line-bound naming failures.
    """
    errors: list[str] = []
    task_codes = _private_task_codes(root)
    registry_pattern = _registry_pattern(task_codes)
    registry_path_pattern = _registry_pattern(task_codes, path_boundary=True)
    for path in visible_files(root):
        if _is_private(path):
            continue
        errors.extend(_path_errors(path, registry_path_pattern))
        if path in _GENERATED_TEXT:
            continue
        text = read_text(path, root)
        if text is not None:
            errors.extend(_content_errors(path, text, registry_pattern))
    return sorted(set(errors))


def main(argv: Sequence[str] | None = None) -> int:
    """Validate descriptive naming and return a redacted process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args(argv)
    return redacted_guard_exit_code(
        "Descriptive naming guard",
        lambda: descriptive_naming_errors(arguments.root.resolve()),
    )


if __name__ == "__main__":
    raise SystemExit(main())
