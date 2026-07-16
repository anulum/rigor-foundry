# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — SPDX header guard
"""Require the seven-line Apache-2.0 identity header on comment-capable files."""

from __future__ import annotations

from pathlib import Path

from tools._repository import ROOT, read_text, redacted_guard_exit_code, visible_files

SPDX_HEADER = "".join(("# SPDX-License-", "Identifier: Apache-2.0"))
HEADER_LINES = (
    SPDX_HEADER,
    "# Apache License 2.0; see LICENSE.",
    "# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.",
    "# © Code 2020–2026 Miroslav Šotek. All rights reserved.",
    "# ORCID: 0009-0009-3560-0851",
    "# Contact: www.anulum.li | protoscience@anulum.li",
)
HEADER_TITLE_PREFIX = "# RigorFoundry — "
COMMENT_SUFFIXES = {".cff", ".py", ".toml", ".yaml", ".yml"}
COMMENT_NAMES = {
    ".dockerignore",
    ".editorconfig",
    ".gitattributes",
    ".gitignore",
    "Dockerfile",
    "Makefile",
    "requirements-dev.txt",
    "requirements.txt",
}


def needs_header(path: Path) -> bool:
    """Return whether ``path`` supports and requires the direct header."""
    return path.suffix in COMMENT_SUFFIXES or path.name in COMMENT_NAMES


def header_errors(root: Path = ROOT) -> list[str]:
    """Return deterministic header failures for Git-visible files."""
    errors: list[str] = []
    for path in visible_files(root):
        if not needs_header(path):
            continue
        text = read_text(path, root)
        if text is None:
            errors.append(f"{path.as_posix()}: expected text header")
            continue
        lines = tuple(text.splitlines()[: len(HEADER_LINES) + 1])
        common = lines[: len(HEADER_LINES)]
        title = lines[len(HEADER_LINES)] if len(lines) > len(HEADER_LINES) else ""
        if (
            common != HEADER_LINES
            or not title.startswith(HEADER_TITLE_PREFIX)
            or not title.removeprefix(HEADER_TITLE_PREFIX).strip()
        ):
            errors.append(f"{path.as_posix()}: missing canonical Apache-2.0 header")
    return errors


def main() -> int:
    """Validate direct headers and return a process exit code."""
    return redacted_guard_exit_code("Header guard", header_errors)


if __name__ == "__main__":
    raise SystemExit(main())
