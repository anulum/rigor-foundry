# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Redaction-safe secret guard
"""Detect explicit credential material without printing candidate values."""

from __future__ import annotations

import re
from pathlib import Path

from tools._repository import ROOT, read_text, visible_files

SKIPPED_PATHS = {Path(".gitleaks.toml"), Path("tools/check_secrets.py")}
RULES = {
    "private-key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "credential-url": re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", re.IGNORECASE),
    "credential-assignment": re.compile(
        r"(?im)^\s*(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\s*[:=]\s*[\"']?([^\s\"']{8,})"
    ),
}
REFERENCE_MARKERS = ("${{ secrets.", "${", "$ENV", "secret-provider", "example", "redacted")


def secret_errors(root: Path = ROOT) -> list[str]:
    """Return rule identifiers and paths, never candidate secret values."""
    errors: list[str] = []
    for path in visible_files(root):
        if path in SKIPPED_PATHS or path.parts[:2] == ("docs", "assets"):
            continue
        text = read_text(path, root)
        if text is None:
            continue
        for rule_id, pattern in RULES.items():
            for match in pattern.finditer(text):
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                line = text[line_start : None if line_end == -1 else line_end]
                if any(marker.lower() in line.lower() for marker in REFERENCE_MARKERS):
                    continue
                line_number = text.count("\n", 0, match.start()) + 1
                errors.append(f"{path.as_posix()}:{line_number}: {rule_id}")
    return errors


def main() -> int:
    """Scan visible files and return a process exit code."""
    errors = secret_errors()
    if errors:
        print("Secret guard failed; candidate values are intentionally redacted:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Secret guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
