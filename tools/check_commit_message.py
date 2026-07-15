# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Commit attribution guard
"""Validate conventional subjects and vendor-neutral agent attribution."""

from __future__ import annotations

import re
import sys
from pathlib import Path

AUTHORSHIP = "Authored by Anulum Fortis & Arcane Sapience (protoscience@anulum.li)"
CONVENTIONAL = re.compile(
    r"^(?:build|chore|ci|docs|feat|fix|perf|refactor|revert|security|style|test)(?:\([a-z0-9._/-]+\))?!?: .+"
)
SEAT = re.compile(r"^Seat:\s*([A-Za-z0-9-]+)\s*$", re.MULTILINE)
_IDENTITIES = (
    "co" + "dex",
    "open" + "ai",
    "chat" + "gpt",
    "clau" + "de",
    "anthro" + "pic",
    "gr" + "ok",
    "x" + "ai",
)
FORBIDDEN_IDENTITIES = re.compile(
    rf"\b(?:{'|'.join(re.escape(identity) for identity in _IDENTITIES)})\b",
    re.IGNORECASE,
)


def commit_message_errors(message: str) -> list[str]:
    """Return policy failures for one proposed commit message."""
    errors: list[str] = []
    subject = message.splitlines()[0] if message.splitlines() else ""
    if not CONVENTIONAL.fullmatch(subject):
        errors.append("subject must use a supported Conventional Commits prefix")
    if len(subject) > 72:
        errors.append("subject exceeds 72 characters")
    if FORBIDDEN_IDENTITIES.search(message):
        errors.append("public commit message contains a vendor or model identity")

    seats = SEAT.findall(message)
    authorship_count = sum(line.strip() == AUTHORSHIP for line in message.splitlines())
    if authorship_count or seats:
        if authorship_count != 1:
            errors.append("agent-assisted commits require exactly one canonical authorship line")
        if len(seats) != 1:
            errors.append("agent-assisted commits require exactly one Seat trailer")
        elif not re.fullmatch(r"[A-Za-z0-9]{4,12}", seats[0]):
            errors.append("Seat trailer must contain only the alphanumeric seat suffix")
    return errors


def main(argv: list[str] | None = None) -> int:
    """Validate the commit message file supplied by Git."""
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: python -m tools.check_commit_message <commit-message-file>")
        return 2
    message = Path(arguments[0]).read_text(encoding="utf-8")
    errors = commit_message_errors(message)
    if errors:
        print("Commit message guard failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
