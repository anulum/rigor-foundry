# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the lockfile integrity report record
"""Record every tracked lockfile's classification as one digest-bound report.

The report ``rigor.lockfile-integrity-report.v1`` binds the commit, its tree, the tracked
content digest and the rule pack, then lists every tracked lockfile in path order with its
entries in line, then key, order. ``report_digest`` is the SHA-256 of the canonical JSON of
the report without that field. The report holds no floating-point number and only fixed
ASCII member names, so that canonical JSON is the RFC 8785 serialisation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .audit_primitives import canonical_digest
from .git_inventory import GitInventory
from .lockfile_integrity import assess_lockfiles
from .lockfile_model import ENTRY_CLASSES, ENTRY_FINDINGS, REFUSAL_REASONS, LockfileResult
from .rules import RULE_PACK_VERSION, rule_pack_digest

LOCKFILE_REPORT_SCHEMA: Final = "rigor.lockfile-integrity-report.v1"


@dataclass(frozen=True)
class LockfileIntegrityReport:
    """The classification of every tracked lockfile of one repository state.

    Parameters
    ----------
    head : str
        The commit the inventory was read at.
    head_tree : str
        That commit's tree.
    tracked_content_digest : str
        The digest of the tracked content that was read.
    rule_pack_version : str
        The built-in rule pack the rules belong to.
    rule_pack_digest : str
        That rule pack's identity.
    files : tuple[LockfileResult, ...]
        One result per tracked lockfile, ordered by path.
    """

    head: str
    head_tree: str
    tracked_content_digest: str
    rule_pack_version: str
    rule_pack_digest: str
    files: tuple[LockfileResult, ...]

    def __post_init__(self) -> None:
        """Refuse files out of path order, or listed twice."""
        paths = [result.path for result in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("report files are unique and ordered by path")

    def summary(self) -> dict[str, object]:
        """Return the counts of files, entries, classes, findings and refusals.

        Returns
        -------
        dict[str, object]
            Every class, finding and refusal reason with its count, zeros included. Entry
            counts include bundled entries, which repeat their ancestor's findings.
        """
        entries = [entry for result in self.files for entry in result.entries]
        return {
            "files": len(self.files),
            "classified_files": sum(result.status == "classified" for result in self.files),
            "refused_files": sum(result.status == "refused" for result in self.files),
            "entries": len(entries),
            "classes": {
                name: sum(entry.entry_class == name for entry in entries) for name in ENTRY_CLASSES
            },
            "findings": {
                name: sum(name in entry.findings for entry in entries) for name in ENTRY_FINDINGS
            },
            "refusals": {
                name: sum(result.refusal_reason == name for result in self.files)
                for name in REFUSAL_REASONS
            },
        }

    def body(self) -> dict[str, object]:
        """Return the report without its digest."""
        return {
            "schema": LOCKFILE_REPORT_SCHEMA,
            "head": self.head,
            "head_tree": self.head_tree,
            "tracked_content_digest": self.tracked_content_digest,
            "rule_pack_version": self.rule_pack_version,
            "rule_pack_digest": self.rule_pack_digest,
            "summary": self.summary(),
            "files": [result.to_dict() for result in self.files],
        }

    @property
    def report_digest(self) -> str:
        """Return the SHA-256 of the canonical JSON of the report without this field."""
        return canonical_digest(self.body())

    def to_dict(self) -> dict[str, object]:
        """Return the complete report, digest included."""
        return {**self.body(), "report_digest": self.report_digest}

    def render_text(self) -> str:
        """Return a short human summary, one line per finding of a recorded entry.

        Returns
        -------
        str
            The summary; bundled entries are counted but not listed.
        """
        summary = self.summary()
        lines = [
            f"lockfile integrity: {summary['files']} lockfiles, "
            f"{summary['classified_files']} classified, {summary['refused_files']} refused, "
            f"{summary['entries']} entries",
        ]
        for result in self.files:
            if result.refusal_reason is not None:
                lines.append(f"{result.path}: refused ({result.refusal_reason})")
                continue
            for entry in result.entries:
                if entry.findings and entry.inherited_from is None:
                    findings = ", ".join(entry.findings)
                    lines.append(
                        f"{result.path}:{entry.line}: {entry.key} {entry.entry_class} ({findings})"
                    )
        lines.append(f"report_digest {self.report_digest}")
        return "\n".join(lines) + "\n"


def lockfile_integrity_report(inventory: GitInventory) -> LockfileIntegrityReport:
    """Classify every tracked lockfile of one repository state into a report.

    Parameters
    ----------
    inventory : GitInventory
        The tracked repository content.

    Returns
    -------
    LockfileIntegrityReport
        The report, bound to the inventory and the built-in rule pack.
    """
    return LockfileIntegrityReport(
        head=inventory.head,
        head_tree=inventory.head_tree,
        tracked_content_digest=inventory.tracked_content_digest,
        rule_pack_version=RULE_PACK_VERSION,
        rule_pack_digest=rule_pack_digest(),
        files=assess_lockfiles(inventory),
    )
