# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — a deterministic repository of tracked lockfiles for integration tests
"""Build one real Git repository whose tracked lockfiles exercise every class and refusal.

Every npm lockfile is the clean ``lockfileVersion`` 3 fixture that npm 10.9.2 generated, after
the recorded edit named beside it here, and ``yarn.lock`` is yarn 1.22.22's own output: the edits keep a few entries and change one field each.
Commit dates and identity are fixed, so the commit, its tree and every digest are reproducible.
Run this module to rewrite the golden report ``tests/fixtures/lockfiles/report-golden.json``.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from repository_audit_git_repository import GitRepository

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lockfiles"
V1 = FIXTURES / "npm-6.14.18-v1" / "package-lock.json.gz"
V3 = FIXTURES / "npm-10.9.2-v3" / "package-lock.json.gz"
YARN1 = FIXTURES / "yarn-1.22.22-v1" / "yarn.lock.gz"
GOLDEN = FIXTURES / "report-golden.json"
COMMIT_DATE = "2026-11-25T00:00:00Z"
SHA1 = "sha1-" + base64.b64encode(hashlib.sha1(b"x", usedforsecurity=False).digest()).decode()
KEPT = (
    "",
    "local-lib",
    "node_modules/bundle-dependencies",
    "node_modules/bundle-dependencies/node_modules/yargs",
    "node_modules/debug",
    "node_modules/is-number",
    "node_modules/local-lib",
    "node_modules/ms",
)


def fixture_text(path: Path) -> str:
    """Return the text npm wrote, from its gzip-compressed fixture.

    Parameters
    ----------
    path : Path
        A ``package-lock.json.gz`` fixture.

    Returns
    -------
    str
        The decompressed UTF-8 text.
    """
    return gzip.decompress(path.read_bytes()).decode("utf-8")


def _reduced_v3() -> dict[str, Any]:
    """Return the clean version 3 fixture with only the kept entries (recorded edit)."""
    document: dict[str, Any] = json.loads(fixture_text(V3))
    document["packages"] = {key: document["packages"][key] for key in KEPT}
    return document


def _dump(document: dict[str, Any]) -> str:
    """Write a document as npm writes it."""
    return json.dumps(document, indent=2) + "\n"


def _findings_lockfile() -> str:
    """Return a reduced fixture where each kept entry carries one recorded defect."""
    document = _reduced_v3()
    packages = document["packages"]
    del packages["node_modules/ms"]["integrity"]  # missing-digest
    packages["node_modules/debug"]["integrity"] = SHA1  # weak-digest
    packages["node_modules/debug"]["resolved"] = "https://evil.example/debug-4.3.4.tgz"
    packages["node_modules/is-number"]["resolved"] = "github:jonschlinkert/is-number#main"
    packages["node_modules/local-lib"]["resolved"] = "../../outside"  # path escape from web/
    packages["node_modules/bundle-dependencies"]["integrity"] += " sha512-!!!"  # malformed
    packages["node_modules/odd"] = {"version": "1.0.0", "resolved": "ftp://mirror.example/odd.tgz"}
    return _dump(document)


@contextmanager
def _fixed_commit_dates() -> Iterator[None]:
    """Fix Git's author and committer dates while the repository is committed."""
    names = ("GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE")
    saved = {name: os.environ.get(name) for name in names}
    os.environ.update(dict.fromkeys(names, COMMIT_DATE))
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def build_lockfile_repository(root: Path) -> GitRepository:
    """Create and commit the deterministic lockfile repository at ``root``.

    Parameters
    ----------
    root : Path
        A path that does not exist yet.

    Returns
    -------
    GitRepository
        The committed repository.
    """
    repository = GitRepository.create(root)
    repository.write_text("package-lock.json", _dump(_reduced_v3()))
    repository.write_text("web/package-lock.json", _findings_lockfile())
    repository.write_text("web/.npmrc", "@acme:registry=https://acme.example/\n")
    repository.write_text("env/package-lock.json", _dump(_reduced_v3()))
    repository.write_text("env/.npmrc", "registry=${NPM_REGISTRY}\n")
    repository.write_text("legacy/npm-shrinkwrap.json", fixture_text(V1))
    repository.write_text("yarn.lock", fixture_text(YARN1))
    repository.write_text("tools/yarn.lock", 'left-pad@^1.3.0:\n  version "1.3.0"\n')
    repository.write_text("empty/yarn.lock", "")
    repository.write_text("crates/Cargo.lock", "version = 4\n")
    repository.write_bytes("bin/package-lock.json", b"{\0}")
    repository.write_text("old/package-lock.json", '{"lockfileVersion": 4}\n')
    with _fixed_commit_dates():
        repository.commit()
    return repository


def render_report_golden(root: Path) -> str:
    """Return the golden report text for a repository built at ``root``.

    Parameters
    ----------
    root : Path
        A path that does not exist yet.

    Returns
    -------
    str
        The report as pretty, key-sorted JSON with a final newline.
    """
    from rigor_foundry.git_inventory import load_git_inventory
    from rigor_foundry.lockfile_report import lockfile_integrity_report

    repository = build_lockfile_repository(root)
    report = lockfile_integrity_report(load_git_inventory(repository.root))
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory(prefix="rigor-lockfile-golden-") as scratch:
        GOLDEN.write_text(render_report_golden(Path(scratch) / "repository"), encoding="utf-8")
    sys.stdout.write(f"wrote {GOLDEN}\n")
