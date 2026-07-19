# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — built-in adapter profile benchmark
"""Measure real Semgrep, Trivy, and offline OSV execution through Bubblewrap."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import statistics
import subprocess  # nosec B404
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from rigor_foundry.adapters import run_adapter
from rigor_foundry.models import AdapterSpec
from rigor_foundry.osv_database import OSVDatabaseArchive, OSVDatabaseManifest

_GIT = "/usr/bin/git"


def _git(root: Path, *arguments: str) -> None:
    """Run one deterministic Git fixture command."""
    subprocess.run(  # nosec B603
        (_GIT, "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        env={
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
        },
    )


def _osv_archive() -> bytes:
    """Return one deterministic, non-matching PyPI advisory database."""
    vulnerability = {
        "id": "OSV-BENCHMARK-1",
        "modified": "2026-07-19T00:00:00Z",
        "published": "2026-07-19T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "different-package"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2"}],
                    }
                ],
            }
        ],
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("OSV-BENCHMARK-1.json", date_time=(2026, 7, 19, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(
            info,
            json.dumps(vulnerability, sort_keys=True, separators=(",", ":")),
        )
    return output.getvalue()


def _write_fixture(root: Path, database_root: Path) -> None:
    """Create one committed multi-language benchmark repository."""
    root.mkdir()
    _git(root, "init", "--quiet")
    _git(root, "config", "user.name", "Rigor Benchmark")
    _git(root, "config", "user.email", "benchmark@example.invalid")
    (root / "config").mkdir()
    (root / "src").mkdir()
    (root / "infra").mkdir()
    (root / "config" / "semgrep.yml").write_text(
        "rules:\n"
        "  - id: no-eval\n"
        "    languages: [python]\n"
        "    message: dynamic evaluation\n"
        "    severity: ERROR\n"
        "    pattern: eval(...)\n",
        encoding="utf-8",
    )
    (root / "config" / "trivy.yml").write_text(
        "format: json\nexit-code: 1\n",
        encoding="utf-8",
    )
    database_payload = _osv_archive()
    database = database_root / "osv-scanner" / "PyPI" / "all.zip"
    database.parent.mkdir(parents=True)
    database.write_bytes(database_payload)
    manifest = OSVDatabaseManifest.build(
        (
            OSVDatabaseArchive(
                ecosystem="PyPI",
                archive_sha256=hashlib.sha256(database_payload).hexdigest(),
                archive_bytes=len(database_payload),
            ),
        )
    )
    (root / "config" / "osv-database.json").write_text(
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("urllib3==1.26.0\n", encoding="utf-8")
    (root / "src" / "safe.py").write_text(
        "def add(left: int, right: int) -> int:\n    return left + right\n",
        encoding="utf-8",
    )
    (root / "src" / "safe.rs").write_text(
        "pub fn add(left: i64, right: i64) -> i64 { left + right }\n",
        encoding="utf-8",
    )
    (root / "infra" / "Dockerfile").write_text(
        "FROM alpine:3.20\nUSER 1000\n",
        encoding="utf-8",
    )
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "benchmark fixture")


def _spec(profile: str) -> AdapterSpec:
    """Return one canonical built-in profile specification."""
    semgrep = profile.startswith("semgrep")
    osv = profile.startswith("osv")
    configuration = (
        "config/semgrep.yml"
        if semgrep
        else "config/osv-database.json"
        if osv
        else "config/trivy.yml"
    )
    return AdapterSpec.from_dict(
        {
            "name": profile,
            "profile": profile,
            "configuration_path": configuration,
            "target_paths": ["src" if semgrep else "requirements.txt" if osv else "infra"],
            "timeout_seconds": 120,
            "scope": "full",
            "working_directory": ".",
            "required": True,
        },
        0,
    )


def _summary(samples: list[float]) -> dict[str, float]:
    """Return bounded descriptive timing statistics in milliseconds."""
    milliseconds = [sample * 1000 for sample in samples]
    return {
        "minimum_ms": round(min(milliseconds), 3),
        "median_ms": round(statistics.median(milliseconds), 3),
        "maximum_ms": round(max(milliseconds), 3),
    }


def run_benchmark(iterations: int) -> dict[str, object]:
    """Run all real profiles and return machine-readable measurements."""
    if iterations < 1 or iterations > 20:
        raise ValueError("iterations must be between 1 and 20")
    profiles = (
        "osv-lockfile-offline-json-v1",
        "semgrep-local-json-v1",
        "trivy-repository-json-v1",
    )
    samples: dict[str, list[float]] = {profile: [] for profile in profiles}
    versions: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="rigor-adapter-benchmark-") as directory:
        repository = Path(directory) / "repository"
        database_root = Path(directory) / "osv-database"
        _write_fixture(repository, database_root)
        previous_database = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")
        os.environ["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(database_root)
        try:
            for profile in profiles:
                spec = _spec(profile)
                for _ in range(iterations):
                    started = time.perf_counter()
                    result = run_adapter(repository, spec, trusted=True)
                    samples[profile].append(time.perf_counter() - started)
                    if not result.complete or result.profile_evidence is None:
                        raise RuntimeError(f"benchmark profile was incomplete: {profile}")
                    versions[profile] = result.profile_evidence.tool_version
        finally:
            if previous_database is None:
                os.environ.pop("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", None)
            else:
                os.environ["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = previous_database
    return {
        "schema_version": "1.0",
        "benchmark": "built-in-adapter-profiles",
        "iterations_per_profile": iterations,
        "isolation": "non-isolated-workstation",
        "logical_cpu_count": os.cpu_count(),
        "machine": platform.machine(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "fixture": {
            "tracked_files": 7,
            "target_files": 4,
            "languages": ["dockerfile", "python", "requirements", "rust"],
        },
        "profiles": {
            profile: {"tool_version": versions[profile], **_summary(samples[profile])}
            for profile in profiles
        },
    }


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark CLI and print canonical JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=3)
    arguments = parser.parse_args(argv)
    result = run_benchmark(arguments.iterations)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
