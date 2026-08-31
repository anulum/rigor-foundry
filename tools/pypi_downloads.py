# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — atomic PyPI download-series snapshot
"""Record the project's daily PyPI download series in a bounded CSV.

The package name comes from ``pyproject.toml`` unless explicitly supplied. The
snapshot reads pypistats' bounded overall series, validates every retained row,
merges it with older valid history, and atomically replaces the target CSV.
"""

from __future__ import annotations

import argparse
import csv
import http.client
import json
import os
import sys
import tempfile
import time
import tomllib
from collections.abc import Callable, Mapping
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import quote

PYPISTATS_HOST = "pypistats.org"
PYPISTATS_PATH = "/api/packages/{package}/overall"
CATEGORIES = ("without_mirrors", "with_mirrors")
CSV_HEADER = ("date", *CATEGORIES)
OVERALL_FIELDS = frozenset(("data", "package", "type"))
OVERALL_TYPE = "overall_downloads"
ROW_FIELDS = frozenset(("category", "date", "downloads"))
Fetch = Callable[[str], bytes]
Sleep = Callable[[float], None]
DownloadRows = dict[str, dict[str, int]]
PROJECT_PACKAGE = "rigor-foundry"
PROJECT_CSV = Path("downloads/rigor-foundry.csv")
RETRYABLE_STATUSES = (429, 502, 503, 504)
RETRY_DELAYS = (15.0, 30.0, 60.0)


class DownloadSnapshotError(RuntimeError):
    """Report a bounded remote snapshot failure."""


class RetryableSnapshotError(DownloadSnapshotError):
    """Report a transient remote failure eligible for a bounded retry."""


def detect_package(pyproject_path: Path) -> str:
    """Return the normalized distribution name from ``[project].name``."""
    document = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project = document.get("project")
    if not isinstance(project, dict):
        raise ValueError(f"no [project] table in {pyproject_path}")
    raw_name = project.get("name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise ValueError(f"no [project] name in {pyproject_path}")
    return raw_name.strip()


def require_project_csv_target(package: str, csv_path: Path) -> None:
    """Accept only RigorFoundry's exact relative metrics path and package name."""
    if package != PROJECT_PACKAGE:
        raise ValueError(f"project metrics package must be {PROJECT_PACKAGE!r}")
    if csv_path.is_absolute() or csv_path.as_posix() != PROJECT_CSV.as_posix():
        raise ValueError(f"project metrics CSV must be {PROJECT_CSV.as_posix()!r}")


def package_endpoint_path(package: str) -> str:
    """Return the fixed-host pypistats path for ``package``."""
    if not package.strip():
        raise ValueError("package name must not be empty")
    return PYPISTATS_PATH.format(package=quote(package.strip(), safe=""))


def _http_get(package: str) -> bytes:
    """Fetch one pypistats payload over a fixed HTTPS endpoint."""
    connection = http.client.HTTPSConnection(PYPISTATS_HOST, timeout=30)
    try:
        connection.request(
            "GET",
            package_endpoint_path(package),
            headers={"Accept": "application/json", "User-Agent": "rigor-foundry-metrics/1"},
        )
        response = connection.getresponse()
        body = response.read()
        if response.status in RETRYABLE_STATUSES:
            raise RetryableSnapshotError(
                f"pypistats returned transient HTTP {response.status} {response.reason}"
            )
        if response.status != 200:
            raise DownloadSnapshotError(
                f"pypistats returned HTTP {response.status} {response.reason}"
            )
        return body
    except OSError as exc:
        raise RetryableSnapshotError(f"pypistats request failed: {exc}") from exc
    finally:
        connection.close()


def fetch_overall(package: str, fetch: Fetch = _http_get) -> DownloadRows:
    """Fetch and validate one pypistats overall-series payload."""
    try:
        decoded: object = json.loads(fetch(package))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DownloadSnapshotError(f"pypistats returned invalid JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise DownloadSnapshotError("pypistats response must be a JSON object")
    return daily_counts(package, decoded)


def fetch_overall_with_retry(
    package: str,
    fetch: Fetch = _http_get,
    sleep: Sleep = time.sleep,
) -> DownloadRows | None:
    """Retry transient failures within a five-minute worst-case request budget."""
    for delay in (*RETRY_DELAYS, None):
        try:
            return fetch_overall(package, fetch)
        except RetryableSnapshotError:
            if delay is not None:
                sleep(delay)
    return None


def _valid_date(raw_date: object) -> str | None:
    if not isinstance(raw_date, str):
        return None
    candidate = raw_date.strip()
    try:
        parsed = date.fromisoformat(candidate)
    except ValueError:
        return None
    return candidate if parsed.isoformat() == candidate else None


def _valid_count(raw_count: object) -> int | None:
    if isinstance(raw_count, bool):
        return None
    if isinstance(raw_count, int):
        count = raw_count
    elif isinstance(raw_count, str):
        try:
            count = int(raw_count)
        except ValueError:
            return None
    else:
        return None
    return count if count >= 0 else None


def daily_counts(package: str, overall: Mapping[str, Any]) -> DownloadRows:
    """Validate an exact pypistats payload and normalize sparse daily counts."""
    if set(overall) != OVERALL_FIELDS:
        raise DownloadSnapshotError("pypistats response fields do not match the overall schema")
    if overall["package"] != package:
        raise DownloadSnapshotError("pypistats response package does not match the request")
    if overall["type"] != OVERALL_TYPE:
        raise DownloadSnapshotError("pypistats response type is not overall_downloads")
    raw_rows = overall["data"]
    if not isinstance(raw_rows, list):
        raise DownloadSnapshotError("pypistats data must be a JSON array")
    if not raw_rows:
        raise DownloadSnapshotError("pypistats data must not be empty")
    counts: DownloadRows = {}
    for index, raw_row in enumerate(raw_rows):
        if not isinstance(raw_row, dict):
            raise DownloadSnapshotError(f"pypistats row {index} must be a JSON object")
        if set(raw_row) != ROW_FIELDS:
            raise DownloadSnapshotError(
                f"pypistats row {index} fields do not match the overall row schema"
            )
        category = raw_row["category"]
        if category not in CATEGORIES:
            raise DownloadSnapshotError(f"pypistats row {index} has an invalid category")
        row_date = _valid_date(raw_row["date"])
        if row_date is None or row_date != raw_row["date"]:
            raise DownloadSnapshotError(f"pypistats row {index} has an invalid date")
        downloads = raw_row["downloads"]
        if isinstance(downloads, bool) or not isinstance(downloads, int) or downloads < 0:
            raise DownloadSnapshotError(f"pypistats row {index} has an invalid download count")
        day = counts.setdefault(row_date, {})
        if category in day:
            raise DownloadSnapshotError(
                f"pypistats row {index} duplicates {category} for {row_date}"
            )
        day[category] = downloads
    for values in counts.values():
        for category in CATEGORIES:
            values.setdefault(category, 0)
    return counts


def read_csv(path: Path) -> DownloadRows:
    """Read and strictly validate an existing download-series CSV."""
    if not path.exists():
        return {}
    rows: DownloadRows = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != CSV_HEADER:
            raise ValueError(f"unexpected CSV header in {path}")
        for line_number, record in enumerate(reader, start=2):
            row_date = _valid_date(record.get("date"))
            if row_date is None:
                raise ValueError(f"invalid date at {path}:{line_number}")
            if row_date in rows:
                raise ValueError(f"duplicate date {row_date} at {path}:{line_number}")
            values: dict[str, int] = {}
            for category in CATEGORIES:
                count = _valid_count(record.get(category))
                if count is None:
                    raise ValueError(f"invalid {category} count at {path}:{line_number}")
                values[category] = count
            rows[row_date] = values
    return rows


def merge_rows(existing: DownloadRows, fresh: DownloadRows) -> DownloadRows:
    """Upsert fresh counts without mutating either input mapping."""
    merged = {row_date: dict(values) for row_date, values in existing.items()}
    for row_date, values in fresh.items():
        merged.setdefault(row_date, {}).update(values)
    return merged


def write_csv(path: Path, rows: DownloadRows) -> None:
    """Atomically write one date-sorted, schema-fixed download series."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", newline="", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            temporary_path = Path(handle.name)
            writer = csv.writer(handle)
            writer.writerow(CSV_HEADER)
            for row_date in sorted(rows):
                writer.writerow(
                    [row_date, *(rows[row_date].get(category, 0) for category in CATEGORIES)]
                )
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def summary(package: str, rows: DownloadRows) -> str:
    """Return a deterministic one-line latest-day summary."""
    if not rows:
        return f"{package}: no download data available yet"
    latest = max(rows)
    return (
        f"{package}: {len(rows)} days recorded; latest {latest} "
        f"without_mirrors={rows[latest].get('without_mirrors', 0)} "
        f"with_mirrors={rows[latest].get('with_mirrors', 0)}"
    )


def main(
    argv: list[str] | None = None,
    fetch: Fetch = _http_get,
    sleep: Sleep = time.sleep,
) -> int:
    """Resolve, fetch, validate, merge, and persist one snapshot."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pyproject", default="pyproject.toml")
    parser.add_argument("--package")
    parser.add_argument("--csv")
    parser.add_argument("--project-csv-only", action="store_true")
    parser.add_argument("--print-package", action="store_true")
    arguments = parser.parse_args(argv)

    try:
        package = arguments.package or detect_package(Path(arguments.pyproject))
        if arguments.print_package:
            print(package)
            return 0
        if not arguments.csv:
            parser.error("--csv is required unless --print-package is used")
        csv_path = Path(arguments.csv)
        if arguments.project_csv_only:
            require_project_csv_target(package, csv_path)
        fresh_rows = fetch_overall_with_retry(package, fetch, sleep)
        if fresh_rows is None:
            print(
                "snapshot skipped: pypistats remained unavailable after bounded retries; "
                "the next successful rolling-window fetch will backfill it",
                file=sys.stderr,
            )
            return 0
        rows = merge_rows(read_csv(csv_path), fresh_rows)
        write_csv(csv_path, rows)
    except (DownloadSnapshotError, OSError, ValueError) as exc:
        print(f"snapshot failed: {exc}", file=sys.stderr)
        return 1
    print(summary(package, rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
