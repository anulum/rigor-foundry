# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — tests for the bounded PyPI metrics branch snapshot

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_MODULE_PATH = _ROOT / "tools" / "pypi_downloads.py"
_SPEC = importlib.util.spec_from_file_location("pypi_downloads", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
downloads = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(downloads)

_SAMPLE: dict[str, Any] = {
    "data": [
        {"category": "without_mirrors", "date": "2026-07-17", "downloads": 11},
        {"category": "with_mirrors", "date": "2026-07-17", "downloads": 19},
        {"category": "without_mirrors", "date": "2026-07-18", "downloads": 13},
        {"category": "with_mirrors", "date": "2026-07-18", "downloads": 23},
    ],
    "package": "rigor-foundry",
    "type": "overall_downloads",
}


def test_detect_package_reads_real_project_contract(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "rigor-foundry"\n', encoding="utf-8")
    assert downloads.detect_package(pyproject) == "rigor-foundry"


@pytest.mark.parametrize(
    "document, message",
    [
        ("[build-system]\nrequires = []\n", "no [project] table"),
        ('[project]\nversion = "1"\n', "no [project] name"),
        ('[project]\nname = ""\n', "no [project] name"),
    ],
)
def test_detect_package_rejects_missing_identity(
    tmp_path: Path, document: str, message: str
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(document, encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape(message)):
        downloads.detect_package(pyproject)


def test_package_endpoint_encodes_untrusted_path_characters() -> None:
    assert downloads.package_endpoint_path("package/name") == (
        "/api/packages/package%2Fname/overall"
    )
    with pytest.raises(ValueError, match="must not be empty"):
        downloads.package_endpoint_path("  ")


def test_fetch_overall_decodes_object_payload() -> None:
    payload = json.dumps(_SAMPLE).encode()
    assert downloads.fetch_overall("rigor-foundry", lambda package: payload)["package"] == (
        "rigor-foundry"
    )


@pytest.mark.parametrize("payload", [b"not-json", b"[]", b"null"])
def test_fetch_overall_rejects_invalid_contract(payload: bytes) -> None:
    with pytest.raises(downloads.DownloadSnapshotError):
        downloads.fetch_overall("rigor-foundry", lambda package: payload)


def test_daily_counts_keeps_only_valid_categories_dates_and_counts() -> None:
    payload: dict[str, Any] = {
        "data": [
            *_SAMPLE["data"],
            None,
            {"category": "unknown", "date": "2026-07-18", "downloads": 1},
            {"category": "with_mirrors", "date": "not-a-date", "downloads": 1},
            {"category": "with_mirrors", "date": "2026-07-18", "downloads": -1},
            {"category": "with_mirrors", "date": "2026-07-18", "downloads": True},
            {"category": "with_mirrors", "date": "2026-07-19", "downloads": "29"},
        ]
    }
    assert downloads.daily_counts(payload) == {
        "2026-07-17": {"without_mirrors": 11, "with_mirrors": 19},
        "2026-07-18": {"without_mirrors": 13, "with_mirrors": 23},
        "2026-07-19": {"with_mirrors": 29},
    }
    assert downloads.daily_counts({"data": "not-a-list"}) == {}


def test_csv_roundtrip_is_date_sorted_and_schema_fixed(tmp_path: Path) -> None:
    csv_path = tmp_path / "downloads" / "rigor-foundry.csv"
    rows = {
        "2026-07-18": {"without_mirrors": 13, "with_mirrors": 23},
        "2026-07-17": {"without_mirrors": 11, "with_mirrors": 19},
    }
    assert downloads.read_csv(csv_path) == {}
    downloads.write_csv(csv_path, rows)
    assert csv_path.read_text(encoding="utf-8").splitlines() == [
        "date,without_mirrors,with_mirrors",
        "2026-07-17,11,19",
        "2026-07-18,13,23",
    ]
    assert downloads.read_csv(csv_path) == rows


@pytest.mark.parametrize(
    "csv_text, message",
    [
        ("date,with_mirrors\n2026-07-18,2\n", "unexpected CSV header"),
        (
            "date,without_mirrors,with_mirrors\nnot-a-date,1,2\n",
            "invalid date",
        ),
        (
            "date,without_mirrors,with_mirrors\n2026-07-18,1,2\n2026-07-18,3,4\n",
            "duplicate date",
        ),
        (
            "date,without_mirrors,with_mirrors\n2026-07-18,-1,2\n",
            "invalid without_mirrors count",
        ),
    ],
)
def test_read_csv_rejects_corrupted_history(tmp_path: Path, csv_text: str, message: str) -> None:
    csv_path = tmp_path / "series.csv"
    csv_path.write_text(csv_text, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        downloads.read_csv(csv_path)


def test_write_csv_real_replace_failure_preserves_destination(tmp_path: Path) -> None:
    csv_path = tmp_path / "series.csv"
    csv_path.mkdir()
    marker = csv_path / "trusted-history"
    marker.write_text("preserved\n", encoding="utf-8")

    with pytest.raises(OSError):
        downloads.write_csv(
            csv_path,
            {"2026-07-18": {"without_mirrors": 1, "with_mirrors": 2}},
        )
    assert marker.read_text(encoding="utf-8") == "preserved\n"
    assert list(tmp_path.iterdir()) == [csv_path]


def test_merge_rows_upserts_without_mutating_inputs() -> None:
    existing = {"2026-07-17": {"without_mirrors": 11, "with_mirrors": 19}}
    fresh = {
        "2026-07-17": {"without_mirrors": 12},
        "2026-07-18": {"without_mirrors": 13, "with_mirrors": 23},
    }
    merged = downloads.merge_rows(existing, fresh)
    assert merged["2026-07-17"] == {"without_mirrors": 12, "with_mirrors": 19}
    assert merged["2026-07-18"] == fresh["2026-07-18"]
    assert existing["2026-07-17"]["without_mirrors"] == 11


def test_main_prints_package_from_real_pyproject(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "rigor-foundry"\n', encoding="utf-8")
    assert downloads.main(["--pyproject", str(pyproject), "--print-package"]) == 0
    assert capsys.readouterr().out.strip() == "rigor-foundry"


def test_main_upserts_real_csv_and_reports_latest_day(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    csv_path = tmp_path / "downloads" / "rigor-foundry.csv"
    downloads.write_csv(
        csv_path,
        {"2026-07-16": {"without_mirrors": 7, "with_mirrors": 9}},
    )
    payload = json.dumps(_SAMPLE).encode()
    assert (
        downloads.main(
            ["--package", "rigor-foundry", "--csv", str(csv_path)],
            lambda package: payload,
        )
        == 0
    )
    assert set(downloads.read_csv(csv_path)) == {
        "2026-07-16",
        "2026-07-17",
        "2026-07-18",
    }
    assert "latest 2026-07-18" in capsys.readouterr().out


def test_main_failure_keeps_existing_series(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    csv_path = tmp_path / "series.csv"
    original = "date,without_mirrors,with_mirrors\n2026-07-16,7,9\n"
    csv_path.write_text(original, encoding="utf-8")

    def fail_fetch(package: str) -> bytes:
        raise downloads.DownloadSnapshotError("offline")

    assert downloads.main(["--package", "rigor-foundry", "--csv", str(csv_path)], fail_fetch) == 1
    assert csv_path.read_text(encoding="utf-8") == original
    assert "snapshot failed: offline" in capsys.readouterr().err


def test_main_requires_csv_when_not_printing() -> None:
    with pytest.raises(SystemExit):
        downloads.main(["--package", "rigor-foundry"])


def test_workflow_has_one_bounded_writer_and_hash_pinned_actions() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "pypi-downloads.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in workflow
    assert "permissions:\n      contents: write" in workflow
    assert "cancel-in-progress: false" in workflow
    assert 'test "${#tracked_paths[@]}" -eq 1' in workflow
    assert 'test "${tracked_paths[0]}" = "$csv_path"' in workflow
    assert "persist-credentials: false" in workflow
    assert "GIT_ASKPASS" in workflow
    assert "x-access-token" not in workflow
    assert "secrets." not in workflow
    action_refs = re.findall(r"uses: [^@\n]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_refs)
