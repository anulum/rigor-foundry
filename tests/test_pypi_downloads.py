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


def test_project_writer_rejects_every_alternate_target_before_fetch(
    tmp_path: Path,
) -> None:
    """The privileged writer must freeze package and lexical CSV path."""
    downloads.require_project_csv_target("rigor-foundry", Path("downloads/rigor-foundry.csv"))
    for package, csv_path in (
        ("other", Path("downloads/rigor-foundry.csv")),
        ("rigor-foundry", Path("downloads/other.csv")),
        ("rigor-foundry", Path("downloads/../downloads/rigor-foundry.csv")),
        ("rigor-foundry", tmp_path / "downloads/rigor-foundry.csv"),
    ):
        with pytest.raises(ValueError, match="project metrics"):
            downloads.require_project_csv_target(package, csv_path)

    fetched = False

    def unexpected_fetch(package: str) -> bytes:
        nonlocal fetched
        fetched = True
        return b"{}"

    assert (
        downloads.main(
            [
                "--package",
                "other",
                "--csv",
                "downloads/rigor-foundry.csv",
                "--project-csv-only",
            ],
            unexpected_fetch,
        )
        == 1
    )
    assert not fetched


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
    assert downloads.fetch_overall("rigor-foundry", lambda package: payload) == {
        "2026-07-17": {"without_mirrors": 11, "with_mirrors": 19},
        "2026-07-18": {"without_mirrors": 13, "with_mirrors": 23},
    }


@pytest.mark.parametrize("payload", [b"not-json", b"[]", b"null"])
def test_fetch_overall_rejects_invalid_contract(payload: bytes) -> None:
    with pytest.raises(downloads.DownloadSnapshotError):
        downloads.fetch_overall("rigor-foundry", lambda package: payload)


@pytest.mark.parametrize(
    "payload",
    [
        {**_SAMPLE, "package": "other"},
        {**_SAMPLE, "type": "recent_downloads"},
        {**_SAMPLE, "extra": None},
        {"data": _SAMPLE["data"], "package": "rigor-foundry"},
        {**_SAMPLE, "data": "not-a-list"},
        {**_SAMPLE, "data": []},
        {**_SAMPLE, "data": [None]},
        {
            **_SAMPLE,
            "data": [
                {"category": "without_mirrors", "date": "2026-07-17", "downloads": 11, "x": 1}
            ],
        },
        {
            **_SAMPLE,
            "data": [{"category": "unknown", "date": "2026-07-17", "downloads": 11}],
        },
        {
            **_SAMPLE,
            "data": [{"category": "without_mirrors", "date": "not-a-date", "downloads": 11}],
        },
        {
            **_SAMPLE,
            "data": [{"category": "without_mirrors", "date": "2026-07-17", "downloads": "11"}],
        },
        {
            **_SAMPLE,
            "data": [{"category": "without_mirrors", "date": "2026-07-17", "downloads": True}],
        },
        {
            **_SAMPLE,
            "data": [{"category": "without_mirrors", "date": "2026-07-17", "downloads": -1}],
        },
        {
            **_SAMPLE,
            "data": [
                {"category": "without_mirrors", "date": "2026-07-17", "downloads": 11},
                {"category": "without_mirrors", "date": "2026-07-17", "downloads": 12},
            ],
        },
        {
            **_SAMPLE,
            "data": [{"category": "without_mirrors", "date": "2026-07-17", "downloads": 11}],
        },
    ],
)
def test_fetch_overall_rejects_remote_schema_drift(payload: dict[str, Any]) -> None:
    with pytest.raises(downloads.DownloadSnapshotError):
        downloads.fetch_overall("rigor-foundry", lambda package: json.dumps(payload).encode())


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


def test_main_rejects_partial_remote_series_before_replacement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    csv_path = tmp_path / "series.csv"
    original = "date,without_mirrors,with_mirrors\n2026-07-16,7,9\n"
    csv_path.write_text(original, encoding="utf-8")
    partial = {
        **_SAMPLE,
        "data": [{"category": "without_mirrors", "date": "2026-07-17", "downloads": 11}],
    }

    assert (
        downloads.main(
            ["--package", "rigor-foundry", "--csv", str(csv_path)],
            lambda package: json.dumps(partial).encode(),
        )
        == 1
    )
    assert csv_path.read_text(encoding="utf-8") == original
    assert "incomplete categories" in capsys.readouterr().err


def test_transient_failures_retry_then_soft_skip(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Shared-runner throttles retry finitely and never corrupt history."""
    calls = 0
    waits: list[float] = []

    def recover(package: str) -> bytes:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise downloads.RetryableSnapshotError("busy")
        return json.dumps(_SAMPLE).encode()

    result = downloads.fetch_overall_with_retry("rigor-foundry", recover, waits.append)
    assert result == {
        "2026-07-17": {"without_mirrors": 11, "with_mirrors": 19},
        "2026-07-18": {"without_mirrors": 13, "with_mirrors": 23},
    }
    assert waits == [15.0, 30.0]

    csv_path = tmp_path / "downloads/rigor-foundry.csv"
    downloads.write_csv(csv_path, {"2026-07-16": {"without_mirrors": 7, "with_mirrors": 9}})

    def unavailable(package: str) -> bytes:
        raise downloads.RetryableSnapshotError("busy")

    assert (
        downloads.main(
            ["--package", "rigor-foundry", "--csv", str(csv_path)],
            unavailable,
            waits.append,
        )
        == 0
    )
    assert "snapshot skipped" in capsys.readouterr().err
    assert downloads.read_csv(csv_path) == {
        "2026-07-16": {"without_mirrors": 7, "with_mirrors": 9}
    }


def test_main_requires_csv_when_not_printing() -> None:
    with pytest.raises(SystemExit):
        downloads.main(["--package", "rigor-foundry"])


def test_workflow_has_one_bounded_writer_and_hash_pinned_actions() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "pypi-downloads.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in workflow
    assert "permissions:\n      contents: write" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert 'readonly package="rigor-foundry"' in workflow
    assert 'readonly csv_path="downloads/rigor-foundry.csv"' in workflow
    assert "--project-csv-only" in workflow
    assert 'test "${#tracked_paths[@]}" -eq 1' in workflow
    assert 'test "${tracked_paths[0]}" = "$csv_path"' in workflow
    assert "persist-credentials: false" in workflow
    assert "GIT_ASKPASS" in workflow
    assert "git push origin HEAD:refs/heads/metrics" in workflow
    assert workflow.count("GH_TOKEN: ${{ github.token }}") == 1
    assert workflow.index("GH_TOKEN: ${{ github.token }}") > workflow.index(
        "- name: Push the metrics commit"
    )
    prepare_step = workflow.split("- name: Prepare the bounded metrics snapshot", maxsplit=1)[1]
    prepare_step = prepare_step.split("- name: Upload the exact download series", maxsplit=1)[0]
    assert "GH_TOKEN" not in prepare_step
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in workflow
    assert "path: ${{ runner.temp }}/rigor-foundry-metrics/downloads/rigor-foundry.csv" in workflow
    assert "if-no-files-found: error" in workflow
    assert "retention-days: 14" in workflow
    assert workflow.index("- name: Upload the exact download series") < workflow.index(
        "- name: Push the metrics commit"
    )
    assert "x-access-token" not in workflow
    assert "secrets." not in workflow
    action_refs = re.findall(r"uses: [^@\n]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_refs)


def test_public_evidence_uses_canonical_published_scorecard() -> None:
    """The README badge must be backed by the official publishing workflow."""
    workflow = (_ROOT / ".github" / "workflows" / "scorecard.yml").read_text(encoding="utf-8")
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert "ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a" in workflow
    assert "publish_results: true" in workflow
    assert "id-token: write" in workflow
    assert "branch_protection_rule:" not in workflow
    assert "workflow_dispatch:" not in workflow
    assert "api.scorecard.dev/projects/github.com/anulum/rigor-foundry/badge" in readme
    assert "scorecard.dev/viewer/?uri=github.com/anulum/rigor-foundry" in readme
    assert "api.securityscorecards.dev" not in readme
    assert "api.reuse.software/badge/github.com/anulum/rigor-foundry" not in readme
