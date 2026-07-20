# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA OSV awareness bridge tests
"""Exercise strict OSV import, adapter binding, selection, and record integrity."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_cra_p1_cli import NOW, osv_output, osv_result

import rigor_foundry.cra_osv as osv_module
from rigor_foundry.adapter_profiles import AdapterProfileEvidence, profile_by_name
from rigor_foundry.cra_osv import OsvAwarenessEvidence, import_osv_awareness
from rigor_foundry.cra_protocol import json_text


def write_inputs(tmp_path: Path, payload: bytes) -> tuple[Path, Path]:
    """Write an exact output and matching complete adapter result."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    output_path = tmp_path / "output.json"
    result_path = tmp_path / "result.json"
    output_path.write_bytes(payload)
    result_path.write_text(json_text(osv_result(payload).to_dict()), encoding="utf-8")
    return result_path, output_path


def import_fixture(tmp_path: Path, payload: bytes | None = None) -> OsvAwarenessEvidence:
    """Import one selected finding through the production boundary."""
    result_path, output_path = write_inputs(tmp_path, payload or osv_output())
    return import_osv_awareness(
        adapter_result_path=result_path,
        output_path=output_path,
        external_id="OSV-TEST-1",
        package_name="urllib3",
        imported_at=NOW,
    ).evidence


def test_awareness_record_round_trip_and_schema_guards(tmp_path: Path) -> None:
    """The derived awareness record is content-addressed with a closed schema."""
    evidence = import_fixture(tmp_path)
    assert OsvAwarenessEvidence.from_dict(evidence.to_dict()) == evidence
    assert evidence.component_ref == "PyPI:urllib3@1.26.0"
    with pytest.raises(ValueError, match="schema_version"):
        OsvAwarenessEvidence.from_dict({**evidence.to_dict(), "schema_version": "2.0"})
    with pytest.raises(ValueError, match="profile is unsupported"):
        OsvAwarenessEvidence.from_dict({**evidence.to_dict(), "profile": "semgrep"})
    with pytest.raises(ValueError, match="digest does not match"):
        OsvAwarenessEvidence.from_dict({**evidence.to_dict(), "awareness_digest": "0" * 64})


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"results": {}}, "results must be an array"),
        (
            {"results": [{"source": {"path": "x", "type": "sbom"}, "packages": []}]},
            "must be lockfile",
        ),
        (
            {"results": [{"source": {"path": "x", "type": "lockfile"}, "packages": {}}]},
            "packages must be an array",
        ),
        (
            {
                "results": [
                    {
                        "source": {"path": "x", "type": "lockfile"},
                        "packages": [
                            {
                                "package": {"name": "a", "version": "1", "ecosystem": "PyPI"},
                                "vulnerabilities": {},
                            }
                        ],
                    }
                ]
            },
            "vulnerabilities must be an array",
        ),
    ],
)
def test_malformed_osv_shapes_fail_through_public_import(
    tmp_path: Path,
    document: object,
    message: str,
) -> None:
    """Malformed bounded OSV arrays and source types never become awareness."""
    payload = json.dumps(document).encode()
    result_path, output_path = write_inputs(tmp_path, payload)
    with pytest.raises(ValueError, match=message):
        import_osv_awareness(
            adapter_result_path=result_path,
            output_path=output_path,
            external_id="OSV-TEST-1",
            package_name="urllib3",
            imported_at=NOW,
        )


def test_strict_json_and_all_osv_item_bounds_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Duplicate/non-finite JSON and each explicit collection bound are enforced."""
    for index, payload in enumerate((b'{"results":[],"results":[]}', b'{"results":NaN}')):
        case = tmp_path / str(index)
        case.mkdir()
        result_path, output_path = write_inputs(case, payload)
        with pytest.raises(ValueError, match=r"duplicate|non-finite"):
            import_osv_awareness(
                adapter_result_path=result_path,
                output_path=output_path,
                external_id="x",
                package_name="x",
                imported_at=NOW,
            )

    invalid_utf8 = tmp_path / "invalid-utf8"
    result_path, output_path = write_inputs(invalid_utf8, b"\xff")
    with pytest.raises(ValueError, match="not complete strict UTF-8 JSON"):
        import_osv_awareness(
            adapter_result_path=result_path,
            output_path=output_path,
            external_id="x",
            package_name="x",
            imported_at=NOW,
        )

    monkeypatch.setattr(osv_module, "MAX_OSV_RESULTS", 0)
    result_path, output_path = write_inputs(tmp_path / "result-bound", osv_output())
    with pytest.raises(ValueError, match="results exceed"):
        import_osv_awareness(
            adapter_result_path=result_path,
            output_path=output_path,
            external_id="OSV-TEST-1",
            package_name="urllib3",
            imported_at=NOW,
        )
    monkeypatch.setattr(osv_module, "MAX_OSV_RESULTS", 10_000)
    monkeypatch.setattr(osv_module, "MAX_OSV_PACKAGES", 0)
    result_path, output_path = write_inputs(tmp_path / "package-bound", osv_output())
    with pytest.raises(ValueError, match="packages exceed"):
        import_osv_awareness(
            adapter_result_path=result_path,
            output_path=output_path,
            external_id="OSV-TEST-1",
            package_name="urllib3",
            imported_at=NOW,
        )
    monkeypatch.setattr(osv_module, "MAX_OSV_PACKAGES", 100_000)
    monkeypatch.setattr(osv_module, "MAX_OSV_FINDINGS", 0)
    result_path, output_path = write_inputs(tmp_path / "finding-bound", osv_output())
    with pytest.raises(ValueError, match="findings exceed"):
        import_osv_awareness(
            adapter_result_path=result_path,
            output_path=output_path,
            external_id="OSV-TEST-1",
            package_name="urllib3",
            imported_at=NOW,
        )


def test_adapter_profile_status_counts_and_selection_are_exact(tmp_path: Path) -> None:
    """Only complete OSV findings whose counts and selection agree are importable."""
    payload = osv_output()
    result_path, output_path = write_inputs(tmp_path, payload)
    result = osv_result(payload)

    result_path.write_text(
        json_text(replace(result, profile_evidence=None).to_dict()), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="complete findings"):
        import_osv_awareness(
            adapter_result_path=result_path,
            output_path=output_path,
            external_id="OSV-TEST-1",
            package_name="urllib3",
            imported_at=NOW,
        )

    semgrep = profile_by_name("semgrep-local-json-v1")
    wrong_profile = AdapterProfileEvidence.build(
        profile=semgrep,
        status="findings",
        reason="findings",
        tool_version="1.170.0",
        version_output_digest="5" * 64,
        configuration_digest="6" * 64,
        input_digest="7" * 64,
        output_digest=result.output_digest,
        finding_count=1,
        scanned_target_count=1,
    )
    result_path.write_text(
        json_text(replace(result, profile_evidence=wrong_profile).to_dict()), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="complete findings"):
        import_osv_awareness(
            adapter_result_path=result_path,
            output_path=output_path,
            external_id="OSV-TEST-1",
            package_name="urllib3",
            imported_at=NOW,
        )

    empty_payload = b'{"results":[]}'
    result_path, output_path = write_inputs(tmp_path / "counts", empty_payload)
    with pytest.raises(ValueError, match="counts do not match"):
        import_osv_awareness(
            adapter_result_path=result_path,
            output_path=output_path,
            external_id="OSV-TEST-1",
            package_name="urllib3",
            imported_at=NOW,
        )

    result_path, output_path = write_inputs(tmp_path / "selection", payload)
    with pytest.raises(ValueError, match="select exactly one"):
        import_osv_awareness(
            adapter_result_path=result_path,
            output_path=output_path,
            external_id="OSV-MISSING",
            package_name="urllib3",
            imported_at=NOW,
        )

    result_path, output_path = write_inputs(tmp_path / "byte-count", payload)
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["output_bytes"] += 1
    result_path.write_text(json_text(value), encoding="utf-8")
    with pytest.raises(ValueError, match="byte count"):
        import_osv_awareness(
            adapter_result_path=result_path,
            output_path=output_path,
            external_id="OSV-TEST-1",
            package_name="urllib3",
            imported_at=NOW,
        )
